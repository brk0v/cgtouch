package main

// https://www.kernel.org/doc/Documentation/vm/pagemap.txt

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	flag "github.com/spf13/pflag"
)

const (
	PAGEMAP_BATCH  = 64 << 10
	PAGEMAP_LENGTH = int64(8)
	SIZEOF_INT64   = 8 // bytes
	PFN_MASK       = 0x7FFFFFFFFFFFFF
	PAGE_SIZE      = 4 * 1024 // bytes
)

const (
	BYTE     = 1.0
	KILOBYTE = 1024 * BYTE
	MEGABYTE = 1024 * KILOBYTE
	GIGABYTE = 1024 * MEGABYTE
	TERABYTE = 1024 * GIGABYTE
)

var (
	debug    bool
	mount    string
	verbose  bool
	follow   bool
	maxDepth uint

	pageSize = int64(syscall.Getpagesize())
	mode     = os.FileMode(0600)
)

func init() {
	flag.BoolVarP(&debug, "debug", "d", false, "debug mode provides more info")
	flag.BoolVarP(&verbose, "verbose", "v", false, "verbose mode outputs per file info")
	flag.BoolVarP(&follow, "follow", "f", false, "follow symbolic links")
	flag.UintVarP(&maxDepth, "max-depth", "p", 12, "max depth walk in dirs")
	flag.StringVarP(&mount, "mount", "m", "/sys/fs/cgroup/", "memory cgroup mount point (by default v2 version)")
}

type Cgroup struct {
	Inode   uint64
	Path    string
	Charged uint64
}

type Cgroups map[uint64]*Cgroup

type File struct {
	Path    string
	Size    int64
	Pages   int64
	Charged uint64
	Cgroups Cgroups
}

type Files map[string]*File

type Stats struct {
	Charged uint64
	Size    int64
	Pages   int64

	Cgroups Cgroups
	Files   Files

	watchedDirs int

	pagemap     *os.File
	kpagecgroup *os.File

	errs []error
}

func NewStats() (*Stats, error) {
	pagemap, err := os.OpenFile("/proc/self/pagemap", os.O_RDONLY, mode)
	if err != nil {
		return nil, err
	}

	kpagecgroup, err := os.OpenFile("/proc/kpagecgroup", os.O_RDONLY, mode)
	if err != nil {
		return nil, err
	}

	return &Stats{
		pagemap:     pagemap,
		kpagecgroup: kpagecgroup,
		errs:        make([]error, 0),
		Cgroups:     make(Cgroups),
		Files:       make(Files),
	}, nil
}

func (st *Stats) HandleFile(path string) error {
	stat, err := os.Lstat(path)
	if err != nil {
		return err
	}

	if stat.Mode()&os.ModeSymlink == os.ModeSymlink {
		return fmt.Errorf("symlinks don't allowed: %s", path)
	}

	if stat.IsDir() {
		return err
	}

	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NOATIME, mode)
	if err != nil {
		return err
	}
	defer file.Close()

	size := stat.Size()
	pages := size/pageSize + 1

	f := &File{
		Cgroups: make(Cgroups),
		Pages:   pages,
		Size:    size,
		Path:    path,
	}
	st.Files[path] = f

	st.Pages += pages
	st.Size += size

	batch := int64(0)
	for off := int64(0); off < size; off += batch {
		np := (size - off + pageSize - 1) / pageSize
		if np > PAGEMAP_BATCH {
			np = PAGEMAP_BATCH
		}
		batch = np * pageSize

		mm, err := syscall.Mmap(int(file.Fd()), off, int(batch), syscall.PROT_READ, syscall.MAP_SHARED)

		// disable readahead
		err = syscall.Madvise(mm, syscall.MADV_RANDOM)
		if err != nil {
			return err
		}

		// mincore for finding out pages in page cache
		mmPtr := uintptr(unsafe.Pointer(&mm[0]))

		mincoreSize := (batch + int64(pageSize) - 1) / int64(pageSize)
		mincoreVec := make([]byte, mincoreSize)

		batchPtr := uintptr(batch)
		mincoreVecPtr := uintptr(unsafe.Pointer(&mincoreVec[0]))

		ret, _, err := syscall.Syscall(syscall.SYS_MINCORE, mmPtr, batchPtr, mincoreVecPtr)
		if ret != 0 {
			return fmt.Errorf("syscall SYS_MINCORE failed: %v", err)
		}

		for i, v := range mincoreVec {
			if v%2 == 1 {
				// load pages to PTE
				_ = *(*int)(unsafe.Pointer(mmPtr + uintptr(pageSize*int64(i))))
			}
		}

		// reset referenced flags
		err = syscall.Madvise(mm, syscall.MADV_SEQUENTIAL)
		if err != nil {
			return err
		}

		index := int64(mmPtr) / pageSize * PAGEMAP_LENGTH
		buf := make([]byte, np*PAGEMAP_LENGTH)

		n, err := st.pagemap.ReadAt(buf, index)
		if err != nil {
			return err
		}

		if int64(n)/PAGEMAP_LENGTH != np {
			return fmt.Errorf("read data from pagemap is invalid")
		}

		data := make([]uint64, len(buf)/SIZEOF_INT64)
		for i := range data {
			data[i] = binary.LittleEndian.Uint64(buf[i*SIZEOF_INT64 : (i+1)*SIZEOF_INT64])
		}

		for _, d := range data {
			pfn := d & PFN_MASK
			if pfn == 0 {
				continue
			}

			cgroup := make([]byte, 8)
			n, err := st.kpagecgroup.ReadAt(cgroup, int64(pfn)*PAGEMAP_LENGTH)
			if err != nil {
				return err
			}

			if int64(n/8) != 1 {
				return fmt.Errorf("read data from /proc/kpagecgroup is invalid")
			}

			ci := binary.LittleEndian.Uint64(cgroup)

			// update per file
			if _, ok := f.Cgroups[ci]; ok {
				f.Cgroups[ci].Charged += 1
			} else {
				f.Cgroups[ci] = &Cgroup{
					Charged: 1,
					Inode:   ci,
				}
			}

			// update for all cgroup
			if _, ok := st.Cgroups[ci]; ok {
				st.Cgroups[ci].Charged += 1
			} else {
				st.Cgroups[ci] = &Cgroup{
					Charged: 1,
					Inode:   ci,
				}
			}

			// update total
			st.Charged += 1
			f.Charged += 1

			if debug {
				fmt.Printf("cgroup memory inode for pfn %x: %d\n", pfn, ci)
			}

			syscall.Munmap(mm)
		}
	}

	return err
}

func (st *Stats) Handle(paths []string, depth uint) {
	for _, path := range paths {
		if debug {
			fmt.Println("Working with file: ", path)
		}

		// get stat
		stat, err := os.Lstat(path)
		if err != nil {
			st.errs = append(st.errs, err)
			continue
		}

		// check on symlink
		if stat.Mode()&os.ModeSymlink == os.ModeSymlink {
			if follow {
				path, err = filepath.EvalSymlinks(path)
				if err != nil {
					st.errs = append(st.errs, err)
					continue
				}
				stat, err = os.Lstat(path)
				if err != nil {
					st.errs = append(st.errs, err)
					continue
				}
			} else {
				st.errs = append(st.errs, fmt.Errorf("Don't follow symlinks for %s. If you want then use \"-f\" flag", path))
				continue
			}
		}

		// check of file type
		if stat.IsDir() {
			// it is directory
			st.watchedDirs += 1

			if depth+1 > maxDepth {
				st.errs = append(st.errs, fmt.Errorf("max depth reached for %s", path))
				continue
			}

			// get file list
			files, err := ioutil.ReadDir(path)
			if err != nil {
				st.errs = append(st.errs, err)
				continue
			}

			// make new depth step
			fs := make([]string, 0)
			for _, file := range files {
				fs = append(fs, filepath.Join(path, file.Name()))
			}

			st.Handle(fs, depth+1)

		} else if stat.Mode().IsRegular() {
			// it's regular file
			err := st.HandleFile(path)
			if err != nil {
				st.errs = append(st.errs, err)
			}
		} else {
			// it's something else: device, pipe, socket
			st.errs = append(st.errs, fmt.Errorf("%s is not a regular file", path))
		}

	}
}

func ByteSize(bytes int64) string {
	unit := ""
	value := float64(bytes)

	switch {
	case bytes >= TERABYTE:
		unit = "T"
		value = value / TERABYTE
	case bytes >= GIGABYTE:
		unit = "G"
		value = value / GIGABYTE
	case bytes >= MEGABYTE:
		unit = "M"
		value = value / MEGABYTE
	case bytes >= KILOBYTE:
		unit = "K"
		value = value / KILOBYTE
	case bytes >= BYTE:
		unit = "B"
	case bytes == 0:
		return "0"
	}

	stringValue := fmt.Sprintf("%.1f", value)
	stringValue = strings.TrimSuffix(stringValue, ".0")
	return fmt.Sprintf("%s%s", stringValue, unit)
}

func printCgroupStats(cgroups Cgroups, charged uint64, pages int64) {
	fmt.Printf("%12s%11s%12s%12s\n", "cgroup inode", "percent", "pages", "path")

	fmt.Printf("%12s%10.1f%%%12d        %s\n", "-",
		float64(uint64(pages)-charged)*100/float64(pages),
		uint64(pages)-charged,
		"not charged",
	)

	for _, c := range cgroups {
		p := float64(c.Charged) * 100 / float64(pages)
		path, err := ResolvCgroup(c.Inode)
		pt := path.Path
		if err != nil {
			pt = err.Error()
		}
		fmt.Printf("%12d%10.1f%%%12d        %s\n", c.Inode, p, c.Charged, pt)
	}
}

// TODO (brk0v): add cache for cgroups
func ResolvCgroup(inode uint64) (*Cgroup, error) {
	cg := &Cgroup{}
	err := filepath.Walk(mount, func(path string, f os.FileInfo, err error) error {
		if f.IsDir() {
			var stat syscall.Stat_t
			if err := syscall.Stat(path, &stat); err != nil {
				return err
			}
			if stat.Ino == inode {
				cg.Path = path
				cg.Inode = stat.Ino
				return nil
			}
		}
		return nil
	})
	return cg, err
}

func main() {
	flag.Parse()

	stat, err := NewStats()
	if err != nil {
		log.Fatalln(err)
	}

	stat.Handle(flag.Args(), 0)

	// out errors
	for _, err := range stat.errs {
		fmt.Println("Warning: ", err)
	}
	if len(stat.errs) > 0 {
		fmt.Println("")
	}

	// print per file stats
	if verbose {
		for _, f := range stat.Files {
			fmt.Println(f.Path)
			printCgroupStats(f.Cgroups, f.Charged, f.Pages)
			fmt.Printf("\n--\n")
		}
	}

	// calculate total
	sc := stat.Charged * PAGE_SIZE
	if int64(sc) > stat.Size {
		sc = uint64(stat.Size)
	}
	percent := float64(sc*100) / float64(stat.Size)

	// print total
	fmt.Printf("%14s: %d\n", "Files", len(stat.Files))
	fmt.Printf("%14s: %d\n", "Directories", stat.watchedDirs)
	fmt.Printf("%14s: %d/%d %s/%s %.1f%%\n\n",
		"Resident Pages",
		stat.Charged,
		stat.Pages,
		ByteSize(int64(sc)),
		ByteSize(stat.Size),
		percent,
	)

	// print per cgroup total
	printCgroupStats(stat.Cgroups, stat.Charged, stat.Pages)

}

# cgtouch

`vmtouch` like util to show per cgroup per file Page Cache stats.

## Example

Show total stats:

```bash
$ sudo go run ./main.go /var/tmp/
```
```
         Files: 2
   Directories: 7
Resident Pages: 46182/74343 180.4M/290.4M 62.1%

cgroup inode    percent       pages        path
           -      37.9%       28161        not charged
        1781       6.2%        4608        /sys/fs/cgroup/user.slice/user-1000.slice/session-3.scope
        1717      55.9%       41574        /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice
```

Show full per file per cgroup stats:

```bash
$ sudo go run ./main.go /var/tmp/ -v
```
``` 
/var/tmp/file1.db
cgroup inode    percent       pages        path
           -      85.9%       28161        not charged
        1781      14.1%        4608        /sys/fs/cgroup/user.slice/user-1000.slice/session-3.scope

--
/var/tmp/ubuntu-21.04-live-server-amd64.iso
cgroup inode    percent       pages        pat
           -       0.0%           0        not charged
        2453     100.0%       38032        /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/run-u10.service

--
         Files: 2
   Directories: 7
Resident Pages: 42640/70801 166.6M/276.6M 60.2%

cgroup inode    percent       pages        path
           -      39.8%       28161        not charged
        1781       6.5%        4608        /sys/fs/cgroup/user.slice/user-1000.slice/session-3.scope
        2453      53.7%       38032        /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/run-u10.service
```

## Internals

Uses **pagemap** and **kpagecgroup** https://www.kernel.org/doc/Documentation/vm/pagemap.txt

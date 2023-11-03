# fwrouter
eBPF routing to/from interface devices on a host machine.

## Dependencies
- llvm >= 10
- clang >= 10
- libelf
- Ubuntu >= 18.04 LTS
- libbpf & bpftool
---

1. Add the appropriate repository:
```
add-apt-repository 'deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-10  main'
```

2. Update packages: `sudo apt update`.

3. Install the dependencies:
```
sudo apt-get install llvm-10     \
                     lldb-10     \
                     llvm-10-dev \
                     libllvm10   \
                     llvm-10-runtime \
                     clang-10    \
                     gcc-multilib

sudo ln -s /usr/bin/llvm-strip-10 /usr/bin/llvm-strip
sudo ln -s /usr/bin/clang-10 /usr/bin/clang
```

# Installing lbbpf & bpftool
Newer Ubuntu versions (versions >= 20.04) contain libbpf installed. However, as most of our work machines (and firewalls) are running Ubuntu 18.04,
we need to manually install the tool from source.
Clone the git repo of libbpf into you're work machine: `git clone https://github.com/libbpf/libbpf.git`
Run the following commands:
```
cd /src
sudo make install
```

Once installed you can make sure that the required headers are in the file system under `/usr/include/bpf`

## Debugging maps, programs, etc.
Use the `bpftool` to debug maps, programs, etc.
To download run: `sudo apt install linux-tools-common`.

## Where are my 'bpf_printk' logs?
Run the following command: `sudo cat /sys/kernel/debug/tracing/trace_pipe`

## How to run `fwrouter`?
Compile the program using `make`, followed by: `sudo ./fwrouter run`

## How to verify the program is loaded properly?
Use the following command: `ip link`, and find the added interfaces listed.
To see the `bpf` filter added use the following: `sudo tc -s -d filter show dev eth0 ingress`.

## How to remove the qdisc added by this program manually?
Use the following command to remove the qdisc: `sudo tc qdisc del dev eth0 clsact`.
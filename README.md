# fwrouter
eBPF routing to/from interface devices on a host machine.

## Dependencies
- llvm >= 11
- clang >= 11
- Ubuntu >= 20.04 LTS
---

1. Update packages: `sudo apt update`.
2. Install the dependencies: 
```
sudo apt-get install llvm-11     \
                     lldb-11     \
                     llvm-11-dev \
                     libllvm11   \
                     llvm-11-runtime \
                     clang-11    \
                     gcc-multilib

sudo ln -s /usr/bin/llvm-strip-11 /usr/bin/llvm-strip
sudo ln -s /usr/bin/clang-11 /usr/bin/clang
```

## Debugging maps, programs, etc.
Use the `bpftool` to debug maps, programs, etc.
To download run: `sudo apt install linux-tools-common`.

## Where are my 'bpf_printk' logs?
Run the following command: `sudo cat /sys/kernel/debug/tracing/trace_pipe`

## How to run `fwrouter`?
Compile the program using `make`, followed by: `sudo ./fwrouter run --config-file=./examples/firewall.yaml`

## How to verify the program is loaded properly?
Use the following command: `ip link`, and find the added interfaces listed.
To see the `bpf` filter added use the following: `sudo tc -s -d filter show dev eth0 ingress`.
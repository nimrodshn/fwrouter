# fwrouter
eBPF routing to/from interface devices on a host machine.

## Dependencies
- llvm >= 10
- clang >= 10
---
1. Retrieve the gpg key for `llvm-10`:
```
wget --no-check-certificate -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
```

2. Add the appropriate repository:
```
add-apt-repository 'deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-10  main'
```
3. Update packages: `sudo apt update`.
4. Install the dependencies: 
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

## Debugging maps, programs, etc.
Use the `bpftool` to debug maps, programs, etc.
To download run: `sudo apt install linux-tools-common`.

## Where are my 'bpf_printk' logs?
Run the following command: `sudo cat /sys/kernel/debug/tracing/trace_pipe`

## How to run `fwrouter`?
Compile the program using `make`, followed by: `sudo ./fwrouter run --config-file=./examples/idps.yaml`

## How to define a state machine for packet flow?
The following is an example of how to define a [state-transition table](https://en.wikipedia.org/wiki/State-transition_table) for packet flow in the firewall. interfaces in the following transition table are represented as physical / virtual interfaces and thus, 
share properties with network interfaces. Each interface only supports a *single* transition.
```
---
interfaces:
  - name: "eth0"
    transition:
      name: "egress-with-envoy-mark-to-idps"
      queue: "egress"
      condition:
        type: "mark"
        match: 0x11
      action:
        next-interface: "dummy0"
        queue: "ingress"
  - name: "dummy0"
  - name: "dummy1"
    transition:
      name: "default-traffic-to-eth0"
      queue: "egress"
      action:
        next-state: "eth0"
        queue: "egress"
```

The above transition table describes the following diagram: 

![packet-flow](./docs/idps-afpacket.jpg)

The router will do its best effort to find interfaces for services if they are not provided in the config file.
The router will route traffic according to the order in the routes provided.
For more example config files see `/examples` folder.

## How to verify the program is loaded properly?
Use the following command: `ip link`, and find the added interfaces listed.
To see the `bpf` filter added use the following: `sudo tc -s -d filter show dev eth0 ingress`.
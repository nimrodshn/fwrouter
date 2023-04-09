# fwrouter
eBPF routing to/from interface devices on a host machine.

## Dependencies
- llvm >= 10
- clang >= 10
---
1. Retrieve the archive signature for `llvm-10`:
```
wget --no-check-certificate -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
```

2. Add the PPA where to install from:
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


## Where are my 'bpf_printk' logs?
Run the following command: `sudo cat /sys/kernel/debug/tracing/trace_pipe`

## How to run this router?
Compile the program using `make`, followed by: `sudo ./fwrouter run --config-file=./examples/test.yaml`

## How to define a state machine for packet flow?
The following is an example of how to define a [state-transition table](https://en.wikipedia.org/wiki/State-transition_table) for packet flow in the firewall. States in the following transition table are represented as physical / virtual interfaces and thus, 
share properties with network interfaces.
```
---
states:
  - name: "eth0"
    interface: "eth0"
    transitions:
      - name: "https-traffic"
        condition: "https"
        next: "haproxy"
      - name: "default-traffic"
        next": "envoy"
        mark: "envoy"
  - name: "haproxy"
    interface: "haproxy0"
    transitions:
      - name: "default-traffic"
        next": "idps"
  - name: "idps"
    interface: "idps0"
    transitions:
      - name: "past-envoy-traffic"
        condition: "envoy"
        next: "eth0"
        queue: "tx"
      - name: "envoy-bound-traffic"
        next: "eth0"
        queue: "rx"
        mark: "envoy"
marks:
  - name: "envoy"
    value: 100
conditions:
  - name: "envoy"
    type: "mark"
    value: "envoy"
  - name: "https"
    type: "l7 protocol"
    value: "https"
```

The router will do its best effort to find interfaces for services if they are not provided in the config file.
The router will route traffic according to the order in the routes provided.
For more example config files see `/examples` folder.
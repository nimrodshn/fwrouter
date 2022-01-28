# fwrouter
eBPF routing to/from interface devices on a host machine.

## Making sure the XDP program is attached
Run the following command: `ip link list`.

## Where are my 'bpf_printk' logs?
Run the following command: `sudo cat /sys/kernel/debug/tracing/trace_pipe`

## How to run this router?
Compile the program using `make`, followed by: `./sudo fwrouter run`

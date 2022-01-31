# fwrouter
eBPF routing to/from interface devices on a host machine.

## Making sure the XDP program is attached
Run the following command: `ip link list`.

## Where are my 'bpf_printk' logs?
Run the following command: `sudo cat /sys/kernel/debug/tracing/trace_pipe`

## How to run this router?
Compile the program using `make`, followed by: `sudo ./fwrouter run --config-file=./examples/test.yaml`

## How to define a route table?
Define a route in the route table using the provided YAML file:
```
---
routes: 
 - name: "test"
   nodes:
   - name: "some-process"
     type: "process"
     iface: "lo"
     traffic: "http"
   - name: "some-container"
     type: "container"
     traffic: "http"
```

The router will do its best effort to find interfaces for containers if they are not provided in the config file.
The router will route traffic according to the order in the routes provided.
For more example config files see `/examples` folder.
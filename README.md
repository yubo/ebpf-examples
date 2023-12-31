## eBPF Examples

```
git clone https://github.com/yubo/ebpf-examples 
cd ebpf-examples
```

## Run

#### Kprobe
with vmlinux.h

```
$ go run ./kprobe
           <...>-134227 [003] d... 37225.735556: bpf_trace_printk: pid 134227 tcp_sendmsg 144
           <...>-134227 [003] d... 37225.736460: bpf_trace_printk: pid 134227 tcp_sendmsg 672
           <...>-134227 [000] d... 37225.736856: bpf_trace_printk: pid 134227 tcp_sendmsg 192
           <...>-134227 [000] d... 37225.926671: bpf_trace_printk: pid 134227 tcp_recv 96
           <...>-134227 [000] d... 37225.927349: bpf_trace_printk: pid 134227 tcp_sendmsg 144
```

#### Fentry
with BPF CO-RE

```
$ go run ./fentry
2023/08/27 09:51:28 Src addr        Port   -> Dest addr       Port   recv   sent
2023/08/27 09:52:25 192.168.1.25    22     -> 192.168.1.14    52653  561202 68775165
2023/08/27 09:52:25 192.168.1.25    38776  -> 110.242.68.4    80     1412   77
2023/08/27 09:52:25 192.168.1.25    38776  -> 110.242.68.4    80     2781   77
2023/08/27 09:52:28 192.168.1.25    22     -> 192.168.1.14    52653  561298 68778429
2023/08/27 09:52:29 192.168.1.25    22     -> 192.168.1.14    52653  561394 68778749
2023/08/27 09:52:29 192.168.1.25    39670  -> 110.242.68.3    80     1412   77
2023/08/27 09:52:29 192.168.1.25    39670  -> 110.242.68.3    80     2781   77

```

## rebuild object(*.o)
default build with x86_64, rebuild with

```
make
```

## References

  - https://github.com/cilium/ebpf

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"os"
	"os/exec"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf kprobe.c -- -I../headers -I../include

const mapKey uint32 = 0

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("tcp_cleanup_rbuf", objs.KprobeTcpCleanupRbuf, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	kp2, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp2.Close()

	cmd := exec.Command("cat", "/sys/kernel/debug/tracing/trace_pipe")
	cmd.Stdout = os.Stdout
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

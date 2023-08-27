// +build ignore go

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "GPL";

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe_tcp_cleanup_rbuf(struct pt_regs *ctx) {
  // struct sock *sk = PT_REGS_PARM1(ctx);
  int copied = PT_REGS_PARM2(ctx);

  u32 pid = bpf_get_current_pid_tgid() >> 32;

  if (copied > 0) {
    bpf_printk("pid %d tcp_recv %d\n", pid, copied);
  }

  return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
  // struct sock *sk = PT_REGS_PARM1(ctx);
  // struct msghdr *msg = PT_REGS_PARM2(ctx);
  size_t size = PT_REGS_PARM3(ctx);

  u32 pid = bpf_get_current_pid_tgid() >> 32;

  if (size > 0) {
    bpf_printk("pid %d tcp_sendmsg %u\n", pid, size);
  }
  return 0;
}

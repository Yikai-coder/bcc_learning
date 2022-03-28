#!/usr/bin/python
#
# This is a Hello World example that formats output as fields.

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
int hello(void *ctx) {                  // 通过后面get_syscall_fname()来指定追踪的kernel1 function，这里可以不需要kprobe__开头
                                        // 需要加载到probe的函数第一个形参必须是*ctx
                                        // 如果是打印help的函数等不需要放在probe执行的则用static inline
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")  # 将定义的probe函数与内核函数关联，可以重复使用

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()   # trace_fields返回trace_pipe里的一系列值
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

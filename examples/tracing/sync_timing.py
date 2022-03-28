#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# Done:这个程序貌似有问题，在调用b.trace_fields()的时候会提示ValueError: not enough values to unpack (expected 4, got 0)
#      有的时候在运行一开始出现，有的时候在连续使用sync的时候出现
# Solution: 不要用apt安装，使用源码编译就可以了

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);         // 创建hash表last，默认为u64类型

int do_trace(void *ctx) {  //struct pt_regs
    u64 ts, *tsp, delta, key = 0;
    u64 *sync_counts_p = NULL, sync_counts = 0, cnt_key = 1;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);   // 查hash，传入key的地址，如果找不到返回NULL
    sync_counts_p = last.lookup(&cnt_key);   // 查hash获取sync次数
    if (tsp != NULL && sync_counts_p != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;   // bpf_ktime_get_ns()获取ns级别时间
        /*
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        */
        sync_counts = *sync_counts_p + 1;
        bpf_trace_printk("%d, %d\\n", delta / 1000000, sync_counts);
        // last.delete(&key);   // Linux kernel 4.8.10前貌似使用update有bug
    }
    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    last.update(&cnt_key, &sync_counts);
    return 0;
}

""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()   # trace_fields返回trace_pipe里的一系列值
        (ms, cnt) = msg.split()
        if start == 0:
            start = ts
        ts = ts - start
        printb(b"At time %.2f s: multiple syncs detected, last %s ms ago, count: %s" % (ts, ms, cnt))
    except KeyboardInterrupt:
        exit()
    # except ValueError:
    #     continue

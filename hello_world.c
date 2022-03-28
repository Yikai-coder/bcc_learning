int kprobe__sys_clone(void *ctx)   // kprobe__开头表示后面的部分会被当成kernel function名
{
    bpf_trace_printk("Hello World!\\n");   // 简单的追踪打印函数，但不具备线程安全性，只能支持1 %s，更好的是BPF_PERF_OUTPUT()
                                            // 通过这个函数从probe向外传输msg
    return 0;                    // 返回给内核hook，这个值会导致不同的行为，一般是返回0即可
}
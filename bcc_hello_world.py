from bcc import BPF

bpf_program = '''
    int kprobe__sys_clone(void *ctx)   // kprobe__开头表示后面的部分会被当成kernel function名进行追踪
    {
        bpf_trace_printk("Hello World!\\n");   // 简单的追踪打印函数，但不具备线程安全性，只能支持1 %s，更好的是BPF_PERF_OUTPUT()
        return 0;                    // 返回给内核hook，这个值会导致不同的行为，一般是返回0即可
    }
'''

if __name__=="__main__":
    # BPF(text=bpf_program).trace_print()
    BPF(src_file='hello_world.c')
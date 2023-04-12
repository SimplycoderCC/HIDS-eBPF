// some ebpf-rootkit
// https://github.com/h3xduck/TripleCross
// https://github.com/krisnova/boopkit
// https://github.com/Gui774ume/ebpfkit
// https://github.com/pathtofile/bad-bpf

// eBPF backdoor(behavior) detection
// https://github.com/kris-nova/boopkit
// eBPF-based rootkit(detection), upload an eBPF program's behavior
// Related kernel functions are here:
// security_bpf(__sys_bpf from SYSCALL, very early stage)
// bpf_check (verifier) => https://elixir.bootlin.com/linux/v6.0/source/kernel/bpf/verifier.c#L15128
// security_bpf_prog(within bpf_prog_new_fd, after bpf_check)
// 
// According to the https://github.com/Gui774ume/ebpfkit-monitor, I simplify this by following:
// 1. kprobe/sys_bpf for initialization
// 2. security_bpf, only recording cmd like
//    BPF_PROG_LOAD/BPF_PROG_ATTACH/BPF_BTF_LOAD/BPF_RAW_TRACEPOINT_OPEN, but we won't do a filter
//    for now, since we also hook security_bpf_prog
// 3. security_bpf_prog, get the context information about the program
// 4. kpretprobe/sys_bpf for popping the result to userspace
//
// Event more, we could block the way to initialize, override the return by
// bpf_override_return(ctx, -EPERM);
// to block. But, be really careful about this action. And, like anti-rootkit part
// we should also add behavior detection instead of doing stack trace...
// 
// Reference:
// https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-With-Friends-Like-EBPF-Who-Needs-Enemies.pdf
// TODO: in ubuntu, sometimes hook failed

// Reference:
// https://github.com/chriskaliX/Hades/blob/fdfbcabb68d48262b09e8bfc03bf44f2bdcf5c9a/plugins/ebpfdriver/kern/include/hades_rootkit.h

#define EPERM 1
SEC("kprobe/bpf")
int BPF_KPROBE(kprobe_sys_bpf)
{
    // Be careful about access to bpf_map and change value directly
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    if (get_config(DENY_BPF) == 0)
        return 0;
    return bpf_override_return(ctx, -EPERM);
}

SEC("kprobe/security_bpf")
int BPF_KPROBE(kprobe_security_bpf)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.type = SYS_BPF;
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 0);
    // command
    int cmd = PT_REGS_PARM1(ctx);
    save_to_submit_buf(&data, &cmd, sizeof(int), 1);
    switch (cmd) {
    case BPF_PROG_LOAD: {
        union bpf_attr *attr = (union bpf_attr *)PT_REGS_PARM2(ctx);
        if (attr == NULL)
            return 0;
        char *name = READ_KERN(attr->prog_name);
        save_str_to_buf(&data, name, 2);
        u32 type = READ_KERN(attr->prog_type);
        save_to_submit_buf(&data, &type, sizeof(u32), 3);
        return events_perf_submit(&data);
    }
    default:
        return 0;
    }
}
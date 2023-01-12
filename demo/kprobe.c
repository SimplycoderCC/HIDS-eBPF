#!/usr/bin/env bpftrace
/*
 * This is a bpftrace version of the bcc tool of the same name.
 *
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 */

/* ===============   主要观测kprobe框架使用的相关行为    =================================== */

BEGIN
{
	printf("Tracing kprobe ... Hit Ctrl-C to end.\n");
	printf("============= self tid:%d  =================== \n",tid);
	printf("COMM TID \n");
	@self_tid = tid;
}

kprobe:insn_init
/tid != @self_tid/	
{
	// @start[tid] = ;
	printf("%s %d called insn_init \n", comm, tid);
}

kprobe:insn_get_length
/tid != @self_tid/	
{
	// @start[tid] = ;
	printf("%s %d called insn_get_length \n", comm, tid);
}

// kprobe:ftrace_set_filter_ip,    		// 最原始的这两个函数没有hook点
// 以下为ftrace相关hook点
// kprobe:kprobe_ftrace_handler			// 无法加载
kprobe:arch_prepare_kprobe_ftrace  	// bpftrace 2次调用     brokepkg 3次调用 且comm 为insmod 操作
// kprobe:__disarm_kprobe_ftrace		// bpftrace 0次调用
// kprobe:arch_check_ftrace_location,	// bpftrace 2次调用		brokepkg 3次调用 
// kprobe:pstore_ftrace_seq_next		// bpftrace 0次调用					
// kprobe:pstore_ftrace_seq_show		// bpftrace 0次调用			
// kprobe:pstore_ftrace_seq_start		// bpftrace 0次调用			
// kprobe:pstore_ftrace_seq_stop		// bpftrace 0次调用			
// kprobe:psz_ftrace_read				// bpftrace 0次调用	
// kprobe:sysrq_ftrace_dump				// bpftrace 0次调用	
/tid != @self_tid/					
{
	// @start[tid] = ;
	printf("%s %d called arch_prepare_kprobe_ftrace \n", comm, tid);
}

kprobe:arch_check_ftrace_location
/tid != @self_tid/	
{
	printf("%s %d called arch_check_ftrace_location \n", comm, tid);
}

kprobe:register_kprobe
{
	printf("%s %d called register_kprobe \n", comm, tid);
}

// kprobe:unregister_kprobe
// {
// 	printf("%s %d called unregister_kprobe \n", comm, tid);
// }

/*
kretprobe:insn_init,
kretprobe:insn_get_length
/@start[arg0]/
{
	@usecs = hist((nsecs - @start[arg0]) / 1000);
	delete(@start[arg0]);
}
*/
END
{
	// clear(@start);
}

/**
 * insn_init() - initialize struct insn
 * @insn:	&struct insn to be initialized
 * @kaddr:	address (in kernel memory) of instruction (or copy thereof)
 * @buf_len:	length of the insn buffer at @kaddr
 * @x86_64:	!0 for 64-bit kernel or 64-bit app
 */
 /*
* void insn_init(struct insn *insn, const void *kaddr, int buf_len, int x86_64)
* {
* 	/*
* 	 * Instructions longer than MAX_INSN_SIZE (15 bytes) are invalid
* 	 * even if the input buffer is long enough to hold them.
* 	
* 	if (buf_len > MAX_INSN_SIZE)
* 		buf_len = MAX_INSN_SIZE;
* 
* 	memset(insn, 0, sizeof(*insn));
* 	insn->kaddr = kaddr;
* 	insn->end_kaddr = kaddr + buf_len;
* 	insn->next_byte = kaddr;
* 	insn->x86_64 = x86_64 ? 1 : 0;
* 	insn->opnd_bytes = 4;
* 	if (x86_64)
* 		insn->addr_bytes = 8;
* 	else
* 		insn->addr_bytes = 4;
* }
*/

/**
 * insn_get_length() - Get the length of instruction
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * immediates bytes.
 *
 * Returns:
 *  - 0 on success
 *  - < 0 on error
*/
/*
int insn_get_length(struct insn *insn)
{
	int ret;

	if (insn->length)
		return 0;

	if (!insn->immediate.got) {
		ret = insn_get_immediate(insn);
		if (ret)
			return ret;
	}

	insn->length = (unsigned char)((unsigned long)insn->next_byte
				     - (unsigned long)insn->kaddr);

	return 0;
}
*/
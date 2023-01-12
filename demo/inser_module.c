#!/usr/bin/env bpftrace
/*
 * This is a bpftrace version of the bcc tool of the same name.
 *
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 */

BEGIN
{
	printf("Tracing module ... Hit Ctrl-C to end.\n");
	printf("============= self tid:%d  =================== \n",tid);
	printf("COMM TID \n");
	@self_tid = tid;
}

/*
insmod 107658 called  - probe: tracepoint:syscalls:sys_enter_finit_module 
insmod 107658 called  - probe: tracepoint:module:module_load   
insmod 107658 called  - probe: tracepoint:module:module_put  
insmod 107658 called  - probe: tracepoint:syscalls:sys_exit_finit_module  
*/

/*     bpftrace 结果
insmod 109812 called  - probe: tracepoint:syscalls:sys_enter_finit_module -   
insmod 109812 called  - probe: tracepoint:module:module_load -  brokepkg 
insmod 109812 called  - probe: tracepoint:module:module_put -  brokepkg 
insmod 109812 called  - probe: tracepoint:syscalls:sys_exit_finit_module 
*/

tracepoint:module:module_load 
{
	printf("%s %d called  - probe: %s -  %s \n", comm, tid ,probe, str(args->name) );
}

/*很多程序都会调用*/
tracepoint:module:module_put 
/comm == "insmod"/
{
	printf("%s %d called  - probe: %s -  %s \n", comm, tid ,probe, str(args->name) );
}

tracepoint:syscalls:sys_enter_finit_module 
{
	printf("%s %d called  - probe: %s -  %s \n", comm, tid ,probe, str(args->uargs) );
}

tracepoint:syscalls:sys_exit_finit_module 
{
	printf("%s %d called  - probe: %s \n", comm, tid ,probe );
}


/* trace all about module */
/*                   
kprobe:*module*
/comm == "insmod"/
{
	printf("%s %d called  - probe: %s,   function: %s  \n", comm, tid ,probe, func );
}
tracepoint:*module*
/comm == "insmod"/
{
	printf("%s %d called  - probe: %s  \n", comm, tid ,probe );
}
*/

/*
tracepoint:module:module_load
    unsigned int taints
    __data_loc char[] name
tracepoint:module:module_put
    unsigned long ip
    int refcnt
    __data_loc char[] name
tracepoint:syscalls:sys_enter_finit_module
    int __syscall_nr
    int fd
    const char * uargs
    int flags
tracepoint:syscalls:sys_exit_finit_module
    int __syscall_nr
    long ret
*/
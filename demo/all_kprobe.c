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
	printf("Tracing kprobe ... Hit Ctrl-C to end.\n");
	printf("============= self tid:%d  =================== \n",tid);
	printf("COMM TID \n");
	@self_tid = tid;
}

kprobe:*kprobe*
/comm == "insmod"/
{
	printf("%s %d called  - probe: %s,   function: %s  \n", comm, tid ,probe, func );
}
* 内核态Rootkit
  * 检测内核函数的修改，主要检测两个点      					-- ***FINISHED***
    * [f0rb1dd3n/Reptile: LKM Linux rootkit (github.com)](https://github.com/f0rb1dd3n/Reptile)  主要是其使用的 KHook [milabs/khook: Linux Kernel hooking engine (x86) (github.com)](https://github.com/milabs/khook) 其中使用了两个关键的内核指令操作函数：`insn_init()`   &&  `insn_get_length()` ，相关分析见：[linux内核钩子--khook - 番茄汁汁 - 博客园 (cnblogs.com)](https://www.cnblogs.com/likaiming/p/10970543.html)
      * [`insn_init` insn.c - arch/x86/lib/insn.c - Linux source code (v5.19) - Bootlin](https://elixir.bootlin.com/linux/v5.19/source/arch/x86/lib/insn.c#L61)
      * [`insn_get_length` insn.c - arch/x86/lib/insn.c - Linux source code (v5.19) - Bootlin](https://elixir.bootlin.com/linux/v5.19/source/arch/x86/lib/insn.c#L699)
      * [try alfonmga/hiding-cryptominers-linux-rootkit: Linux rootkit POC to hide a crypto miner&#39;s process and CPU usage. (github.com)](https://github.com/alfonmga/hiding-cryptominers-linux-rootkit) 也是使用khook的rootkit， reptile 在22.04上无法编译与使用
    * 基于ftrace框架的内核函数hook，主要基于 `ftrace_set_filter_ip()` 与 `register_ftrace_function()` 两个函数 。简单的例子：[ilammy/ftrace-hook: Using ftrace for function hooking in Linux kernel (github.com)](https://github.com/ilammy/ftrace-hook)
      * 相关的rootkit：[h3xduck/Umbra: A LKM rootkit targeting 4.x and 5.x kernel versions which opens a backdoor that can spawn a reverse shell to a remote host, launch malware and more. (github.com)](https://github.com/h3xduck/Umbra) 此rootkit在22.04上无法编译
      * [R3tr074/brokepkg: The LKM rootkit working in Linux Kernels 2.6.x/3.x/4.x/5.x (github.com)](https://github.com/R3tr074/brokepkg) 此rootkit可在22.04上编译且能用kprobe.c进行检测，但ebpf无法跟踪ftrace相关操作
    * 这两个函数ebpf都没有hook点，ebpf无法跟踪到ftrace内核框架中的函数，只能查看其他调用过程中的关键函数。eg. kprobe framework的使用
  * 在加载模块时，查看模块名建立已知rootkit模块敏感列表 		-- ***TODO***
* 用户态Rootkit
  * 检测每个进程栈空间中的环境变量，查看是否存在LD_PRELOAD这一环境变量


### 自实现的内核函数修改

以khook为例：https://github.com/milabs/khook

原函数执行流：

```
CALLER
| ...
| CALL X -(1)---> X
| ...  <----.     | ...
` RET       |     ` RET -.
            `--------(2)-'
```

hook后执行流：

```
CALLER
| ...
| CALL X -(1)---> X
| ...  <----.     | JUMP -(2)----> STUB.hook
` RET       |     | ???            | INCR use_count
            |     | ...  <----.    | CALL handler -(3)------> HOOK.fn
            |     | ...       |    | DECR use_count <----.    | ...
            |     ` RET -.    |    ` RET -.              |    | CALL origin -(4)-----> STUB.orig
            |            |    |           |              |    | ...  <----.            | N bytes of X
            |            |    |           |              |    ` RET -.    |            ` JMP X + N -.
            `------------|----|-------(8)-'              '-------(7)-'    |                         |
                         |    `-------------------------------------------|---------------------(5)-'
                         `-(6)--------------------------------------------'
```

X的第一条指令被替换成JUMP的跳转指令，另外，还可以知道多了3个部分STUB.hook、HOOK.fn、STUB.orig，他们的含义分别是

STUB.hook：框架自定义的钩子函数模板，有4部分，除了引用的维护的两部分，还有(3)一条跳转，(8)一条返回。(3)是跳转到HOOK.fn

HOOK.fn：这是使用者自定义的钩子函数，在上面的例子中，这个函数被定义成khook_inode_permission、khook_load_elf_binary。这里的(4)就是KHOOK_ORIGIN，钩子替换下来的原函数地址，一般来说，自定义的钩子函数最后也会调用原函数，用来保证正常的执行流程不会出错

STUB.orig：框架自定义的钩子函数模板，由于X的第一条指令被替换成JUMP的跳转指令，要正常执行X，则需要先执行被替换的几个字节，然后回到X，也就是图中的过程(5)

**整体的思路就是，替换掉需要钩掉的函数的前几个字节，替换成一个跳转指令，让X开始执行的时候跳转到框架自定义的STUB代码部分，STUB再调用用户自定义的钩子函数。然后又会执行原先被跳转指令覆盖的指令，最后回到被钩掉的函数的正常执行逻辑**

#### 检测思路：

用到了两个内核中操作指令的函数，两个函数的功能是获取某个地址的指令（用struct insn表示）和 获取这个指令的长度

```
/**
 下面是内核关于这两个函数的说明
 insn_init() - initialize struct insn
 @insn:    &struct insn to be initialized
 @kaddr:    address (in kernel memory) of instruction (or copy thereof)
 @x86_64:    !0 for 64-bit kernel or 64-bit app

insn_get_length() - Get the length of instruction
@insn:    &struct insn containing instruction

If necessary, first collects the instruction up to and including the
immediates bytes.
*/
```

检测两个函数的使用情况，配合LKM模块插入的情况完成检测。 


### 基于ftrace框架的内核函数hook

主要基于 `ftrace_set_filter_ip()` 与 `register_ftrace_function()` 两个函数 。同时也会使用上文中的内核中操作指令函数

简单的例子：[ilammy/ftrace-hook: Using ftrace for function hooking in Linux kernel (github.com)](https://github.com/ilammy/ftrace-hook)

ftrace_hook结构体

```
/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};
```

注册并使能 ftrace hook

```
/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}
```

移除hooks

```
/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}
```

#### 检测思路：

ebpf无法跟踪ftrace相关操作，`ftrace_set_filter_ip()` 与 `register_ftrace_function()`这两个函数ebpf都没有hook点，ebpf无法跟踪到ftrace内核框架中的函数，只能查看其他调用过程中的关键函数。

检测在插入LKM过程中kprobe framework的使用，目前发现的rootkit都基于kprobe去查找到 kallsyms_lookup_name 函数地址，并进一步使用这个kallsyms_lookup_name 函数去获取内核中的其他符号地址。


### 综上

检测LKM内核模块插入过程中的 (1)内核中操作指令函数的使用 和(2)kprobe framework的使用

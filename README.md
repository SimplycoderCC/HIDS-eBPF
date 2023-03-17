# eBPF-HIDS

Intrusion Detection System based on eBPF

# 为什么是eBPF？

稳定：通过验证器，防止用户编写的程序导致内核崩溃。相比内核模块，eBPF更稳定

免安装：eBPF内置于Linux内核，无需安装额外依赖，开箱即用。

内核编程：支持开发者插入自定义的代码逻辑（包括数据采集、分析和过滤）到内核中运行

高效的信息交流机制：通过Map（本质上是一种共享内存的方式）进行数据传输，实现各个hook点、用户态与内核态的高效信息交互。

# eBPF-HIDS source code

```shell
# hids source code
./hids/config.h  
./hids/utils.h  
./hids/hids.h  
./hids/hids.bpf.c  
./hids/hids.c  
./hids/hids.h 
./hids/com_funaddr.c 
# bpftrace 跟踪各种系统调用序列的脚本
./demo/*.c #bpftrace跟踪脚本
./demo/*.txt #得到的系统调用序列
```

# Documents

#### [文档：判断进程是否运行在容器中](./doc/区分容器进程.md)

#### [文档：Rootkit检测原理](./doc/Rootkit检测.md)

#### [项目中期文档](./doc/中期报告-面向云原生的内核威胁检测系统的设计与实现.pdf)

#### [项目中期slides](./doc/中期答辩PPT.pdf)

#### [项目开题slides](./doc/开题答辩PPT.pdf)

#### [内核信息提取hook点的研究](https://github.com/haozhuoD/bpftrace-hook-demo)

#### Other

[容器加固学习文档](./doc/容器加固.md)

[docker容器运行时安全早期学习文档](./doc/docker容器运行时安全.md)


# Branches

* `main`               ------主分支，仅实现检查功能
* `lsm`           -------基于KRSI内核运行时检测，基于LSM hook点实现函数级的入侵阻断
* `send_signal`          ------基于bpf_send_signal()辅助函数发送信号，实现进程级的入侵阻断

# usage

```shell
# Enter the folder
cd hids 
# Compile
make hids   # 或者 make all  
# 运行hids
sudo ./hids

# clear
make clear  # 或者 make clean
```

# 容器逃逸检查

TODO：截图、完善文档

# Rootkit-Examples

### Diamophine Rootkit 
```shell
# https://github.com/m0nad/Diamorphine
# 直接修改系统调用表，实现对系统调用的劫持

# Install
cd Diamorphine          # Enter the folder
make                    # Compile
insmod diamorphine.ko   # Load the module(as root)

# Uninstall
kill -63 0          # The module starts invisible, to remove you need to make it visible
rmmod diamorphine   # Then remove the module(as root)
```

![](./images/detected-dia.png)    

### brokepkg Rootkit
```shell
# https://github.com/R3tr074/brokepkg
# 基于ftrace framework实现对系统调用及内核函数的劫持

# Install
cd brokepkg             # Enter the folder
make config             # Configuration
make install            # Compile
insmod brokepkg.ko      # Load the module(as root)

# Uninstall
kill -31 0  # Remove brokepkg invisibility to uninstall him
sudo rmmod brokepkg  # Then remove the module
```

![](./images/detected-broke.png)    

#  Check preload(User-mode Rootkit)

``` shell
# 发送44号信号到任意PID触发动态链接注入检测
kill -44 2100
kill -44 $(ANY PID)
```

![](./images/user-rootkit.png)  

#  Nofile attack 无文件攻击

TODO：截图、完善文档

[无文件攻击demo](./no_file_attack/no_file_attack.py)

[学习资料：linux_no_file_elf_mem_execute](https://xeldax.top/article/linux_no_file_elf_mem_execute)

# Hook points

> 项目目前支持 `18` 种 Hook，足以实现本项目所需功能。这些hook点的选取主要基于本人的实践，存在优化空间

<details><summary> 项目使用的 eBPF Hook point 详情 </summary>
<p>

| Hook                                       | Status & Description                     |
| :----------------------------------------- | :------------------------------------    |
| tracepoint/module/module_load              | ON & 提取*.ko文件相关信息                                      |
| tracepoint/syscalls/sys_exit_finit_module | ON & 触发系统调用表检查                                       |
| tracepoint/syscalls/sys_enter_mount       | ON                                     |
| tracepoint/syscalls/sys_exit_mount        | ON                                       |
| tracepoint/syscalls/sys_enter_open        | ON                                       |
| tracepoint/syscalls/sys_exit_open         | ON                                    |
| tracepoint/syscalls/sys_enter_openat      | ON                                     |
| tracepoint/syscalls/sys_exit_openat       | ON                                     |
| tracepoint/syscalls/sys_enter_execve      | ON                                       |
| tracepoint/syscalls/sys_enter_execveat    | ON                                     |
| tracepoint/syscalls/sys_enter_kill        | ON & 基于信号系统实现功能分发                                   |
| tracepoint/syscalls/sys_enter_memfd_create| ON & 无文件攻击相关                                    |
| kprobe/kprobe_lookup_name                 | ON & kprobe framework相关函数                                    |
| kprobe/arm_kprobe                         | ON & kprobe framework相关函数                                   |
| kprobe/insn_init                          | ON & 篡改内存代码行为相关函数                                   |
| kprobe/insn_get_length                    | ON & 篡改内存代码行为相关函数                           |
| lsm/cred_prepare                          | OFF(only ON in lsm branch) & 基于lsm阻断insmod                                    |
| lsm/kernel_read_file                      | OFF(only ON in lsm branch) & 基于lsm阻断无文件加载攻击                                  |

</p></details>

# todo

#### todolist

* [ ] 检测中断向量表idt_table 0X80号软中断系统调用服务表项的修改。和系统调用表检查类似，检查idt_table[0X80]的地址值是否变化或者超出范围
* [ ] 容器逃逸相关检测。示例截图、完善原理文档
* [ ] Nofile attack 无文件攻击文档工作。示例截图、完善原理文档
* [ ] 完善文件的fop检查，相关内容bpftrace-hook-demo仓库kern_hook_demo中的security_file_permission

Complete documentation... 

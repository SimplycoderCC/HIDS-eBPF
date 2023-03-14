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

# todo
Complete documentation... 

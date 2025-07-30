#  D-LINK DIR-815多次溢出漏洞   
原创 curve  SecNL安全团队   2024-12-26 12:31  
  
title: D-LINK DIR-815多次溢出漏洞               
author: 1ens                                                   tags:   - 漏洞复现                             categories:   - iot                                         date: 2022-08-25    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibgDMsGU712ibyaGtsJtYykuuWIXmzF1ricqKuM0UfH1Y6HDj6lAks8g0A/640?wx_fmt=gif&from=appmsg "")  
  
  
**准备**  
  
参考：  
[原创  
]  
家用路由器漏洞挖掘实例分析[图解D-LINK DIR-815多次溢出漏洞]-智能设备-看雪论坛-安全社区|安全招聘|bbs.pediy.com  
  
 该漏洞的描述位于  
这里  
，可知漏洞出现在  
hedwig.cgi  
文件中，漏洞产生的原因是Cookie的值超长造成缓冲区溢出。首先了解一下  
cgi  
文件。  
> cgi(Common Gateway Interface)  
，通用网关接口。运行在服务器上提供同客户端 HTML 页面的接口的一段程序。  
  
  
固件下载地址  
  
http://legacyfiles.us.dlink.com/DIR-815/REVA/FIRMWARE/DIR-815_REVA_FIRMWARE_v1.01.ZIP  
  
binwalk解压固件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibYTB9o5fNoGzn0NuEjQlYHUghDj8ibXxYCbqicDwfTcwTuZOAsY4976uw/640?wx_fmt=png&from=appmsg "")  
  
  
查看  
**bin/busybox**  
得知是MIPS32，小端：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibxuF74ib7LIcENbraHicL46SrPyaqofCp9aFibfAbibxRiceVNJuWZEyCL2A/640?wx_fmt=png&from=appmsg "")  
  
###   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibgDMsGU712ibyaGtsJtYykuuWIXmzF1ricqKuM0UfH1Y6HDj6lAks8g0A/640?wx_fmt=gif&from=appmsg "")  
  
****  
****  
**寻找线索**  
  
###   
  
find . -name '*cgi'  
查找文件  
  
并  
ls -l ./htdocs/web/hedwig.cgi  
发现hedwig.cgi是指向./htdocs/cgibin的符号链接，也就是说真正的漏洞代码在cgibin中。   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibgDMsGU712ibyaGtsJtYykuuWIXmzF1ricqKuM0UfH1Y6HDj6lAks8g0A/640?wx_fmt=gif&from=appmsg "")  
  
  
**静态分析**  
  
IDA静态调试  
cgibin  
文件，  
hedwigcgi_main  
函数处理整个过程，由于是  
HTTP_COOK  
这个字段引起的漏洞溢出点，可以在IDA（SHIFT+F12）搜索字符串，然后通过X，交叉引用来跟踪到  
hedwigcgi_main  
函数条用的位置。  
  
跟踪到主函数的位置hedwigcgi_main，对函数功能进行大致分析，可以定位到其中的  
sprintf  
函数引起了栈溢出。调用  
sess_get_uid  
，得到  
HTTP_COOKIE  
的值。同样创建两个指针数组  
a1,a2  
，以等号为界将前半部分存入  
a1  
偏移为5处，后半部分存入  
a2  
偏移为5处，  
a1[5]  
为  
uid  
则将  
a2[5]  
存入参数指针数组的偏移为5处。函数  
sobj_get_string  
获得该数组中指向  
cookie  
的指针。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibB8VwCWXde6jYOnKiaUryT31wukMkyUvxc1nibia2VxcO4PLRshztxxcdQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibgDMsGU712ibyaGtsJtYykuuWIXmzF1ricqKuM0UfH1Y6HDj6lAks8g0A/640?wx_fmt=gif&from=appmsg "")  
  
  
**IDA动态调试-确定偏移位置**  
  
程序通过 getenv 的方式获取 HTTP 数据包中的数据，流程应该为：  
```
```  
  
测试脚本test.sh  
```
```  
  
利用patternLocOffset.py生成content文件，包含特定格式的2000个字符串。类似于cyclic  
```
```  
  
在0x0409A38处断下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibUGs5f8fmg7WjwrIA0t0rrd6TRTiadjZAYI6mS6lsvyNoOz69kqCpwFw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibVUNouar7VicE1vY3icZGZEiazYUG1TGkXRo0oiarPEiclJ7uBSKE2B3JWow/640?wx_fmt=png&from=appmsg "")  
  
python patternLocOffset.py -s 0x38694237 -l 2000  
计算偏移：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibkdPuKOTj0OEDzIVW5SCS12OO9jsmXPh6y8IoQLw1NriagSXicJMUq7RA/640?wx_fmt=png&from=appmsg "")  
  
跟完  
sess_get_uid()  
函数可发现后面还有一个  
sprintf()  
，这里也会造成栈溢出，哪到底哪个才是真正的利用点呢  
  
从整个函数可以看出，  
fopen("/var/tmp/temp.xml", "w")  
的成功与否会导致程序走向这两个地方，即成功后是第二个  
sprintf()  
为溢出利用点，而失败时是第一个  
sprintf()  
为溢出利用点  
  
如果   
fopen("/var/tmp/temp.xml", "w")  
 打开成功则会执行到第二个   
sprintf  
，因为没有实机没法判断实际固件中是否有这个目录  
  
因此我们手动创建该目录及文件  
```
```  
  
这里假设第二个  
sprintf()  
为漏洞点（其实是第一个还是第二个对于用户模式下的调试并没有多大关系，就是偏移不一样罢了，构造 rop 链方法都是一样的），所以偏移得重新计算  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibK9iaWjSPYo94cKBVico80kBsZYu30Q8KSpk3vETyB1V9EItribts0OqQw/640?wx_fmt=png&from=appmsg "")  
  
但是haystack为0的话无法走到第二个sprintf  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibtyKKGibCDR38kptsbLlCrRWGJgvedX1ky2JVkWZyPlzMBZcIuxkqoQw/640?wx_fmt=png&from=appmsg "")  
  
交叉引用找到这  
  
动调可知在sub_402B40函数，这里影响着haystack的赋值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibeJmJu4VfURM2iaw7behWKibKSI7qydBGWE1EUmiahtNTId3ShCQxpicuQw/640?wx_fmt=png&from=appmsg "")  
  
这部分前面的代码，可知随便传点参数即可  
  
参考  
D-Link DIR-815 路由器多次溢出漏洞分析 | Lantern's 小站  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibgZAySNRda0nQoBXPPTDs4YXpawfVrBUKTeyUEicpjtIPibl28ia4yZhNw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibNrumRZTM3JbnxJD5m4hkdzxdYichkXayp6Swh4ZichzXyDRJNE8s9Aww/640?wx_fmt=png&from=appmsg "")  
  
最终的偏移为1009.  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibgDMsGU712ibyaGtsJtYykuuWIXmzF1ricqKuM0UfH1Y6HDj6lAks8g0A/640?wx_fmt=gif&from=appmsg "")  
  
  
**ROP 链的构造**  
  
#### gdb-multiarch+QEMU动态调试分析验证  
  
1，通过gdb指定脚本调试（避免重复输入，重复造轮子浪费时间）  
```
```  
  
执行 #一定要加载文件htdocs/cgibin不然vmmap得不到结果  
```
```  
  
-x是指定要执行的命令文件  
  
but...还是每找到完整的vmmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ib7Y0m2f6gennNIqJfo9XkTKKAh961ZOWjWBGlwpnnmTLUIytF0sVj9Q/640?wx_fmt=png&from=appmsg "")  
  
但实际上，我们查看   
lib  
 目录下的   
libc.so.0  
 即可知  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibXXCibOiaUMqYm0wlsLickyWVHQvyhtJDt5sdictGABREhdia5K02HI0LV5g/640?wx_fmt=png&from=appmsg "")  
  
找到systeam的地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibUYF8lIv05pVSbwydKJjev7kpiay1KGlqDrsUanKPdCeupRhuN95hsCQ/640?wx_fmt=png&from=appmsg "")  
  
另外一种方法  
```
```  
  
得到 system address: 0x7f78b200  
  
  
然后便是找一个能将   
system()  
 首个参数写入   
$a0  
 的 gadget，这里在   
libuClibc-0.9.30.1.so  
 中使用   
mipsrop  
 插件，利用   
mipsrop.stackfinder()  
 命令找将栈上数据放入寄存器的 gadget：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibQ016LPnh43PPtM1WX96JMLxQuJBGrSjP0DQh3uymT6t7Oibr3o1SyoQ/640?wx_fmt=png&from=appmsg "")  
  
打开 mips rop gadgets  
  
然后命令行输入mipsrop.stackfinders()  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ib1SLIKBDolRpDS0QWUkEqz0zc5wyM3BLrVAJSr6CH2ibx2rtKgksE3Pw/640?wx_fmt=png&from=appmsg "")  
  
选择0x159cc的指令。该指令序列首先将SP+0x10（动调）地址存入寄存器S5中，而在偏移0x159EO处将$S5作为参数存入 Sa0，也就是说，这里需要将第一步得到的system地址填充到$So中，然后在$SP+0x10处填充需要执行的命令，即可实现对system(""command")函数的调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51iby9rSmIGrXIXicfUGTUPjnTgrCib54riaxGcrFn213tE1WDnlH8TFRXRiaw/640?wx_fmt=png&from=appmsg "")  
  
  
因为 system地址的最低位为0x00，而在 hedwig_main获取Cookie的过程中，也没有对这部分数据进行解码，所以，试图通过访问 hedwig.cgi时对Cookie进行编码来避开0x00是不可能的，这就使 sprintf函数可能被截断，造成缓冲区溢出失败。为了避开   
0x00  
，写入时- 1  ，后面再找一个 gadget 加一即可  
  
  
hedwigcgi_main()  
 结尾部分：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibBXGhkVqu1BpGDTwgqtiaQ3jKSw1qeQMj6UKk1pccJYMw0xibf4wzPcicg/640?wx_fmt=png&from=appmsg "")  
  
修改  
```
```  
  
ROP的思路  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibBJWWjNhdyib68qSFWNfLHJB9v9t8KWs8PHKrb64CLHFUpDW9WsEvVog/640?wx_fmt=png&from=appmsg "")  
  
  
```
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibgDMsGU712ibyaGtsJtYykuuWIXmzF1ricqKuM0UfH1Y6HDj6lAks8g0A/640?wx_fmt=gif&from=appmsg "")  
  
  
**qemu系统模式**  
  
这里主要是为了在qemu虚拟机中重现http服务。  
  
/sbin/httpd  
应该是用于监听web端口的http服务，同时查看  
/htdocs/web  
文件夹下的cgi文件和php文件，可以了解到接受到的数据通过php+cgi来处理并返回客户端。  
  
find ./ -name '*http*'  
找到web配置文件httpcfg.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibVOOk6aD0Bg8MHBGoFnBNJROPlWEB9DfWf8YY6lyVqpg4ewks0IzL0Q/640?wx_fmt=png&from=appmsg "")  
  
查看内容后分析出  
httpcfg.php  
文件的作用是生成供所需服务的  
配置文件  
的内容，所以我们参照里面内容，自己创建一个conf作为生成的  
配置文件  
，填充我们所需的内容。（留个坑，暂时没搞懂）  
```
```  
  
使用qemu-system-mipsel从系统角度进行模拟，就需要一个mips架构的内核镜像和文件系统。可以在如下网站下载：  
Index of /~aurel32/qemu  
  
因为是小端，这里直接选择mipsel，然后下载其中两个文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ib10oPdZKuEHbtGYjNnokNdzibs6NxfSf8bznHib9ObUO7vKCRibibIGUl5Q/640?wx_fmt=png&from=appmsg "")  
  
**debian_squeeze_mipsel_standard.qcow2**  
是文件系统，  
**vmlinux-3.2.0-4-4kc-malta**  
是内核镜像  
  
启动脚本start.sh  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kR3MmOkZ9r58ibXiafdLabavePlMptNMyKuOYIjaMGv7qPB2MUGZiaqYMuD0fFhBCMgFK4UN9XcJXwOsaicFPRNhHw/640?wx_fmt=png "")  
  
输入用户名/密码 root/root或user/user即可登录qemu模拟的系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ib9OrXOdn7ibkWXVAZzxfibCYN8RBNic82V804iarsgWV06zCaanYhHUNFGg/640?wx_fmt=png&from=appmsg "")  
  
接下来在宿主机创建一个网卡，使qemu内能和宿主机通信。  
  
安装依赖库：  
```
```  
  
在宿主机编写如下文件保存为net.sh并运行：  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibP4yKEvujSyFz1aWuZ0ZbJaicJQ8kRV0UZxQTyUKzvVEFQA6JeeJN4Wg/640?wx_fmt=png&from=appmsg "")  
  
然后配置qemu虚拟系统的路由，在qemu虚拟系统中编写net.sh并运行：  
```
```  
  
eth0的网卡是192.168.100.2并且可以和宿主机ping通表示成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibZaES7ygLSmISOQ4nAvZgjnibib99fXrpOFNGzWp0RXF9qv1eRsZIdmtQ/640?wx_fmt=png&from=appmsg "")  
  
随后使用  
scp  
命令将binwalk解压出来的  
**squashfs-root**  
文件夹上传到qemu系统中的  
**/root**  
路径下：  
```
```  
  
然后在qemu虚拟系统中将  
**squashfs-root**  
文件夹下的库文件替换掉原有的，此操作会改变文件系统，如果不小心退出了虚拟系统，再次启动qemu时会失败，原因是因为改变了文件系统的内容。此时需要使用新的文件系统，因此在此操作之前可以先备份一份。编写auto.sh并执行：  
```
```  
  
接下来在qemu虚拟系统的根目录（ / ）下，创建一个名为conf的文件，此文件是httpd服务的配置文件。内容如下：  
```
```  
  
最后启动httpd服务：  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibuVkCMtJr8XtVZSUXUmBbZ3Lf8wicoGia3RDCCVM7a02lgMHkGI8ib9NLw/640?wx_fmt=png&from=appmsg "")  
  
这里访问失败是因为hedwig.cgi服务没有收到请求，需要提前配置qemu虚拟环境中的  
REQUEST_METHOD  
等方法，因为httpd是读取的环境变量，这里就直接通过环境变量进行设置：  
```
```  
  
这里在qemu虚拟系统中运行hedwig.cgi，再次访问  
http://192.168.100.2:4321/hedwig.cgi  
就可以正常收到内容了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibQ2ibJBzSZkVHaBWp7nnHaREvGPN8QP0QXqeWHPvunXLykA5kZGFW0zQ/640?wx_fmt=png&from=appmsg "")  
  
接下来就是使用gdbserver对hedwig.cgi进行调试了。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibgDMsGU712ibyaGtsJtYykuuWIXmzF1ricqKuM0UfH1Y6HDj6lAks8g0A/640?wx_fmt=gif&from=appmsg "")  
  
  
**gdbserver调试**  
  
动态调试确定偏移但是在那之前需要关掉地址随机化，因为qemu的虚拟机内核开启了地址随机化，每次堆的地址都在变化，导致libc的基地址也不断在变，所以需要关闭地址随机化  
```
```  
  
注：正常路由环境和 MIPS 虚拟机中为了程序运行速度会取消 canary，地址随机化等保护机制  
  
这里需要提前将 MIPSEL 架构的 gdbserver 传到 qemu 虚拟机中，这里选择了别人编译好的   
gdbserver  
  
auto.shell  
```
```  
  
宿主机连接 gdbserver  
```
```  
  
这里我们终于可以看到vmmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibIeLfUbFT4WTtPtny6kLA2NLJdKF64w8pWe7zcZEoicWak89ajk3bW0A/640?wx_fmt=png&from=appmsg "")  
  
接下来是确定libc的基地址，需要先把环境变量配置好，不然/htdocs/web/hedwig.cgi很快就执行完，进程立马就结束了，就得不到maps。  
  
利用（注意根据会先pid规律，快速修改预测pid执行，否则maps地址数据不会出来）  
```
```  
  
**a&b 先执行a，在执行b，无论a成功与否都会执行b**  
。因为关闭了地址随机化，libc.so.0的基地址就是0x77f34000。这里的libc.so.0是指向libuClibc-0.9.30.1.so。所以libuClibc-0.9.30.1.so基地址为0x77f34000。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibVfuljgML71qsgKRJeMuu3yyexKDjCAGyB0v79aH2BsluLAZvxT9M6w/640?wx_fmt=png&from=appmsg "")  
```
```  
  
编写exp（注意是py2  
```
```  
  
生成的context通过scp拷贝到mips虚拟机~目录中并且在~目录下创造debug.sh  
```
```  
  
在宿主机运行  
```
```  
  
然后再mips虚拟机执行debug.sh  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMmIGMyHNTrZ6jLMTvzrg51ibKg9c6jj8DeryLtdGHjtxNicP6ZNEckZWFP8usWez8PKpDkH0QEDAonA/640?wx_fmt=png&from=appmsg "")  
  
getshell !  
  
  
**总结**  
  
  
  
****  
断断停停终于算是真正完整复现了第一个漏洞，dlink DIR-815，依照0day路由器漏洞挖掘还有师傅们的博客，对mips架构和qemu有了进一步的了解****  
  
  
  
  
  

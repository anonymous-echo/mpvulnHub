#  漏洞扫描神器 -- AWVS 24.4.24（win+Linux你懂的版）   
Pwn3rzs  Web安全工具库   2024-05-27 22:08  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。  
0x01 工具介绍  
AWVS（Acunetix Web Vulnerability Scanner）是一款专业的Web漏洞扫描工具，用于检测网站的安全漏洞  
。  
0x02 安装与使用  
一、替换host文件（C:\Windows\System32\drivers\etc\hosts）  
```
127.0.0.1  erp.acunetix.com
127.0.0.1  erp.acunetix.com.
::1  erp.acunetix.com
::1  erp.acunetix.com.

192.178.49.174  telemetry.invicti.com
192.178.49.174  telemetry.invicti.com.
2607:f8b0:402a:80a::200e  telemetry.invicti.com
2607:f8b0:402a:80a::200e  telemetry.invicti.com.
```  
  
二、替换文件  
```
wvsc.exe替换到下面位置：C:\Program Files (x86)\Acunetix\24.4.240427095\wvsc.exe
license_info.json和wa_data.dat替换到下面位置：C:\ProgramData\Acunetix\shared\license
```  
  
三、启动程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtiaFuCWcC2JVvxO6MUIwrG6PZ2LH800WaJLLeWWKOllAicd7e3qOwL7LbTSUNaojjusZzlE8oRVq8w/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
网盘下载链接：（解压密码：  
Pwn3rzs）  
  
Acunetix-v24.4.240427095-  
Linux-Pwn3rzs-CyberArsenal  
  
链接：https://pan.quark.cn/s/d41af1fef6bf  
  
Acunetix-v24.4.240427095-  
Windows-Pwn3rzs-CyberArsenal   
  
链接：https://pan.quark.cn/s/bc1d2fd8227e  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtiaFuCWcC2JVvxO6MUIwrG6ZC8g9tnbhMpMWTQ34mibGCaaQDdXEK728IUa2AOyGicW20Uh6WOPkvqQ/640?wx_fmt=png&from=appmsg "")  
  
京东购买链接：https://item.jd.com/10101315977240.html  
> 本书共27章，分为6篇。第1篇“Linux基础知识”主要介绍Linux系统概述、Linux基本操作、GCC/G++编译器、GDB调试器、开发环境搭建等；第2篇“C/C++语言基础知识”主要介绍C语言编程基础、数据类型、运算符、表达式、程序控制结构、数组与指针、函数、字符与字符串处理、结构体与共用体、C++语言编程基础等；第3篇“Linux系统编程”主要介绍文件操作、文件I/O操作、进程控制、进程间的通信与线程控制等；第4篇“Linux网络编程与数据库开等  
  
  
  
  

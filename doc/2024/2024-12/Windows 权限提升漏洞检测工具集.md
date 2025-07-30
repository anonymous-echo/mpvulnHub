#  Windows 权限提升漏洞检测工具集   
BC-SECURITY  夜组安全   2024-12-09 00:01  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WrOMH4AFgkSfEFMOvvFuVKicy48weID39VvUTddKTwHoS4mYSaY7uDz19jR8poiaEV61l6ib4XiacJicg/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
**工具介绍**  
  
Moriarty 是一个全面的 .NET 工具，它扩展了最初由 @_RastaMouse  
 开发的 Watson  
 和 Sherlock  
 的功能。它旨在枚举缺失的 KB，检测各种漏洞，并建议 Windows 环境中权限提升的潜在漏洞。Moriarty 结合了 Watson 和 Sherlock 的功能，增加了对新漏洞的增强扫描，并集成了额外的检查。  
  
  
**02**  
  
**支持检测系统版本**  
  
Windows 10（版本：1507、1511、1607、1703、1709、1803、1809、1903、1909、2004、20H2、21H1、21H2、22H2） Windows 11（版本：21H2、22H2） 服务器 2016、2019、2022  
  
**03**  
  
**支持检测漏洞**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UPU0M9BBDian4ibicPaT4jInm47dZeyX4libXFYhicU0KeYy41UAeGpVyh5c37bPic4mX2d6XXoictIUSsA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UPU0M9BBDian4ibicPaT4jInmu9on80ia4vKL6LyZCf3tqfZiaNzT3evyxK0Ppdbicy950Yib8Gz8be7KdA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UPU0M9BBDian4ibicPaT4jInmyq3ZY4H3lPtXdtsD4H1jMWsv1B0389OmVyFeOYJRKuJoibN75EicBveg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**工具使用**  
  
```
C:\> Moriarty.exe
███    ███  ██████  ██████  ██  █████  ██████  ████████ ██    ██
████  ████ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██     ██  ██
██ ████ ██ ██    ██ ██████  ██ ███████ ██████     ██      ████
██  ██  ██ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██       ██
██      ██  ██████  ██   ██ ██ ██   ██ ██   ██    ██       ██

                                                 v1.0
                                                 BC Security

 [*] OS Version: 22H2 (22621)
 [*] Enumerating installed KBs...
 [+] CVE-2023-36664 : VULNERABLE
  [>] https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection

 [+] PrintNightmare (CVE-2021-1675, CVE-2021-34527) : VULNERABLE
  [>] https://github.com/xbufu/PrintNightmareCheck/tree/main

 [*] Vulnerabilities found: 2/30
 [+] Scan Complete!
```  
  
  
  
  
**05**  
  
**工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【241209****】获取**  
**下载链接**  
  
  
**06**  
  
**往期精彩**  
  

							  
  
[ 哥斯拉webshell管理工具二次开发规避流量检测设备 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492924&idx=1&sn=6480fbcef03f510d24353a08df6010ef&chksm=c36ba1c4f41c28d259f68b38b90d0f126b59ceb669b272c7b458b12c0141901ce28c6e3cbece&scene=21#wechat_redirect)  

						  
  
  

							  
  
[ 解决X/Twitter推特的钓鱼信息，保护你的Web3资产安全 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492920&idx=1&sn=681b850f5562d56bd0b14839971a8dbc&chksm=c36ba1c0f41c28d678185c520ddef7470d0208fff4f24fa136fd307eb81bbed8934bf7f44b88&scene=21#wechat_redirect)  

						  
  
  

							  
  
[ POC集合，框架nday漏洞利用 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492910&idx=1&sn=09a010c00e7b570a4044e87718fd1ea4&chksm=c36ba1d6f41c28c0d43b32072e9bced88b6c22aa7e123b2e973b06ae4ef3de25d19c0b2d284f&scene=21#wechat_redirect)  

						  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557 "")  
  

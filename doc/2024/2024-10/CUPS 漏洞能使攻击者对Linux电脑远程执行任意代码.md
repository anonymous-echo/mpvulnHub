#  CUPS 漏洞能使攻击者对Linux电脑远程执行任意代码   
Zicheng  FreeBuf   2024-10-02 09:31  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGPvzARz4caOQrkrialGFPK0uk7Eoj8k7aPU1ibToalBBe49expJsM9Htw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
据BleepingComputer消息， Linux 系统中广泛使用的打印系统CUPS（Common UNIX Printing System）存在漏洞，能在受攻击的电脑上远程执行任意代码。  
目前该漏洞尚未有修复补丁。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibnhd8H7KzVZSU5z57tZxZu7CnstUX07KjEziclmCD3mrYGwOR0PZ5nwUJ8ORQ2Xk7ZUrAsicbibztmQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这些安全漏洞由 Simone Margaritelli 发现，被跟踪为 CVE-2024-47076 （libcupsfilters）、CVE-2024-47175 （libppd）、CVE-2024-47176 （cups-browsed） 和 CVE-2024-47177 （cups-filters），主要涉及到CUPS中的一个组件 cups-browsed。  
  
  
Cups-browsed 是一个守护进程，可以在本地网络中搜索网络打印机或共享打印机，并使它们可用于在计算机上打印。这类似于 Windows 和 Mac 在网络中搜索需要打印到的远程网络打印机。  
  
  
Margaritelli 发现，如果启用了 Cups-browsed 守护进程（大多数系统都没有启用），它就会监听 UDP 631 端口，默认情况下还允许从网络上的任何设备创建新打印机的远程连接。如果攻击者创建一个恶意 PostScript 打印机描述（PPD），就可手动将其公布给在 UDP 631 端口上运行的 cups-browsed 进程，从而导致远程设备自动安装恶意打印机，并使其可用于打印。如果该暴露服务器上的用户使用这些新打印机进行打印，PPD 中的恶意命令就会在计算机本地执行。  
  
  
虽然这是一个远程代码执行攻击，但攻击者必须克服一些障碍才能利用漏洞并真正实现远程代码执行。  
  
  
首先，目标系统必须启用 cups-browsed 守护程序（默认情况下通常不启用），才能在网络上公开其 UDP 端口。之后，攻击者必须诱骗用户从其本地网络上使用新出现的恶意打印机服务器进行打印。此外，UDP 在网络入口时被广泛禁用，并且该服务通常默认不开启。出于这些原因，Red Hat 已将这些缺陷评级为“重要”而非“严重”级别。  
  
  
虽然目前漏洞补丁仍在开发中，但 Red Hat分享了缓解措施，管理员可使用以下命令阻止 cups-browsed 服务运行并防止其在重启时自动启用：  
> sudo systemctl stop cups-browsed  
> sudo systemctl disable cups-browsed  
  
  
  
此外还可以使用以下命令来查明系统是否正在运行 cups-browsed：  
> sudo systemctl status cups-browsed  
  
  
  
如果结果显示 “Active：inactive ”，表明 cups-browsed 已被禁止。如果结果显示 “running” 或 “enabled”，并且 “BrowseRemoteProtocols” 指令在配置文件 /etc/cups/cups-browsed.conf 中包含值 “cups”，表明 cups-browsed正在运行，需要将其关闭。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://www.bleepingcomputer.com/news/security/cups-flaws-enable-linux-remote-code-execution-but-theres-a-catch/  
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

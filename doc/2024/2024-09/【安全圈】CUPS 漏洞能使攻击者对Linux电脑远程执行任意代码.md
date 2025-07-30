#  【安全圈】CUPS 漏洞能使攻击者对Linux电脑远程执行任意代码   
 安全圈   2024-09-29 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
据BleepingComputer消息， Linux 系统中广泛使用的打印系统CUPS（Common UNIX Printing System）存在漏洞，能在受攻击的电脑上远程执行任意代码。目前该漏洞尚未有修复补丁。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhQfYVBs0lSlkj4EPxYud05Il8QTLmz6qd2U0e0MIzibCyKFfz4kzibtbxVNjeTYa2SibbbvNyhUA90g/640?wx_fmt=jpeg&from=appmsg "")  
  
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
  
参考来源：  
CUPS flaws enable Linux remote code execution, but there’s a catch  
  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhQfYVBs0lSlkj4EPxYud05tvuftN39bTQW8iblNx66RSzNKtU50lkjIia6BnRLLvO3J184GdHkphFA/640?wx_fmt=jpeg "")  
[【安全圈】寻求刺激入侵视频监控系统，一男子被山东警方采取刑事强制措施](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064747&idx=1&sn=fe44287b6e0a4beac09f4f9d56e77faa&chksm=f36e67abc419eebd03ce06fff8f7c2a2d73416f50362f9005715217c13d189148f527f310d92&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljvHleU06H1K5XEeEtyFNIREJ5hcDlnfFsb4WHI9NvUJhheZsgiciaqYxGTwo3F9nSHbGPe4qILRQEg/640?wx_fmt=jpeg "")  
[【安全圈】ChatGPT 客户端曝“记忆”漏洞，黑客可令 AI “转发对话记录”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064747&idx=2&sn=794aa8ee4f38945f6c525525ffa0fcf1&chksm=f36e67abc419eebd4c6abf786ab80ae28d1d0f727283f05add4aa4ea22224aea23ccf3f15642&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhQfYVBs0lSlkj4EPxYud05R04n1GNiamgFoHW8X3cIPSYORkPrrfuGow4EOMsz29ic0gxtyg3l1ysw/640?wx_fmt=jpeg "")  
[【安全圈】OpenAI 被币圈黑客盗号，15 个月内第四起](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064747&idx=3&sn=e4142fa9f4eda9b5c369a8654b2163db&chksm=f36e67abc419eebdcffbd895bd53522f9f033139a8087730a91c1e0a9c932d756233aa0b7859&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhQfYVBs0lSlkj4EPxYud05dearFOXMlibLSMaL8WgFfqaNT1aYGLFrGdZfT3ksovB5aPdLIE8vmVw/640?wx_fmt=jpeg "")  
[【安全圈】起亚经销商网站曝出严重漏洞！黑客可在30秒内远程操控数百万辆汽车](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064747&idx=4&sn=0ad8e79bc37793bdec4e27ceccd86183&chksm=f36e67abc419eebd1f227c0320e2024d7e1443e23e6e656cc7b8c73ea12037871637df6270d4&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
  
  

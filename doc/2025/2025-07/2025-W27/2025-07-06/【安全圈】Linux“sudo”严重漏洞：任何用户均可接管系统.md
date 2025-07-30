> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070525&idx=1&sn=7b6337e89711c9e9f413dd1cb303bd76

#  【安全圈】Linux“sudo”严重漏洞：任何用户均可接管系统  
 安全圈   2025-07-06 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
全球数百万台Linux系统（包括运行关键服务的系统）现存在一个易于利用的新型sudo漏洞，可能允许未经授权的用户在Ubuntu、Fedora等服务器上以root权限执行命令。  
  
  
sudo是Linux系统中允许用户以root或超级用户身份运行命令的实用程序。Stratascale网络安全研究单元（CRU）团队发现了两个影响sudo的关键漏洞。  
  
  
安全研究人员警告称，任何用户都能快速获取无限制的系统访问权限。攻击者可利用此漏洞以root身份执行任意命令，完全接管系统。  
  
  
该漏洞首次出现在2023年6月发布的1.9.14版本中，已在2025年6月30日发布的最新sudo版本1.9.17p1中修复。漏洞利用已在Ubuntu和Fedora服务器上验证成功，但可能影响更多系统。  
  
  
报告指出：“这些漏洞可能导致受影响系统的权限提升至root级别。”  
  
  
研究人员敦促管理员尽快安装最新sudo软件包，因为目前没有其他解决方案。  
  
  
“默认sudo配置存在漏洞，”Stratascale网络安全研究单元的Rich Mirch解释道。  
  
  
研究人员已公开概念验证代码，其他团队也成功复现了该漏洞。  
  
### 漏洞涉及sudo的chroot功能  
  
  
关键漏洞存在于sudo中较少使用的chroot选项中。该选项用于修改特定进程的根工作目录，限制其对文件系统的访问。  
  
  
虽然本意是将用户限制在其主目录内，但漏洞允许用户突破限制并提升权限。利用此漏洞不需要为用户定义任何sudo规则。  
  
  
研究人员表示：“因此，如果安装了易受攻击的版本，任何本地非特权用户都可能将权限提升至root。”  
  
  
要利用此漏洞，攻击者需要在用户指定的根目录下创建文件，并欺骗sudo加载任意共享库。该文件定义了系统如何解析用户账户、组、主机名、服务等。  
  
  
sudo维护者已确认该问题，并在1.9.17p1版本中弃用了chroot选项。  
  
  
他们在公告中表示：“攻击者可利用sudo的chroot选项以root身份运行任意命令，即使他们未被列入sudoers文件。”  
  
  
Mirch的脚本演示了非特权攻击者如何创建临时目录、添加授予root权限的函数文件、编译恶意共享库，然后通过chroot选项欺骗sudo以提升的权限执行它。这样，攻击者就能完全控制系统。  
  
  
由于chroot选项会降低环境安全性，建议管理员避免使用该功能。  
  
  
数百万系统可能受此漏洞影响。德国媒体heise.de甚至发现，德国某大型云托管提供商新安装的Ubuntu虚拟机仍然存在漏洞，尽管补丁已经发布。  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】你的耳机在被偷听！20+音频设备曝出漏洞：索尼、Bose、JBL等沦陷](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070509&idx=1&sn=6cf6b923bca528cc5cc03d57ebcc2bf6&scene=21#wechat_redirect)  
  
  
  
[【安全圈】日本爱知全县初中模拟考试负责机构遭网络攻击，超 31 万考生信息面临泄露风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070509&idx=2&sn=d8450068896e47f71ebe3b313633bade&scene=21#wechat_redirect)  
  
  
  
[【安全圈】哥伦比亚大学遭网络攻击，黑客声称已获取横跨数十年的约 250 万份信息](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070509&idx=3&sn=9c6f34a3e9a356d9b39e0316991caf1e&scene=21#wechat_redirect)  
  
  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  

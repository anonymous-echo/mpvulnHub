#  【安全圈】微软的符号链接补丁造成了新的 Windows DoS 漏洞   
 安全圈   2025-04-25 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
Microsoft  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaK50E4nv3xvMMJaGjmwKyz3MEEoGO0hEGmkb21EQVARLW6u0QibARib5jMEqAYxibzKEjeV65PU27iaA/640?wx_fmt=png&from=appmsg "")  
  
微软最近发布的安全更新旨在修补一个严重的权限提升漏洞，但却无意中引入了一个新的重大缺陷。   
  
此修复程序现在允许非管理用户有效阻止所有未来的 Windows 安全更新，从而创建拒绝服务条件。 该补丁的意外后果凸显了软件安全的复杂性以及防止不可预见的漏洞的持续挑战。  
## 符号链接漏洞和微软的修复  
##   
  
2025 年 4 月，微软发布了安全更新以解决CVE-2025-21204漏洞，该漏洞被评为“重要”，CVSS 3.1 评分为 7.8。   
  
该漏洞涉及 Windows 更新堆栈中文件访问（“链接跟踪”）之前的不正确链接解析，从而允许授权攻击者在本地提升权限。  
  
为了缓解此漏洞，微软实施了一项修复程序，无论是否安装了 Internet 信息服务 (IIS) ，都会在所有 Windows 系统的系统驱动器上自动创建一个名为“ inetpub ”的文件夹。  
  
微软明确警告用户不要删除此文件夹，因为它是安全增强的一个组成部分。  
## 新的 DoS 漏洞  
##   
  
安全研究员 Kevin Beaumont 发现此修复程序引入了一个拒绝服务漏洞，允许非管理员用户永久阻止 Windows 安全更新。   
  
Beaumont 发现，通过简单的命令行操作，用户就可以创建一个破坏更新机制的连接点（Windows 中的一种文件系统重定向）。  
  
Beaumont 在他的研究中解释道：“非管理员（和管理员）用户都可以在 c: 中创建连接点。” 这种利用方法只需要标准用户权限和基本的命令行访问权限。  
  
可以通过一个简单的命令来利用此漏洞，该命令在受保护的 inetpub 文件夹和系统文件之间创建符号链接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaK50E4nv3xvMMJaGjmwKyzmlLNcc4w9cRpqmypW4dVKGStOTrpvZrfGjh95STnrm0XmR9HADMU9w/640?wx_fmt=png&from=appmsg "")  
  
此命令创建一个将 c:\inetpub 重定向到 Windows 记事本的连接点。建立此连接点后，Windows 更新在尝试与该文件夹交互时会遇到错误，导致更新失败或回滚。  
  
“此后，2025 年 4 月的Windows 操作系统更新（以及未来的更新，除非微软修复它）将永远无法安装——它们会出错和/或回滚。所以你只能继续使用没有安全更新的版本，”Beaumont 指出。  
  
该漏洞最令人担忧的方面是它不需要管理权限即可利用。   
  
标准用户可以在许多默认配置的系统上创建这些连接点，从而可能阻止在整个系统范围内安装关键的安全更新。这不仅仅是暂时的拒绝服务 - 而是一个持续存在的问题，直到有人手动解决连接问题或重新安装系统为止。   
  
安全专家警告称，恶意软件或恶意行为者可以轻松地编写脚本并部署该程序，以使系统容易受到其他攻击。大约两周前， 博蒙特向微软安全响应中心报告了他的发现，但尚未收到回复。在微软解决此问题之前，建议系统管理员监视系统驱动器是否存在异常连接点。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】警惕！新型恶意软件通过多层混淆技术劫持Docker镜像](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069259&idx=1&sn=326c3497b6e6e654a9628f4e662d3909&scene=21#wechat_redirect)  
  
  
  
[【安全圈】重大供应链攻击预警：XRP官方NPM包遭劫持植入私钥窃取程序](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069259&idx=2&sn=afe3ad55e70f079c97b674d104dfe7a4&scene=21#wechat_redirect)  
  
  
  
[【安全圈】加州蓝盾医保470万患者数据遭泄露，误配谷歌分析工具酿近年最大医疗隐私事件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069259&idx=3&sn=a34002c3f2e5b52241931f98f5e52646&scene=21#wechat_redirect)  
  
  
  
[【安全圈】新型钓鱼攻击预警：黑客滥用Google表单绕过邮件安检窃取凭证](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069259&idx=4&sn=37779dd9ac19192b61a98b1d6d0e8b44&scene=21#wechat_redirect)  
  
  
  
  
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
  
  

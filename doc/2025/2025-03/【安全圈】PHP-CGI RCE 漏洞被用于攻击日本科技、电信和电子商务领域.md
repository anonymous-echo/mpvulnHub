#  【安全圈】PHP-CGI RCE 漏洞被用于攻击日本科技、电信和电子商务领域   
 安全圈   2025-03-10 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljtQzdsf9H4L3lNyhBcZzPLtLsS4GAmNDiccictjVryRlFGG47n1XMic4WQCQicUZXY3VTD6d70hLI8KA/640?wx_fmt=png&from=appmsg "")  
  
自 2025 年 1 月以来，来源不明的威胁行为者被归咎于主要针对日本组织的恶意活动。  
  
思科 Talos 研究员 Chetan Raghuprasad在周四发布的技术报告中表示：“攻击者利用了漏洞CVE-2024-4577，这是 Windows 上 PHP 的 PHP-CGI 实现中的一个远程代码执行 (RCE) 缺陷，以获取受害机器的初始访问权限。”  
  
“攻击者利用公开的Cobalt Strike 套件‘TaoWu’的插件进行后期开发活动。”  
  
恶意活动的目标涵盖日本的科技、电信、娱乐、教育和电子商务领域的公司。  
  
一切始于威胁行为者利用 CVE-2024-4577 漏洞获取初始访问权限并运行 PowerShell 脚本来执行 Cobalt Strike 反向 HTTP shellcode 负载，以授予自己对受感染端点的持久远程访问权限。  
  
下一步需要使用 JuicyPotato、RottenPotato、SweetPotato、Fscan 和 Seatbelt 等工具进行侦察、权限提升和横向移动。通过使用名为 TaoWu 的 Cobalt Strike 套件插件，通过 Windows 注册表修改、计划任务和定制服务来建立额外的持久性。  
  
“为了保持隐秘，他们使用 wevtutil 命令擦除事件日志，从 Windows 安全、系统和应用程序日志中删除其操作的痕迹，”Raghuprasad 指出。“最终，他们执行 Mimikatz 命令，从受害者机器的内存中转储和窃取密码和 NTLM 哈希值。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljtQzdsf9H4L3lNyhBcZzPLgL86FXTVLSWC7j6YZFzMISoXjqXsM6Yj6WTdWYCa2lhgJOe6HR9SDg/640?wx_fmt=png&from=appmsg "")  
  
攻击的最终结果是黑客团队从受感染的主机窃取密码和 NTLM 哈希。对与 Cobalt Strike 工具相关的命令和控制 (C2) 服务器的进一步分析表明，威胁行为者将目录列表留在互联网上可访问，从而暴露了托管在阿里云服务器上的全套对抗工具和框架。  
  
以下列出了值得注意的工具 -  
- 浏览器利用框架 (BeEF)，一种公开可用的渗透测试软件，用于在浏览器上下文中执行命令  
  
- Viper C2 是一个模块化 C2 框架，可帮助执行远程命令并生成 Meterpreter 反向 shell 负载  
  
- Blue-Lotus 是一个 JavaScript webshell 跨站点脚本 (XSS) 攻击框架，可以创建 JavaScript webshell 负载来发起 XSS 攻击、捕获屏幕截图、获取反向 shell、窃取浏览器 cookie 以及在内容管理系统 (CMS) 中创建新帐户  
  
Raghuprasad 表示：“根据我们对其他后利用活动的观察，我们有信心认为攻击者的动机不仅限于获取凭证，例如建立持久性、提升到系统级权限以及可能访问对抗框架，这表明未来发生攻击的可能性。”  
  
来源：https://thehackernews.com/2025/03/php-cgi-rce-flaw-exploited-in-attacks.html  
  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】网络犯罪分子利用 DeepSeek 的流行度来传播木马化的 AI 客户端](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=1&sn=5600b75d725f6e90a4cbfddf6a7e10cc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】美国特勤局主导的行动查封了 Garantex 加密货币交易所](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=2&sn=aa8cff3d814795a2126e35071802a530&scene=21#wechat_redirect)  
  
  
  
[【安全圈】大规模网络攻击活动利用美国和中国的 4,000 个 ISP IP 进行凭证窃取和加密劫持](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=3&sn=5837f215d68ad78ddef593cdc7f26b35&scene=21#wechat_redirect)  
  
  
  
[【安全圈】虚假验证码网络钓鱼活动影响超1150个组织](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=4&sn=65d9fb1f0ec0515e698cff3981995b80&scene=21#wechat_redirect)  
  
  
  
  
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
  
  

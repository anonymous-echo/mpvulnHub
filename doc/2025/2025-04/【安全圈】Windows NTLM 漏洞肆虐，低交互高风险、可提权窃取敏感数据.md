#  【安全圈】Windows NTLM 漏洞肆虐，低交互高风险、可提权窃取敏感数据   
 安全圈   2025-04-19 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
科技媒体 bleepingcomputer 昨日（4 月 17 日）发布博文，报道称已有证据表明，黑客利用 Windows 漏洞（CVE-2025-24054），在网络钓鱼活动中，通过 .library-ms 文件诱导用户泄露 NTLM 哈希值，从而绕过身份认证和提升权限。  
  
微软已经在 2025 年 3 月的补丁星期二活动日中，**修复了该漏洞，但修复发布后仅几天，Check Point 研究人员便发现攻击活动激增，尤其在 3 月 20 日至 25 日期间达到高峰。**  
  
IT之家注：NTLM（New Technology LAN Manager）是微软的一种认证协议，通过哈希进行挑战-响应协商，避免明文密码传输。然而，NTLM 早已不安全，易受重放攻击和暴力破解等威胁。  
  
Check Point 观察到，攻击者通过钓鱼邮件发送包含 Dropbox 链接的 ZIP 压缩包，其中藏有恶意 .library-ms 文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgzdjGCOFk2icUicO0yvRZ6wZfcjlE74iaSPJWas2HSfFpic57FKviaJ7DQsKnUhSD0og2PQMvjtygCEUg/640?wx_fmt=jpeg&from=appmsg "")  
  
一旦用户解压文件，Windows Explorer 会自动与其交互，触发 CVE-2025-24054 漏洞，强制 Windows 连接到攻击者控制的远程 SMB 服务器，并通过 NTLM 认证泄露用户哈希。后续攻击甚至无需压缩包，仅下载 .library-ms 文件即可触发漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgzdjGCOFk2icUicO0yvRZ6wZZNnVMq8cLDeTyzPYRgWrzTFkVkm7msnNdia6iadCUgZDSRkeSH6rGf0A/640?wx_fmt=jpeg&from=appmsg "")  
  
Check Point 指出，攻击者控制的 SMB 服务器 IP 地址包括 159.196.128.120 和 194.127.179.157。微软警告称，该漏洞仅需最小的用户交互（如单击或右键查看文件）即可触发。  
  
此外，恶意压缩包内还包含“  
xd.url  
”、“  
xd.website  
”和“  
xd.link  
”等文件，利用旧版 NTLM 哈希泄露漏洞作为备用手段，泄露 NTLM 哈希可能导致身份验证绕过和权限提升。  
  
尽管 CVE-2025-24054 仅被评为“中等”严重性，但其潜在后果极为严重。专家强烈建议，所有组织立即安装 2025 年 3 月更新，并禁用不必要的 NTLM 认证，将风险降至最低。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】Linux中国开源社区官网正式关闭 因为Linux.cn域名因未知原因被冻结](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069156&idx=1&sn=6ef2bbd00ae7a1d822d2a2013daa1f34&scene=21#wechat_redirect)  
  
  
  
[【安全圈】维基百科提供免费的人工智能数据集来应对无休止的网络爬虫](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069156&idx=2&sn=d3b832b18265d7676875493143642d03&scene=21#wechat_redirect)  
  
  
  
[【安全圈】GoDaddy 域名注册错误导致 Zoom 全球中断](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069156&idx=3&sn=a1ad81c26b108e944c12422ac5c981f9&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Erlang/OTP SSH 远程代码执行漏洞 PoC 漏洞利用发布](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069156&idx=4&sn=b108806bca06e4e6ea54839526d21ed7&scene=21#wechat_redirect)  
  
  
  
  
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
  
  

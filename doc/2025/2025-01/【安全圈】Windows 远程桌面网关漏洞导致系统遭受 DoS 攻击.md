#  【安全圈】Windows 远程桌面网关漏洞导致系统遭受 DoS 攻击   
 安全圈   2025-01-15 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylggibe6wJDluKPQjAeh5MPR9HuuFeA7ibibQv1aFnoeBbUFIzM0QqY5px7SIbC4DrXiczicicLVUaFmyQKQ/640?wx_fmt=jpeg&from=appmsg "")  
  
微软披露了其 Windows 远程桌面网关 (RD 网关) 中的一个严重漏洞，该漏洞可能允许攻击者利用竞争条件，从而导致拒绝服务 (DoS) 攻击。  
  
该漏洞被编号为 CVE-2025-21225，已在该公司  
2025 年 1 月的补丁星期二更新  
中得到解决。  
  
当系统的行为取决于并发操作中事件的时间或顺序时，就会出现竞争条件漏洞，攻击者会利用这种不同步的情况。  
  
在 CVE-2025-21225（Windows 远程桌面网关（RD 网关）拒绝服务漏洞）的背景下，RD 网关服务在处理网络请求期间会出现竞争条件。  
### Windows 远程桌面网关漏洞  
  
该漏洞源自类型混淆问题，分类为**CWE-843：使用不兼容类型访问资源**  
。此漏洞允许攻击者利用与网络堆栈绑定的 RD 网关组件，使其可通过互联网远程利用。通过成功触发竞争条件，攻击者可以破坏 RD 网关服务的可用性。  
  
虽然现有连接不受影响，但新连接可能会被阻止，经过反复利用后可能会导致服务无法使用。  
  
这种类型的拒绝服务攻击对依赖 RD 网关进行安全远程访问的组织构成了严重风险。尽管该漏洞不会导致数据窃取或远程代码执行，但对系统可用性的影响却很大。  
  
该漏洞影响Windows Server的多个版本，其中包括：  
- **Windows Server 2016**  
（核心和标准安装）  
  
- **Windows Server 2019**  
（核心和标准安装）  
  
- **Windows Server 2022**  
（核心和标准安装）  
  
- **Windows Server 2025**  
（核心和标准安装）  
  
每个受影响的版本都已收到具有唯一标识符的安全更新。例如：  
- Windows Server 2019：更新 KB5050008（内部版本 10.0.17763.6775）  
  
- Windows Server 2022：更新 KB5049983（内部版本 10.0.20348.3091）  
  
- Windows Server 2025：更新 KB5050009（内部版本 10.0.26100.2894）  
  
要利用此漏洞，攻击者需要赢得竞争条件——对于熟练的威胁者来说，这是一项具有挑战性但并非不可能完成的任务。由于该漏洞可能会破坏关键服务，因此被评为“重要”，但目前尚未公开可用的漏洞利用代码。  
  
截至 2025 年 1 月 15 日，没有报告或证据表明   
CVE-2025-21225  
（Windows 远程桌面网关 (RD 网关) 拒绝服务漏洞）已被主动利用。此外，尚未披露此漏洞的概念验证 (PoC) 漏洞或公开的漏洞利用工具。  
### 缓解措施和建议  
  
微软已在其 2025 年 1 月安全更新中发布了补丁来解决此漏洞。强烈建议各组织立即应用这些更新，以降低被利用的风险。  
  
此外：  
- 确保强大的网络监控，以检测针对 RD 网关服务的异常活动。  
  
- 通过防火墙规则将 RD 网关的暴露限制在仅受信任的网络中。  
  
- 考虑为远程访问实施额外的安全层，例如 VPN 或多因素身份验证。  
  
2025 年 1 月补丁星期二  
更新解决了  
微软生态系统中的 159 个漏洞，包括 8 个零日漏洞和几个严重的远程代码执行漏洞。  
  
虽然 CVE-2025-21225 未被归类为严重级别，但它对服务可用性的潜在影响凸显了主动补丁管理和系统强化的重要性。  
  
随着网络威胁不断演变，各组织必须保持警惕，应用安全更新并监控系统是否存在入侵迹象。  
  
来源：https://cybersecuritynews.com/windows-rd-gateway-vulnerability/  
  
   END    
  
  
阅读推荐  
  
  
[【安全圈】2025年首个满分漏洞，PoC已公布，可部署后门](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652067342&idx=1&sn=533ba142831a3c994e00cb6ec7d6d36c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】AI抢不走的工作，微软力挺红队测试仍需人类“掌舵”](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652067342&idx=2&sn=7630e1838566bfaad814bfbeff239c32&scene=21#wechat_redirect)  
  
  
  
[【安全圈】不干净的视频评论区，攻击者利用Youtube传播窃密软件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652067342&idx=3&sn=488b956f65f869c09be3e3d7874e6d90&scene=21#wechat_redirect)  
  
  
  
[【安全圈】为网络安全研究人员定制的虚假漏洞利用攻击利用恶意软件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652067342&idx=4&sn=380dc9803cf52db7c5d1771d404c4279&scene=21#wechat_redirect)  
  
  
  
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
  
  

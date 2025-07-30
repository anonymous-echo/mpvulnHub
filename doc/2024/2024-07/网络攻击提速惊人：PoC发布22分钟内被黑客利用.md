#  网络攻击提速惊人：PoC发布22分钟内被黑客利用   
 网络安全应急技术国家工程中心   2024-07-16 15:22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176kiaR91jjEMMYPzVgV4nwPMJ9vxw6GRQW2zcAzUM0bIciaicZT2icnXe9nvwnZwnhpUOj7oHEOzhuq5ibg/640?wx_fmt=png&from=appmsg "")  
  
根据Cloudflare发布的2024年应用安全报告，黑客在漏洞概念验证（PoC）利用发布后仅22分钟便可在实际攻击中加以武器化。该报告涵盖了2023年5月至2024年3月期间的网络攻击活动，重点介绍了新兴威胁趋势。以下是报告的几个重点发现：  
  
**攻击大提速：22分钟内武器化PoC**  
  
Cloudflare每秒处理平均5700万个HTTP请求，持续观察到对已披露CVE的扫描活动显著增加，其次是命令注入和尝试利用公开发布的PoC。  
  
在报告调查期间，最常被攻击的漏洞包括Apache产品中的CVE-2023-50164和CVE-2022-33891，Coldfusion中的CVE-2023-29298、CVE-2023-38203和CVE-2023-26360，以及MobileIron中的CVE-2023-35082。  
  
一个典型的例子是JetBrains TeamCity中的身份验证绕过漏洞CVE-2024-27198。攻击者在该漏洞的PoC发布后仅22分钟便部署了基于PoC的利用（下图），几乎不给防御者留下任何修复机会。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbWUUBIicqRibamZsHw6kTzDypfevIKvTqYVz1zBHc9PrWo2xQibIzDA8moQGVvLBRl2ribRQoroc1elw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
黑客在22分钟内武器化了CVE-2024-27198的PoC 来源：Cloudflare  
  
**人工智能助力防御**  
  
报告指出，唯一能应对攻击提速的方法是使用人工智能迅速制定有效的检测规则。  
  
报告解释说：“漏洞PoC利用披露后的武器化速度通常比人类创建WAF规则或开发和部署补丁的速度更快。Cloudflare自己的安全分析团队也面临同样的挑战，这促使我们将人类编写签名和基于机器学习的方法相结合，以在低误报率和响应速度之间实现最佳平衡。”  
  
报告指出，某些攻击者专门针对特定CVE类别和产品，对如何快速利用新的漏洞披露颇有心得。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbWUUBIicqRibamZsHw6kTzDyvxnLsGyeFkHmbaXRxpgxHqjLNwQSRQqKZGExWiaFRZRn59oEjQ1C9kQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
2024年全球RCE漏洞日请求（攻击尝试）数量快速增长 来源：Cloudflare  
  
**DDoS攻击占互联网流量的6.8%**  
  
报告的另一个重要发现是高达6.8%的每日互联网流量来自分布式拒绝服务（DDoS）攻击，后者可导致在线应用和服务用户体验下降甚至不可用。  
  
相比于前12个月（2022-2023年）记录的6%，2024年DDoS攻击总量显著增长。  
  
Cloudflare表示，在大型全球网络攻击事件期间，恶意流量可能占所有HTTP流量的12%。  
  
“2024年第一季度，Cloudflare每天平均阻止2090亿次恶意HTTP请求（同比增长86.6%），相对于去年同期，这是一个相当惊人的增长。”Cloudflare在报告中表示。  
  
**参考链接：**  
  
https://www.cloudflare.com/2024-application-security-trends/  
  
  
  
原文来源  
：GoUpSec  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  

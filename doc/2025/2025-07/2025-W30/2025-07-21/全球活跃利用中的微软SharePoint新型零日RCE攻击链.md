> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651325214&idx=2&sn=751d846f97b99cfd0a5db9b0943b2a0c

#  全球活跃利用中的微软SharePoint新型零日RCE攻击链  
 FreeBuf   2025-07-21 10:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR385xfQfOZT3FGrBQUN2aE64xHLrUDEnwv6N0bOfEialDFibQLxdSic8dQR3lPoSE0iaNELicl00GJ0eoZw/640?wx_fmt=png&from=appmsg "")  
  
  
2025年7月18日晚间，Eye Security安全团队发现一起大规模利用新型Microsoft SharePoint远程代码执行（RCE）漏洞链的攻击活动，该漏洞链被命名为ToolShell。攻击者通过组合利用CVE-2025-49704和CVE-2025-49706两个漏洞，可在无需认证的情况下完全控制本地部署的SharePoint服务器。  
  
  
"这并非凭证泄露问题，而是已被武器化的Pwn2Own漏洞利用代码在野利用"，Eye Security特别强调。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR385xfQfOZT3FGrBQUN2aE64rcH1elJv2cAYEHXiakCFRt1CxUYHq176YxIOCxLcUwKWNXJRzyKKEjQ/640?wx_fmt=other&from=appmsg "")  
  
  
**Part01**  
## 漏洞技术细节  
##   
  
ToolShell攻击链包含两个关键漏洞：  
  
- CVE-2025-49706（CVSS 6.3）：SharePoint服务器欺骗漏洞  
  
- CVE-2025-49704（CVSS 8.8）：通过ToolPane端点触发的SharePoint RCE漏洞  
  
初步分析认为攻击需要有效凭证，但深入调查显示实际无需任何认证。报告指出："对/_layouts/15/ToolPane.aspx的POST请求特征非常明显...我们确信攻击全程未使用任何凭证"。  
  
  
**Part02**  
## 攻击手法分析  
  
  
攻击基于Code White GmbH曾在Pwn2Own上演示的概念验证代码，现已被完全武器化。成功利用后，攻击者可直接植入隐蔽的ASPX恶意负载而无需登录。已观测到的恶意文件spinstall0.aspx疑似基于Sharpyshell开发，其设计目的并非直接执行命令，而是窃取加密机器密钥。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR385xfQfOZT3FGrBQUN2aE64MOZ3rqzqic2G3XvibvGbM5rQspKbMHuzZa1YUc46KjCWm6K6zYZs1a2Q/640?wx_fmt=png&from=appmsg "")  
  
  
"这不是典型的网页后门...该页面通过调用.NET内部方法读取SharePoint服务器的MachineKey配置"，研究人员解释。这些密钥（如ValidationKey和DecryptionKey）用于生成有效的__VIEWSTATE令牌——这是ASP.NET的核心安全机制。获取密钥后，攻击者可使用ysoserial等工具签署恶意负载实现完全远程代码执行。  
  
  
"这些负载可嵌入任意恶意命令，并被服务器视为可信输入，最终在无需凭证的情况下完成RCE攻击链"，报告补充道。  
  
  
**Part03**  
## 影响范围与响应措施  
  
  
Eye Security扫描了8,000余台暴露在公网的SharePoint服务器，发现数十台已遭入侵。通过分析160字节的独特响应特征和spinstall0.aspx端点可识别受影响系统。  
  
  
截至7月19日，Palo Alto Networks Unit 42确认攻击仍在持续，观测到攻击者：  
  
- 通过PowerShell投放恶意ASPX负载  
  
- 窃取机器密钥建立持久化访问  
  
- 从可疑IP（如96[.]9[.]125[.]147）执行攻击模块  
  
微软已发布紧急补丁和安全指南，建议本地部署SharePoint的用户立即采取以下措施：  
  
- 安装7月补丁星期二发布的最新SharePoint更新  
  
- 扫描入侵痕迹，重点检查/ToolPane.aspx和/spinstall0.aspx路径  
  
- 检查加密密钥是否泄露，如已失窃需立即重新生成  
  
- 监控HTTP(S)外联连接和反向Shell活动  
  
**参考来源：**  
  
ToolShell: New SharePoint RCE Zero-Day Chain Under Active Global Exploitation  
  
https://securityonline.info/toolshell-new-sharepoint-rce-zero-day-chain-under-active-global-exploitation/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324992&idx=1&sn=8303e67651ddba23a73497aeb18955fa&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  

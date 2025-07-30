#  最新的 Ivanti SSRF 零日漏洞正在被大规模利用   
 网络安全应急技术国家工程中心   2024-02-07 16:21  
  
Bleeping Computer 网站消息，安全研究员发现 Ivanti Connect Secure 和 Ivanti Policy Secure 服务器端请求伪造 (SSRF) 漏洞（CVE-2024-21893 ）正在被多个威胁攻击者大规模利用。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibE7qkicW106hCFyjuYQykvcxvIy0FlZz1v1JRZ5IrypbnV8YFQQoavicVKkB1K5zD42BY9ic5aA2HyA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
2024 年 1 月 31 日，Ivanti 首次就网关 SAML 组件中的安全漏洞发出 CVE-2024-21893 警告，并将该漏洞判定为”零日状态“，一旦威胁攻击者成功利用安全漏洞，就可以轻松绕过身份验证并访问易受攻击设备（版本 9.x 和 22.x）上的受限资源。  
  
随后，威胁监测服务机构 Shadowserver 发现有多个威胁攻击者正在积极利用 SSRF 漏洞（其中有 170 个不同的 IP 地址试图利用 CVE-2024-21893 漏洞）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibE7qkicW106hCFyjuYQykvcQzpqIHPCJsQXeDB7N1icdZvFkB7NicWQKnibJ2Do11N71deJGARydG2dw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
CVE-2024-21893 漏洞的利用量远远超过近期修复或缓解的其他 Ivanti 漏洞，表明威胁攻击者的重点可能发生明显转移。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibE7qkicW106hCFyjuYQykvcTIjzNjdIRu99nooNZp5I4JbnAFvrfdKyx1AlFjajoog5bEt9NBpNpA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
最新 Ivanti 漏洞的利用量（来源：Shadowserver）  
  
2024 年 2 月 2 日，Rapid7 安全研究人员发布了概念验证（PoC）漏洞，此举可能帮助潜在威胁攻击者更好的利用 CVE-2024-21893 安全漏洞。但是 Shadowserver 指出，其网络安全人员在 Rapid7 报告发布前几个小时，就观察到威胁攻击者利用了 CVE-2024-21893 安全漏洞。  
  
这意味着威胁攻击者已经知道如何利用 CVE-2024-21893 安全漏洞对易受攻击的 Ivanti 端点进行不受限制、未经验证的访问。从 ShadowServer 的分析结果来看，目前有近 22500 台 Ivanti Connect Secure 设备暴露在互联网上，但目前尚不清楚有多少设备易受 CVE-2024-21893 安全漏洞的影响。  
  
# Ivanti 安全漏洞频出  
  
披露 CVE-2024-21893 安全漏洞的同时， Ivanti 还发布了影响同一产品的另外两个零点漏洞（CVE-2023-46805 和 CVE-2024-21887）的安全更新补丁。据悉，安全研究人员已经发现威胁攻击者成功入侵了设备，并安装 了webshell 和后门程序。1 月中旬，设备感染量达到峰值，约为 1700 次。  
  
鉴于多个关键零日漏洞正在被大规模利用、缺乏有效的缓解措施以及部分受影响产品版本缺乏安全更新，美国网络安全和基础设施安全局（CISA）已下令联邦机构断开所有 Ivanti Connect Secure 和 Policy Secure VPN 设备的连接，只有经过出厂重置并升级到最新固件版本的设备才能重新连接到网络。  
  
**参考资料：**  
  
https://www.bleepingcomputer.com/news/security/newest-ivanti-ssrf-zero-day-now-under-mass-exploitation/  
  
  
  
原文来源  
：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  

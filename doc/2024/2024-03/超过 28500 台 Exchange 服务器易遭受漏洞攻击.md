#  超过 28500 台 Exchange 服务器易遭受漏洞攻击   
 网络安全应急技术国家工程中心   2024-03-27 15:16  
  
Exchange Server 广泛应用于商业环境中，以促进用户之间的通信和协作，提供电子邮件、日历、联系人管理和任务管理服务。  
  
威胁监控服务Shadowserver宣布，其扫描仪已识别出大约 97000 个潜在易受攻击的服务器。这些 Microsoft Exchange 服务器极易受到严重性权限升级漏洞（跟踪为 CVE-2024-21410）的影响。  
  
该安全问题允许未经身份验证的远程攻击者对 Microsoft Exchange Server 执行 NTLM 中继攻击并提升其在系统上的权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ico822DGq9VANdawxPLhic5UkHZicfh7ibDkYRMKYxXNCgUdHOaVrL2QqvL2xF5IRNFURXRsbgibam9Bw/640?wx_fmt=jpeg&from=appmsg&wxfrom=13 "")  
  
在97000台服务器中，估计有 68500 台服务器的易受攻击状态，取决于管理员是否应用了缓解措施，而 28500 台服务器被确定容易受到 CVE-2024-21410 的攻击。  
  
受影响最严重的国家是德国、美国、英国、法国、奥地利、俄罗斯、加拿大和瑞士 。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ico822DGq9VANdawxPLhic5U0a0Y4EV8t6b0GK8jx3FEa4bFue5LxCFia0c8EYSkUicVL4HdRxS9xHLQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
服务器暴露数量最多的国家   
  
目前，CVE-2024-21410 还没有公开的概念验证 (PoC) 漏洞，这在一定程度上限制了利用该缺陷进行攻击的攻击者数量。  
  
为了解决 CVE-2024-21410，建议系统管理员应用 2024 年 2 月补丁星期二期间发布的 Exchange Server 2019 累积更新 14 (CU14) ，该更新将启用 NTLM 凭据中继保护。  
  
美国网络安全和基础设施安全局 (CISA) 还将CVE-2024-21410 添加到其“已知利用的漏洞”目录中，允许联邦机构在 2024 年 3 月 7 日之前应用可用的更新/缓解措施或停止使用该产品。  
  
利用 CVE-2024-21410 可能会带来严重后果，因为具有 Exchange Server 更高权限的攻击者可以访问电子邮件等机密数据，并将该服务器用作进一步攻击的武器。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/over-28-500-exchange-servers-vulnerable-to-actively-exploited-bug/  
  
  
  
原文来源  
：嘶吼专业版  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

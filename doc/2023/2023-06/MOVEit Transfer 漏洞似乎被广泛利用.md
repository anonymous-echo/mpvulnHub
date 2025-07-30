#  MOVEit Transfer 漏洞似乎被广泛利用   
 关键基础设施安全应急响应中心   2023-06-06 15:29  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaz5iaQYxGogsTLrpGoibpib7jzaL41K6pFH9DlhBajFeicZ4XOMWDvDCUQ65A4dGqEQrHsF10QYuR4YzGmtAibqxTPw/640?wx_fmt=png "")  
  
Progress Software 已在其文件传输软件 MOVEit Transfer 中发现一个漏洞，该漏洞可能导致权限提升和潜在的未经授权访问环境，该公司在一份安全公告中表示。   
  
在 MOVEit Transfer Web 应用程序中发现了一个 SQL 注入漏洞，可能允许未经身份验证的攻击者未经授权访问 MOVEit Transfer 的数据库。  
  
这取决于所使用的数据库引擎（MySQL 、Microsoft SQL Server 或 Azure SQL），攻击者除了执行更改或删除数据库元素的 SQL 语句外，还可能推断出有关数据库结构和内容的信息。   
  
MOVEit Transfer 旨在让企业在业务合作伙伴和客户之间安全地传输文件。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/UgrRwCweQXgWxzF5S6hegI9LQ7AVniaGl55C2awvSPT0K4ytLRBzH0ZG8cOsXYRt6qCTEpENHmwSEl97LM3AdKg/640?wx_fmt=png "")  
  
所有 MOVEit Transfer 版本都受此漏洞影响，Progress 在公告中表示。该公司已为版本 2021.0.6 (13.0.6)、2021.1.4 (13.1.4)、2022.0.4 (14.0.4)、2022.1.5 (14.1.5) 和 2023.0.1 (15.0) 提供补丁)。  
  
该漏洞尚未分配 CVE 和 CVS 分数。   
  
**该漏洞已被利用**  
  
几家网络安全公司报告称，威胁行为者可能已经利用了该漏洞。  
  
Progress Software 建议 MOVEit 客户至少在过去 30 天内检查未授权访问的指标，这意味着在漏洞被披露之前检测到攻击者活动。  
  
Rapid7 在博客中表示，截至 5 月 31 日，大约有 2500 个 MOVEit Transfer 实例暴露在公共互联网上，其中大部分似乎在美国。  
  
该公司已在多个客户环境中识别出相同的 web shell 名称，这可能表明存在自动利用。   
  
Web shell 代码可以首先确定入站请求是否包含名为 X-siLock-Comment 的标头，如果标头未填充特定的类似密码的值，则返回 404“未找到”错误。  
  
截至 2023 年 6 月 1 日，Rapid7 观察到的所有 MOVEit Transfer 利用实例都涉及 MOVEit 安装目录的 wwwroot 文件夹中文件 human2.aspx 的存在（human.aspx 是 MOVEit 用于网络的本机 aspx 文件界面）。   
  
**建议用户查看过去90天的活动**  
  
早在 2023 年 3 月 3 日，网络安全公司 GreyNoise 就观察到位于 /human.aspx 的 MOVEit Transfer 登录页面的扫描活动。  
  
虽然我们没有观察到与利用直接相关的活动，但我们观察到的所有 5 个试图发现 MOVEit 安装位置的 IP 都被 GreyNoise 标记为“恶意”以进行先前的活动。  
  
该公司在一篇博客文章中说，并补充说根据观察到的扫描活动，建议 MOVEit Transfer 的用户将审查潜在恶意活动的时间窗口延长至至少 90 天。   
  
同样，TrustedSec 还指出，自 2023 年 5 月 28 日以来，后门程序已上传到公共站点，这意味着攻击者可能利用阵亡将士纪念日假期周末获得了对系统的访问权限。也有关于受影响受害者的数据泄露的报告。  
  
**缓解建议**  
  
Progress 建议用户拒绝所有 HTTP (TCP/80) 和 HTTPS (TCP/443) 流量到 MOVEit 环境。  
  
请注意，这将阻止对系统的所有访问，但目前似乎未受影响的 SFTP/FTP 仍将有效。  
  
该公司还建议通过阻止入站和出站流量来隔离服务器，并检查环境中是否存在可能的危害指标，如果是，则在应用修复程序之前将其删除。  
  
近年来，文件传输解决方案一直是包括勒索软件集团在内的攻击者的热门目标。我们强烈建议 MOVEit Transfer 客户在紧急情况下优先考虑缓解措施，Rapid7 在帖子中说。   
  
CISA还发布了警告，敦促用户和组织遵循缓解措施以防止任何恶意活动。  
  
  
  
原文来源：网络研究院  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  

#  Veeam与IBM发布备份和AIX系统高危漏洞补丁   
 FreeBuf   2025-03-21 18:14  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
Veeam近日发布了安全更新，修复了其备份与复制软件中的一个关键安全漏洞，该漏洞可能导致远程代码执行。  
  
  
![Veeam](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38XwTgRA48WDosoh2GoRypxtyeULKtX18aclxJCyS86T8589FicrlJIL8J2tTDOoXCFu5hncVsGrTg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**高风险漏洞详情**  
  
  
  
该漏洞被标记为CVE-2025-23120，CVSS评分为9.9（满分10.0），影响12.3.0.310及之前所有版本12的构建。Veeam在周三发布的公告中表示：“该漏洞允许通过认证的域用户远程执行代码（RCE）。”  
  
  
安全研究员Piotr Bazydlo因发现并报告此漏洞而获得认可，该问题已在版本12.3.1（构建12.3.1.1139）中得到解决。  
  
  
根据Bazydlo和研究员Sina Kheirkhah的分析，CVE-2025-23120源于Veeam在处理反序列化机制时的不一致性，导致允许反序列化的类为内部反序列化提供了途径，而内部反序列化本应采用基于黑名单的机制来防止对高风险数据的反序列化。  
  
  
这意味着，攻击者可以利用黑名单中缺失的反序列化工具链来实现远程代码执行。  
  
  
反序列化工具链具体如下：1.  
Veeam.Backup.EsxManager.xmlFrameworkDs  
  
2.Veeam.Backup.Core.BackupSummary  
  
  
研究员指出：“任何属于Veeam服务器Windows主机本地用户组的用户都可以利用这些漏洞。如果服务器已加入域，任何域用户都可以利用这些漏洞。”  
  
  
**补丁的有效性和局限性**  
  
  
  
Veeam发布的补丁将上述两个工具链添加到现有黑名单中，但如果发现其他可行的反序列化工具链，该解决方案可能再次面临类似风险。  
  
  
**IBM AIX系统漏洞修复**  
  
  
  
CVE-2024-20439并不是Cisco近年来从其产品中移除的第一个后门账户。此前，该公司曾在Digital Network Architecture（DNA）Center、IOS XE、Wide Area Application Services（WAAS）和Emergency Responder软件中发现过硬编码凭证。  
  
  
与此同时，IBM也发布了修复程序，解决了其AIX操作系统中两个可能导致命令执行的关键漏洞。这些漏洞影响AIX 7.2和7.3版本，具体如下：  
  
1.CVE-2024-56346（CVSS评分：10.0）：一个不当的访问控制漏洞，可能允许远程攻击者通过AIX NIM master服务执行任意命令。  
  
2.CVE-2024-56347（CVSS评分：9.6）：一个不当的访问控制漏洞，可能允许远程攻击者通过AIX nimsh服务的SSL/TLS保护机制执行任意命令。  
  
  
**安全建议**  
  
  
  
尽管目前没有证据表明这些关键漏洞已被利用，但建议用户尽快应用相关补丁，以防范潜在的威胁。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif "")  
  

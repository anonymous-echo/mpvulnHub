#  Kimsuky 利用 BlueKeep RDP 漏洞入侵韩国和日本系统   
Rhinoer  犀牛安全   2025-04-28 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBkQ5YJHoFGVzHoiaXZ3e8hBqQZtZL6OLoKuxXA1UszPtaiaXcT01WynpTfC4qhzSlf0iabc0wwlrtKfg/640?wx_fmt=png&from=appmsg "")  
  
网络安全研究人员发现了一项新的恶意活动，该活动与朝鲜国家支持的威胁行为者Kimsuky有关，该行为者利用影响 Microsoft 远程桌面服务的现已修补的漏洞来获取初始访问权限。  
  
该活动被AhnLab 安全情报中心 (ASEC)命名为**Larva-24005 。**  
  
这家韩国网络安全公司表示： “在某些系统中，初始访问权限是通过利用 RDP 漏洞（BlueKeep，CVE-2019-0708）获得的。虽然在受感染的系统中发现了 RDP 漏洞扫描程序，但没有证据表明它已被实际使用。”  
  
CVE-2019-0708（CVSS 评分：9.8）是远程桌面服务中的一个严重蠕虫漏洞，可以启用远程代码执行，允许未经身份验证的攻击者安装任意程序、访问数据，甚至创建具有完全用户权限的新帐户。  
  
然而，攻击者要想利用该漏洞，需要通过 RDP 向目标系统远程桌面服务发送特制请求。微软已于 2019 年 5 月修复了该漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBkQ5YJHoFGVzHoiaXZ3e8hBqrc14qF9BOLGPCGGSj85INMI5fiaFp4kn69ibrmUCtdibicbe12XkKmRSsg/640?wx_fmt=png&from=appmsg "")  
  
威胁行为者采用的另一个初始访问媒介是使用嵌入文件的网络钓鱼邮件，这些文件会触发另一个已知的公式编辑器漏洞（CVE-2017-11882，CVSS 评分：7.8）。  
  
一旦获得访问权限，攻击者就会利用植入器安装名为 MySpy 的恶意软件和名为 RDPWrap 的 RDP 工具，并更改系统设置以允许 RDP 访问。MySpy 旨在收集系统信息。  
  
此次攻击最终导致部署 KimaLogger 和RandomQuery等键盘记录器来捕获击键。  
  
据估计，该攻击活动自 2023 年 10 月以来一直针对韩国和日本的受害者，主要针对韩国的软件、能源和金融行业。该组织瞄准的其他一些国家包括美国、中国、德国、新加坡、南非、荷兰、墨西哥、越南、比利时、英国、加拿大、泰国和波兰。  
  
  
信息来源 ：  
ThehackerNews  
  

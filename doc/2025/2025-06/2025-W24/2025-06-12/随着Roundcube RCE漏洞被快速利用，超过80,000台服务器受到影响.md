#  随着Roundcube RCE漏洞被快速利用，超过80,000台服务器受到影响  
鹏鹏同学  黑猫安全   2025-06-12 01:20  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceibIHGEHhMzClCFv0WQBE8TGvyEa9O7QbWsgSIOMvy1p6HKFtWOrOAP49xTSqzVd7UkV4H64qqTOug/640?wx_fmt=png&from=appmsg "")  
  
威胁攻击者在Roundcube关键远程代码执行漏洞（CVE-2025-49113）补丁发布数日后便发起大规模利用，已波及超80,000台服务器。  
  
Roundcube作为主流网页邮件平台，长期被APT28、Winter Vivern等高级威胁组织盯上。历史攻击案例显示，黑客常利用此类漏洞窃取登录凭证并监控敏感通信。这些攻击活动表明，未打补丁的系统——尤其是高价值目标——始终面临严峻风险。  
  
这项CVSS评分达9.9的关键漏洞（CVE-2025-49113）潜伏超十年后于上周曝光。攻击者可借此完全控制受影响系统执行恶意代码，使用户及机构陷入重大危机。漏洞发现者为FearsOff公司创始人兼CEO基里尔·菲尔索夫。  
  
美国国家标准与技术研究院（NIST）发布的公告指出："Roundcube Webmail 1.5.10之前版本及1.6.x系列1.6.11之前版本存在安全隐患，由于program/actions/settings/upload.php未对URL中的_from参数进行验证，导致经过身份验证的用户可通过PHP对象反序列化实现远程代码执行。"该漏洞已在1.6.11和1.5.10 LTS版本中修复。  
  
菲尔索夫评估该漏洞影响超5300万台主机（包括cPanel、Plesk、ISPConfig、DirectAdmin等管理工具），表示技术细节与概念验证代码即将公开。  
  
漏洞披露后，Positive Technologies公司研究人员宣布成功复现CVE-2025-49113漏洞，强烈建议用户立即升级至最新版本。Shadowserver基金会监测显示，目前全球仍有约84,000个互联网暴露的Roundcube实例未打补丁。  
  
  

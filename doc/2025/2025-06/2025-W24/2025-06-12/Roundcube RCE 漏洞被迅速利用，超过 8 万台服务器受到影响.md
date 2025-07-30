#  Roundcube RCE 漏洞被迅速利用，超过 8 万台服务器受到影响  
会杀毒的单反狗  军哥网络安全读报   2025-06-12 01:01  
  
**导****读**  
  
  
  
Roundcube 中的一个严重远程代码执行 (RCE) 漏洞在修补几天后被利用，影响了超过 80,000 台服务器。  
  
  
补丁发布几天后，威胁组织就利用了 Roundcube 中一个严重远程代码执行 (RCE) 漏洞（CVE-2025-49113 ），攻击了超过 80,000 台服务器。  
  
  
Roundcube 是一个流行的 Web 邮件平台，曾多次成为 APT28 和 Winter Vivern等高级威胁组织的攻击目标。过去，攻击者曾利用这些漏洞窃取登录凭证并监视敏感通信。  
  
  
上周，严重漏洞 CVE-2025-49113（CVSS 评分 9.9）被发现，该漏洞此前已潜伏十余年。攻击者可利用该漏洞控制受影响的系统并运行恶意代码，使用户和组织面临巨大风险。FearsOff 创始人兼首席执行官 Kirill Firsov 发现了该漏洞。  
  
  
NIST 发布的安全公告指出： “Roundcube Webmail 1.5.10 之前的版本和 1.6.11 之前的 1.6.x 版本允许经过身份验证的用户执行远程代码，因为 URL 中的 _from 参数未在 program/actions/settings/upload.php 中验证，从而导致 PHP 对象反序列化。”  
  
  
该漏洞已 在 1.6.11 和 1.5.10 LTS 版本中得到解决。  
  
  
该漏洞披露后，Positive Technologies 的研究人员宣布已在 Roundcube 中复现了 CVE-2025-49113 漏洞。专家敦促用户立即更新至 Roundcube 的最新版本。  
  
  
研究人员警告称 ，互联网上暴露的大约 84,000 个 Roundcube 实例仍未得到修补。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaELyoXPPYuVB7TPjsTC6GiagX2SwnCPon0SugzenIvORV2zRfNeE0n9fpV30wFXrdfrXyoJEvgSh6Q/640?wx_fmt=png&from=appmsg "")  
  
  
新闻链接：  
  
https://securityaffairs.com/178887/hacking/over-80000-servers-hit-as-roundcube-rce-bug-gets-rapidly-exploited.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  

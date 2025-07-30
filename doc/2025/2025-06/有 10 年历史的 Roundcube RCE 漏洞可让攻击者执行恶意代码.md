#  有 10 年历史的 Roundcube RCE 漏洞可让攻击者执行恶意代码   
会杀毒的单反狗  军哥网络安全读报   2025-06-04 01:00  
  
**导****读**  
  
  
  
Roundcube Webmail 中发现一个已有十年历史的严重安全漏洞，该漏洞可能允许经过身份验证的攻击者在易受攻击的系统上执行任意代码，从而可能影响全球数百万个安装。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFiaOEaWPiaNQG1WT0h3zf9iauibEFqMF2lVDKZudXjXqJ4GjQjREJXzxq92Q31Y7RicbuzEPSAH17nNzw/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞的编号为 CVE-2025-49113，CVSS 评分高达 9.9（满分 10.0），是近年来发现的最严重的漏洞之一。  
  
  
该漏洞影响 Roundcube Webmail 1.5.10 之前的所有版本以及 1.6.11 之前的 1.6.x 版本，影响范围惊人，涉及全球超过 5300 万台主机。  
  
  
该漏洞涉及流行的网络托管控制面板，例如 cPanel、Plesk、ISPConfig 和 DirectAdmin，它们将 Roundcube 捆绑作为其默认的网络邮件解决方案。  
  
  
迪拜网络安全公司 FearsOff 的创始人兼首席执行官 Kirill Firsov 发现了这个利用 PHP 对象反序列化的经过身份验证的远程代码执行漏洞。  
  
  
_from该安全漏洞源于文件内 URL 中的参数验证不足program/actions/settings/upload.php，导致恶意用户能够操纵序列化的 PHP 对象并在服务器上执行任意代码。  
  
  
Roundcube 一直以来都是  
APT  
组织的首要目标。该网络邮件平台此前存在的漏洞曾被 APT28 和 Winter Vivern 等  
APT  
组织利用。  
  
  
去年，身份不明的黑客试图利用 CVE-2024-37383 进行网络钓鱼攻击，旨在窃取用户凭证。  
  
  
最近，ESET 研究人员记录了 APT28 利用包括 Roundcube 在内的各种网络邮件服务器中的跨站点脚本漏洞来收集东欧政府实体和国防公司的机密数据。  
  
  
多国网络安全中心强烈建议各组织在全面测试后以最高优先级安装更新。目前已发布修复版本，包括 Roundcube Webmail 1.6.11 和 1.5.10 LTS，可修复此漏洞。  
  
  
使用 Roundcube Webmail 的组织应优先立即修补并实施增强的监控功能，以检测任何可能表明试图利用此严重漏洞的可疑活动。  
  
  
更多信息，参考fearsoff公司发布的安全公告：  
  
https://fearsoff.org/research/roundcube  
  
  
新闻链接：  
  
https://cybersecuritynews.com/10-year-old-roundcube-rce-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  

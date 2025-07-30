> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795544&idx=2&sn=c4b3f53fda7cbd38f267401a4b6af0eb

#  新漏洞使数百万台 Brother 打印机面临黑客攻击  
会杀毒的单反狗  军哥网络安全读报   2025-06-26 01:01  
  
**导****读**  
  
  
  
Rapid7 研究人员发现，Brother 和其他供应商的数百种打印机型号存在严重漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaFMuQGar8ibwIjPK4SkpNjGnWaibKSiaiaO6dKcS2fDoTrkxcFd9X05pZOeM5NXxviawSZJBfic868uLianw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该网络安全公司周三透露，其研究人员发现了影响 Brother 生产的多功能打印机的八个漏洞。  
  
  
这些安全漏洞已发现影响 Brother 的 689 款打印机、扫描仪和标签机型号，部分或全部漏洞还影响 46 款富士商业创新、5 款理光、6 款柯尼卡美能达和 2 款东芝打印机。  
  
  
总体而言，据信数百万企业和家庭打印机因这些漏洞而面临黑客攻击。  
  
  
其中最严重的漏洞编号为 CVE-2024-51978，严重等级为“严重”，可允许远程和未经身份验证的攻击者通过获取设备的默认管理员密码来绕过身份验证。  
  
  
CVE-2024-51978 可以与信息泄露漏洞 CVE-2024-51977 关联，利用该漏洞可获取设备序列号。而该序列号是生成默认管理员密码所必需的。  
  
  
Rapid7 解释说：“这是因为发现了 Brother 设备使用的默认密码生成程序。该程序将序列号转换为默认密码。受影响的设备在制造过程中会根据每个设备的唯一序列号设置默认密码。”  
  
  
有了管理员密码，攻击者就可以重新配置设备或滥用经过身份验证的用户执行功能。  
  
  
其余漏洞的严重程度评级为“中”和“高”，可被用于 DoS 攻击，迫使打印机打开 TCP 连接，获取已配置的外部服务密码，触发堆栈溢出，并执行任意 HTTP 请求。Rapid7 发现的八个漏洞中有六个无需身份验证即可利用。  
  
  
大约一年前，该网络安全公司通过日本 JPCERT/CC 向 Brother报告了其发现，而该供应商已发布公告告知客户这些漏洞。  
  
  
Brother 已修复大部分漏洞，但表示 CVE-2024-51978 无法在固件中完全修复。新的制造工艺将确保未来的设备不会受到攻击。对于现有设备，已有解决方法。  
  
  
JPCERT/CC、理光、富士、东芝和柯尼卡美能达也发布了公告。  
  
  
漏洞公告：  
  
https://support.brother.com/g/s/security/en/  
  
  
新闻链接：  
  
https://www.securityweek.com/new-vulnerabilities-expose-millions-of-brother-printers-to-hacking/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  

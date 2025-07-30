#  QNAP修复NAS、路由器软件中的严重漏洞   
Bill Toulas  代码卫士   2024-11-26 10:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**QNAP 在上周末发布安全通告，修复了多个漏洞，其中包括三个严重漏洞，用户应尽快予以修复。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQxCRwYqKgACgn1LYp12wLYawtQ8oJapniaViakib0AWH4x16nBD0GyT8RmWicoLPkbEZcInbuW1azX3A/640?wx_fmt=png&from=appmsg "")  
  
  
  
从 QNAP Notes Station 3（该公司NAS系统中所用的记笔记和协作应用）版本开始，受如下两个漏洞的影响：  
  
- CVE-2024-38643：对关键函数缺少认证可导致远程攻击者获得越权访问权限并执行具体的系统函数。缺少正确的认证机制很可能导致攻击者在没有事先凭据的前提下利用该缺陷，从而导致系统遭攻陷（CVSS v4评分9.3，“严重”级别）。  
  
- CVE-2024-38645：服务器端请求伪造 (SSRF) 漏洞可导致具有认证凭据的远程攻击者发送操控服务器端行为的构造请求，可能暴露敏感的应用数据。  
  
  
  
QNAP 已在 Notes Station 3 版本3.9.7中修复了这些问题，并建议用户更新至该版本或后续版本以缓解该风险。该安全公告还发布了更新指南。公告中还提到了两个漏洞CVE-2024-38644和CVE-2024-38646，它们是高危的（CVSSv4评分分别为8.7和8.4）命令注入和越权数据访问问题，要求高级别访问权限才能利用。  
  
  
**0****1**  
  
**QuRouter 缺陷**  
  
  
  
QNAP修复的第三个严重漏洞是CVE-2024-48860，影响 QuRouter 2.4.x 产品、QNAP的高速安全路由器系列产品。该漏洞的CVSS v4评分为9.5，是“严重”级别的OS命令注入漏洞，可导致远程攻击者在主机系统上执行命令。QNAP还修复了另外一个严重级别稍低的命令注入漏洞CVE-2024-48861，这两个漏洞均已在QuRouter版本2.4.3.106中修复。  
  
  
**0****2**  
  
**QNAP 修复其它漏洞**  
  
  
  
QNAP还修复了AI Core（AI引擎）、QuLog Center（日志管理工具）、QTS（NAS设备的标准OS）和QuTS Hero（QTS的高阶版本）中的漏洞。这些产品中最重要的漏洞概述如下，CVSS v4评分介于7.7至8.7，属于高危级别。  
  
- CVE-2024-38647：信息泄露漏洞，可导致远程攻击者获得对敏感数据的访问权限并攻陷系统安全。该漏洞影响 QNAP AI Core 3.4.x版本，已在3.4.1及之后版本中修复。  
  
- CVE-2024-48862：链接跟随 (link-following) 缺陷，可导致远程越权攻击者遍历文件系统并访问或修改文件，影响 QuLog Center 1.7.x 和 1.8.x 版本，已在1.7.0.831和1.8.0.888中修复。  
  
- CVE-2024-50396和CVE-2024-50397：对外部控制的格式字符串处理不当，可导致攻击者访问敏感数据或修改内存。CVE-2024-50396可遭远程利用，操控系统内存；而CVE-2024-50397要求用户级别的访问权限。这两个漏洞已在 QTS 5.2.1.2930和QuTS hero h5.2.1.2929中修复。  
  
  
  
强烈建议QNAP客户尽快安装这些更新，以防遭攻击。QNAP设备永远不应直接连接到互联网，而应当获得VPN保护，阻止对漏洞的远程利用。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[QNAP提醒注意NAS设备中严重的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519033&idx=2&sn=59f095fb0e0636ab2257aaf9cc7d7e27&scene=21#wechat_redirect)  
  
  
[QNAP 修复多款产品中的多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518617&idx=2&sn=6cbff27b3d2e598b07c8c757f85efbc9&scene=21#wechat_redirect)  
  
  
[CISA：FXC 路由器和 QNAP NVR 漏洞已遭在野利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518480&idx=1&sn=372723a1263ca0cbc9c63dfe1a68c98e&scene=21#wechat_redirect)  
  
  
[QNAP 修复两个严重的命令注入漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518080&idx=2&sn=71583bf9067a3f7b1848503bf006dce0&scene=21#wechat_redirect)  
  
  
[QNAP正在紧急修复两个0day，影响全球超8万设备](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516164&idx=2&sn=00deb0a15fae5034e3bbde0e1407178b&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/qnap-addresses-critical-flaws-across-nas-router-software/  
  
  
题图：  
Pixabay  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

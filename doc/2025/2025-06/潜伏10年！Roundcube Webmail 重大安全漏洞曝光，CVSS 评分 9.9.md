#  潜伏10年！Roundcube Webmail 重大安全漏洞曝光，CVSS 评分 9.9   
看雪学苑  看雪学苑   2025-06-04 09:59  
  
网络安全研究人员披露了 Roundcube Webmail 软件中一个未被发现长达十年的严重安全漏洞，该漏洞可能被利用来接管易受影响的系统并执行任意代码。  
  
  
该漏洞被追踪为 CVE - 2025 - 49113，CVSS 评分为 9.9（满分 10.0），是一种通过 PHP 对象反序列化实现的后认证远程代码执行漏洞。  
  
  
美国国家漏洞数据库（NVD）中对该漏洞的描述为：“Roundcube Webmail 1.5.10 之前的版本及 1.6.x 中 1.6.11 之前的版本存在漏洞，远程已认证用户可利用此漏洞执行代码，因为在 program/actions/settings/upload.php 中的 _from 参数未经过验证，导致 PHP 对象反序列化。”  
  
  
该缺陷影响所有 1.6.10 及更早版本的软件，已在 1.6.11 和 1.5.10 LTS 版本中得到修复。FearsOff 创始人兼首席执行官基里尔・菲尔索夫发现了该漏洞并进行了报告。  
  
  
这家总部位于迪拜的网络安全公司在一份简短的咨询报告中指出，计划在 “不久” 后公开更多技术细节和概念验证（PoC），以便用户有足够时间应用必要的补丁。  
  
  
此前披露的 Roundcube 安全漏洞已成为像 APT28 和 Winter Vivern 这类国家级威胁行为者的有利目标。去年，Positive Technologies 曝光称，未具名的黑客试图利用 Roundcube 漏洞（CVE - 2024 - 37383）实施网络钓鱼攻击，以窃取用户凭证。  
  
  
两周前，ESET 发现 APT28 利用了 Roundcube、Horde、MDaemon 和 Zimbra 等各类网络邮件服务器中的跨站脚本攻击（XSS）漏洞，收集东欧政府机构和国防公司特定电子邮件账户的机密信息。  
  
  
更新：Positive Technologies 在 X 平台发布的帖子中称，其能够复现 CVE - 2025 - 49113 漏洞，敦促用户尽快更新至最新版本的 Roundcube。这家俄罗斯网络安全公司补充道：“此漏洞允许已认证用户通过 PHP 对象反序列化执行任意命令。”  
  
  
  
资讯来源  
：  
thehackernews  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  

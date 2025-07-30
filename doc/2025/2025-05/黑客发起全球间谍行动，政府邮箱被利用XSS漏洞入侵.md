#  黑客发起全球间谍行动，政府邮箱被利用XSS漏洞入侵   
网络攻防情报小组  C4安全团队   2025-05-27 06:05  
  
近日，安全研究人员披露，一个名为**“RoundPress”**  
的全球网络间谍活动正在持续展开，攻击者通过 Webmail 服务中的数个XSS漏洞，对全球多国政府和关键机构发起邮件窃密攻击。该行动被认为与黑客组织 APT28（又称“Fancy Bear”或“Sednit”）有关。  
  
   
  
**一、行动时间跨度长，涉及目标广泛**  
  
这项网络间谍活动始于 2023 年，并在 2024 年持续扩展攻击范围。被攻击的 Webmail 系统包括 Roundcube、Horde、MDaemon 及 Zimbra。  
  
根据披露，遭到攻击的目标涵盖：  
1. 希腊、乌克兰、塞尔维亚、喀麦隆等**国家政府部门**  
；  
  
1. 乌克兰和厄瓜多尔的**军方单位**  
；  
  
1. 乌克兰、保加利亚、罗马尼亚的**国防企业**  
；  
  
1. 乌克兰和保加利亚的**关键基础设施单位**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQdSgKLoGRNHxosfWAF6q2LKojqTKW7bsAeyhvDMFl32K5CdYY6Fzib3Khrz5hicerQjmebl97PGr3g/640?wx_fmt=png&from=appmsg "")  
  
攻击目标分布（来源：ESET）  
  
   
  
**二、打开邮件即中招，攻击过程零交互**  
  
攻击从一封带有当前新闻或政治内容的钓鱼邮件开始，攻击者常引用**真实新闻片段**  
提升可信度。  
  
邮件正文中嵌入恶意 JavaScript 脚本，借助 Webmail 前端页面的 XSS 漏洞实现执行。受害者**仅需打开邮件即可触发攻击，无需点击链接、输入信息或其他操作**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQdSgKLoGRNHxosfWAF6q2LsyEz6MFDJRshjNPgJuVpxWvLzezUJfYO0PlvSiadtHiayibS2XCUic6T5A/640?wx_fmt=png&from=appmsg "")  
  
攻击链概述（来源：ESET）  
  
攻击脚本不具备持久化能力，但足以在一次执行中完成以下行为：  
1. 创建隐藏输入字段，引导浏览器或密码管理器**自动填充邮箱凭据**  
；![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQdSgKLoGRNHxosfWAF6q2LC4o2Clibic32HnCvtRyqYmNsNYjd9gwVib9B2lCo8moRIDm7yNVfp8gnA/640?wx_fmt=png&from=appmsg "")  
凭据窃取函数（来源：ESET）  
  
1. 读取页面 DOM 或发送 HTTP 请求，获取邮件内容、联系人、Webmail 配置、登录记录、2FA 设置及密码等信息；  
  
1. 将采集数据通过 HTTP POST 请求发送至攻击者控制的远程服务器。  
  
根据目标 Webmail 产品的不同，攻击脚本具备略有差异的功能模块，表现出**高度定制化**  
。  
  
   
  
**三**  
、**涉及多个严重 XSS 漏洞**  
  
“RoundPress” 行动利用了多个 Webmail 产品中的 XSS 漏洞，进行恶意 JavaScript 注入。具体漏洞包括：  
  
**1.Roundcube – CVE-2020-35730**  
  
2023 年被用于攻击的存储型 XSS 漏洞，攻击者将脚本嵌入邮件正文，用户在浏览器中**打开即被执行**  
，导致凭据和数据泄露。  
  
**2.Roundcube – CVE-2023-43770**  
  
2024 年初被利用的漏洞，Roundcube 在处理超链接文字时存在过滤不当问题，攻击者可插入 **<script>**  
标签实施攻击。  
  
**3.MDaemon – CVE-2024-11182**  
  
2024 年底被用作零日攻击的 HTML 解析器漏洞，攻击者构造畸形 title 属性及 noembed 标签，通过隐藏的**<img onerror>**  
实现 JavaScript 执行，获取凭据并**绕过双因素认证**  
。  
  
**4.Horde –****未确认 XSS 漏洞**  
  
黑客曾尝试在 **<img onerror>**  
 中注入脚本攻击 Horde，但疑因新版系统具备过滤机制未能成功，具体漏洞未被证实，疑似已被修复。  
  
**5.Zimbra – CVE-2024-27443**  
  
该漏洞出现在 Zimbra 的日历邀请处理功能，攻击者利用 X-Zimbra-Calendar-Intended-For 头部未过滤输入，实现 JavaScript 注入，在用户查看日历邀请时执行。  
  
虽然尚未发现 2025 年有明确的 RoundPress 攻击活动迹象，但研究人员指出，鉴于主流 Webmail 产品中仍持续曝出 XSS 漏洞，黑客组织所使用的攻击技术具备**高度可复用性**  
，仍对全球政府机构及关键行业构成潜在威胁。  
  
消息来源：  
  
https://www.bleepingcomputer.com/news/security/government-webmail-hacked-via-xss-bugs-in-global-spy-campaign/  
  
  
  
****  
**专栏介绍**  
  
Freebuf知识大陆内部共享资料截屏详情如下  
  
（每周保持更新，已更新 170+文档，扫码可免费预览）  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkzvdgfFtJotO7T8dD5ATKyyeuQibDwZoltOB3Uy5nRicGDxCEpwrlRYNg/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT7AzyPll3BkGK2UWYiaa1TPXPpichRjSPC19Mfy8sblsdtsoUsJhCn4SbVmlGgeibKTkD8Ima1icVic8Q/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&tp=wxpic "")  
  
  
  
**知识大陆——安全渗透感知大家族**  
****  
  
圈子券后现价   
￥39.9元/年       
￥59.9元/永久  
  
（新人优惠券折扣  
20  
￥，扫码即可领取优惠）  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJR7GIiatmMxDnlYcGJjOmibZcd7ribwq1zichkjwIczCqhZ1zpXib3VcJpMWlSLfa6qpXwfVy6hguOXdibA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
内部圈子——  
群  
友反馈，价格优惠，内容优质  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkZXuRl4vOBsaQwJK1AbsPcGMiczaPickCuIzicPiblfFjyjic3aeuzqVLLhg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJSiao22HdM7F7OBu4zNJicKjkpxDWia5shmzQH4UialWGUCsoWYMHVpcEtUxF7RsfJaHKl9gsVWEjqAuw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**课程专栏介绍--内部教程**  
  
团队内部课程如下，感兴趣的师傅扫码咨询  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQdSgKLoGRNHxosfWAF6q2LORrxiaqE2Kr7X3DtRbbrCsJrRgxwe5yNiaEnHIsn8HJrsia8UEutLphxA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQdSgKLoGRNHxosfWAF6q2LdocA5XthMthOr19wJZJlF0FeRoTaHiabKkfmiaS7tsDM2liceBUibbjLKg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
  
  
  
END  
  
  
  
关注Cod  
e4th安全团队  
  
了解更多安全相关内容~  
  
  
  
****#   
  
  

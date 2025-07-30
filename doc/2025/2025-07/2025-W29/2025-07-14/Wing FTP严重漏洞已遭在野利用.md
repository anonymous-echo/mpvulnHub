> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523565&idx=2&sn=3cc3fd02d7bb4c8d993138dce7afa3f6

#  Wing FTP严重漏洞已遭在野利用  
Ravie Lakshmanan  代码卫士   2025-07-14 10:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRbVcfGOx8mR4bewm9ZU6yNRPPvC15rCmYgZiaz6f5hBIpxjgpG2Tjrbiazv8CWxXKmhJs79rdicL2KQ/640?wx_fmt=gif&from=appmsg "")  
  
**网络安全公司 Huntress 指出，最近披露的影响 Wing FTP Server 的一个中危漏洞已遭在野活跃利用。**  
  
  
该漏洞的编号是CVE-2025-47812（CVSS评分10.0），是因为对服务器web界面的空字节 (‘\0’) 的处理不当造成的，可导致远程代码执行后果，已在7.4.4版本中修复。  
  
CVE.org上的一份相关安全公告提到，“用户和管理员 web 界面错误处理了 ‘\0’ 字节，最终导致任意Lua 代码被注入用户会话文件中。攻击者可通过FTP 服务（默认为root或系统）权限执行任意系统命令。”  
  
更令人担忧的是，可通过匿名 FTP 账号利用该漏洞。2025年6月，RCE   
  
Security 公司的研究员发布该漏洞的全面分析。网络安全公司 Huntress 表示，已发现威胁人员利用该漏洞下载并执行恶意 Lua 文件、实施侦查以及安装远程监控和管理软件。该公司的研究人员表示，“CVE-2025-47812源自空解字节在用户名参数中的处理方式（具体与 loginok.html 文件有关，该文件负责处理认证流程），它可导致远程攻击者在使用用户名参数的空解字节后执行 Lua 注入。通过利用该空解字节注入，攻击者可破坏存储这些会话特征的 Lua 文件中的预测输入。”  
  
该漏洞遭活跃利用的迹象首先出现在2025年7月1日的某个客户处，距离利用详情公开仅仅过去了一天的时间。在获得访问权限后，威胁人员据称已运行枚举和侦查命令，创建新用户以作为一种持久形式，并释放 Lua 文件为 ScreenConnect 释放一个安装工具。目前尚未有证据表明该远程桌面软件已被真正安装，因为该攻击是在它能够进一步发展之前被检测且被阻止的。目前尚不清楚该攻击的幕后黑手。  
  
Censys 发布数据显示，目前存在8103个运行 Wing FTP Server 的公开可访问设备，其中5004台的 web 界面遭暴露。这些实例大多数位于美国、德国、英国、印度等国家。  
  
鉴于已遭活跃利用，用户应立即采取措施，应用最新补丁并将 Wing FTP Server 更新至7.4.4或后续版本。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2025中国软件供应链安全分析报告》全文](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523516&idx=1&sn=0b6fc53ba92e7b5135395b67fff6a822&scene=21#wechat_redirect)  
  
  
[CrushFTP 提醒用户立即修复已遭利用的 0day 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519338&idx=1&sn=ec0b92257a640cd98dd5d59c00746548&scene=21#wechat_redirect)  
  
  
[CompleteFTP 路径遍历缺陷可导致服务器文件遭删除](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513283&idx=2&sn=1191567d5c667a5413e00d453ef8b5da&scene=21#wechat_redirect)  
  
  
[开源OS FreeBSD 中 ftpd chroot 本地提权漏洞 (CVE-2020-7468) 的技术分析](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499356&idx=1&sn=f95ec3f9ca222c3ccef3d1162af259b8&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/07/critical-wing-ftp-server-vulnerability.html  
  
  
题图：  
Pixabay Licen  
se  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523615&idx=2&sn=cac2857656da7d1c204446add8dfee9a

#  CrushFTP 新0day被用于劫持服务器  
Lawrence Abrams  代码卫士   2025-07-21 10:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**CrushFTP 提醒称，威胁人员正在积极利用一个0day漏洞CVE-2025-54309，它可导致攻击者通过易受攻击服务器上的web 接口获得管理员访问权限。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSgcm13K0zsHjTh0qiajXbCxmo8Xj9EI9RK48jlrI3Wibvqy54LDZHaYE0ADTBT36KHLgxAXuLaxdsw/640?wx_fmt=png&from=appmsg "")  
  
  
CrushFTP 是一款企业文件传输服务器，供组织机构通过FTP、SFTP、HTTP/S和其它协议以安全的方式分享和管理文件。CrushFTP 表示，威胁人员最初在美国中部时间7月18日上午9点检测到漏洞遭利用，不过利用可能是在前一天的更早时候。  
  
CrushFTP的首席执行官 Ben Spink 表示，他们此前修复了HTTP (S) 中于 AS2 相关的一个漏洞，这可能也拦截了这个新0day漏洞。Spink 表示，“之前的一个修复方案偶然也拦截了这个漏洞，但之前的修复方案针对的是一个不同的问题，并默认关闭了一些很少用的特性。”  
  
CrushFTP 表示，它认为威胁人员逆向工程其软件并发现了这个新漏洞，在未更新的设备上开始利用该信漏洞。CrushFTP 在安全公告中提到，“我们认为该漏洞位于大概在7月1日之前发布的版本中……CrushFTP 的最新版本已修复该漏洞。该攻击向量是如何利用该服务器的HTTP (s)。我们已经修复了于HTTP (S) 中与AS2相关联的另外一个问题，并未意识到之前的这个漏洞可像新漏洞这样利用。黑客显然看到了我们的代码变更，并找到了利用之前漏洞的方式。和以往一样，我们建议定期和经常打补丁。任何更新至最新版本的用户并不受该利用影响。”  
  
攻击通过 CrushFTP v10.8.5和CrushFTP v11.3.4)23之前版本中的web接口发生。目前尚不清楚这些版本何时发布，但CrushFTP 认为大概在7月1日左右发生。CrushFTP 强调称已更新至最新版本的系统并不受影响。  
  
使用DMZ CrushFTP 实例隔离主服务器的企业客户应该不受该漏洞影响。  
  
建议认为系统已遭攻陷的管理员从7月16日之前的备份中恢复默认用户配置。妥协指标如下：  
  
- Main Users/default/user.XML 中的异常条目，尤其是最新修改或 last_logins 字段  
  
- 新的、未获认可的管理员级别用户名称如 7a0d26089ac528941bf8cb998d97f408m。  
  
  
  
Spink 表示，他们多数看到默认的用户被修改为主要的IOC，“通常来讲，我们看到默认的用户被修改为主要IOC。一般来说，以无效方式修改的仍然只可为攻击者所用。”CrushFTP 建议查看上传和下载日志中的异常活动，并采取如下措施缓解利用：  
  
- 用于服务器和管理员访问权限的IP白名单  
  
- 使用DMZ实例  
  
- 启用自动化更新  
  
  
  
然而，Rapid7 公司认为使用DMZ可能并非阻止利用的可靠策略。该公司提到，“出于谨慎考虑，Rapid7 建议不要依赖DMZ作为缓解策略。” 目前尚不清楚攻击是否用于盗取数据或部署恶意软件。然而，文件传输管理解决方案已成为近年来盗取数据的高价值目标。此前，勒索团伙（一般是Clop）一直利用类似平台如 Cleo、MOVEit Transfer、GoAnywhere MFT和Accellion FTA中的0day漏洞，大规模盗取数据和执行勒索攻击。  
  
  
开源  
卫士试用地址：  
https://oss.qianxin.com/#/login  
  
  
代码卫士试用地址：https://sast.qianxin.com/#/login  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CrushFTP 提醒用户立即修复已遭利用的 0day 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519338&idx=1&sn=ec0b92257a640cd98dd5d59c00746548&scene=21#wechat_redirect)  
  
  
[Vmware 修复 Pwn2Own 柏林大赛上遭利用的四个 ESXi 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523602&idx=1&sn=3ec9fd59b332276a13eb21d88cdd9217&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复已遭利用的 Chrome 0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523583&idx=1&sn=f3695d751d9189ce3ff6b61f71cc9942&scene=21#wechat_redirect)  
  
  
[看我如何通过 OpenAI o3 挖到 Linux 内核远程 0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523149&idx=1&sn=0298267a08369cc3ea9bdbdec81eb788&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/new-crushftp-zero-day-exploited-in-attacks-to-hijack-servers/  
  
  
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
  

#  最新Invicti Professional v24.12漏洞扫描器下载   
原创 城北  渗透安全HackTwo   2024-01-14 16:29  
  
前言  
  
> Invicti 专业 Web 应用程序安全扫描器  
> 自动、极其准确且易于使用的 Web 应用程序安全扫描程序，可自动查找网站、Web 应用程序和 Web 服务中的安全漏洞。  
> Invicti Professional Edition 是一款商业 Web 应用程序安全扫描器。它旨在自动查找和修复 Web 应用程序中的 SQL 注入、跨站脚本 (XSS) 和跨站请求伪造 (CSRF) 等漏洞。它可以扫描托管在各种平台上的 Web 应用程序，包括 Windows、Linux 和 macOS。它提供了一系列功能来帮助开发人员和安全专业人员识别和修复其 Web 应用程序中的漏洞，包括可以识别各种漏洞的自动扫描程序，以及允许用户手动测试漏洞的手动测试工具。它可以作为独立产品或云服务提供。  
> **一些基本的安全测试应包括测试：**  
>   
> SQL注入XSS（跨站脚本）DOM跨站脚本攻击命令注入盲命令注入本地文件包含和任意文件读取远程文件包含远程代码注入/评估CRLF / HTTP 标头注入 / 响应分割打开重定向帧注入具有管理员权限的数据库用户漏洞 - 数据库（推断的漏洞）ViewState 未签名ViewState 未加密网络后门TRACE / TRACK 方法支持已启用禁用 XSS 保护启用 ASP.NET 调试启用 ASP.NET 跟踪可访问的备份文件可访问的 Apache 服务器状态和 Apache 服务器信息页面可访问的隐藏资源存在漏洞的 Crossdomain.xml 文件易受攻击的 Robots.txt 文件易受攻击的 Google 站点地图应用程序源代码公开Silverlight 客户端访问策略文件存在漏洞CVS、GIT 和 SVN 信息和源代码公开PHPInfo() 页面可访问以及 PHPInfo() 在其他页面中的披露可访问敏感文件重定向响应主体太大重定向响应 BODY 有两个响应通过 HTTP 使用不安全的身份验证方案通过 HTTP 传输的密码通过 HTTP 提供的密码表单暴力破解获取认证通过 HTTP 获取的基本身份验证凭证薄弱电子邮件地址泄露内部IP泄露目录列表版本公开内部路径泄露访问被拒绝的资源MS Office信息披露自动完成已启用MySQL 用户名泄露默认页面安全性Cookie 未标记为安全Cookie 未标记为 HTTPOnly堆栈跟踪披露编程错误信息披露数据库错误信息披露  
>   
  
  
**Tips-AWVS/Acunetix Premium v23.11扫描工具新增最新Linux版本，需要的请点击以下文章链接去获取**：[最新AWVS/Acunetix Premium v23.11高级版漏洞扫描器Windows/Linux下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247484417&idx=1&sn=9ee5b7d2bc4e7efb89712d7082cb2e84&chksm=cf16a2b1f8612ba7ece566ed49839962b4dc3b7f9948dbc0f0df38b0fc6406508884fbcd1ec2&scene=21#wechat_redirect)  
  
  
  
01  
  
# 更新介绍  
  
  
```
更新日志
新功能
在扫描设置部分，我们添加了一个复选框(在Authentication > Form下)来收集关于身份验证进度的所有日志
增强了DOM XSS漏洞报告功能
改进
更新鲨鱼Dotnet传感器到。net Core 6
改进的网站登出检测
修复
解决了报告策略数据库中缺少信息的问题
修正了将扫描数据从企业版导入标准版的问题
修正了导入链接的错误
通过更新软件包修复了Invicti Docker镜像上的一些漏洞
修正了一些假/正被动过时漏洞的报告
```  
  
  
  
02  
  
# 使用/安装方法  
  
  
1.解压打开Netsparkey.exe  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4SC6V1mtSrzj7q5M24icn02NVTrZkuz9qmeuia32ttrlWrBcJqekLkhibCyxMibLCsJoC5zap4to6nicw/640?wx_fmt=png "")  
  
2.选择URl进行测试即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4SC6V1mtSrzj7q5M24icn02AEWq0CDO7VYXtdiaaIw76vgdYCfVKYOy6nl1YTc0jlUIvrTTqrNpmiaw/640?wx_fmt=png "")  
  
  
  
  
03  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20240114获取软件解压密码HackTwo**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4SC6V1mtSrzj7q5M24icn02zt0pHsqhK72eTmbuX81s7XFwmka330icENu8GGh2QDOkYgYibsia6RgXQ/640?wx_fmt=png "")  
  
**后台回复"星球"有优惠券，加入知识星球享受内部VIP资源，别的星球几百块我这只要几十元即可享受同样资源（后续价格只涨不降）**  
  
**点击了解-->>内部VIP知识星球福利介绍V1.2版本-元旦优惠**  
  
# 最后必看  
  
  
    本工具及文章技巧仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。  
为  
避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。  
  
  
    在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。  
如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。  
本工具来源于网络，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
    在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。  
  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP知识星球福利介绍V1.2版本-元旦优惠**  
  
[2. 2023HW的110+个poc发布直接下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483899&idx=1&sn=8f428144e749c1f115d39bae69072604&chksm=cf16a74bf8612e5dbc086b8af8a08b195481f367a8904f89ac44e66f06703afe54f1c6c641d6&scene=21#wechat_redirect)  
  
  
**3.最新Nessus2024.01.11.1版本漏洞扫描/探测工具下载Windows**  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
###### 渗透安全HackTwo  
###### 想了解星球福利回复:星球  
  
  
微信号：关注公众号获取  
  
扫码关注 了解更多    
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜  
欢的朋友可以点赞转  
发  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/tqRiaNianNl1mGavBwp9Mf5RO17Jib6HN2NRSYwVT0jk8EzYYGOCRUxicpRHooD7KBlfkawia1zgicxnwMXlqxhFowCpwANhQJxA6A/640 "")  
  
  

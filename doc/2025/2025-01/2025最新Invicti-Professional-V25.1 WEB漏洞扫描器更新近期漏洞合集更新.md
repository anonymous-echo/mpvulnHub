#  2025最新Invicti-Professional-V25.1 WEB漏洞扫描器更新|近期漏洞合集更新   
原创 城北  渗透安全HackTwo   2025-01-16 16:00  
  
前言  
  
> **内部星球近期漏洞验真合集更新|漏洞威胁情报更新**  
****  
> Invicti 专业 Web 应用程序安全扫描器  
> 自动、极其准确且易于使用的 Web 应用程序安全扫描程序，可自动查找网站、Web 应用程序和 Web 服务中的安全漏洞。  
> Invicti Professional Edition 是一款商业 Web 应用程序安全扫描器。它旨在自动查找和修复 Web 应用程序中的 SQL 注入、跨站脚本 (XSS) 和跨站请求伪造 (CSRF) 等漏洞。它可以扫描托管在各种平台上的 Web 应用程序，包括 Windows、Linux 和 macOS。它提供了一系列功能来帮助开发人员和安全专业人员识别和修复其 Web 应用程序中的漏洞，包括可以识别各种漏洞的自动扫描程序，以及允许用户手动测试漏洞的手动测试工具。它可以作为独立产品或云服务提供。  
> **一些基本的安全测试应包括测试：**  
>   
> SQL注入XSS（跨站脚本）DOM跨站脚本攻击命令注入盲命令注入本地文件包含和任意文件读取远程文件包含远程代码注入/评估CRLF / HTTP 标头注入 / 响应分割打开重定向帧注入具有管理员权限的数据库用户漏洞 - 数据库（推断的漏洞）ViewState 未签名ViewState 未加密网络后门TRACE / TRACK 方法支持已启用禁用 XSS 保护启用 ASP.NET 调试启用 ASP.NET 跟踪可访问的备份文件可访问的 Apache 服务器状态和 Apache 服务器信息页面可访问的隐藏资源存在漏洞的 Crossdomain.xml 文件易受攻击的 Robots.txt 文件易受攻击的 Google 站点地图应用程序源代码公开Silverlight 客户端访问策略文件存在漏洞CVS、GIT 和 SVN 信息和源代码公开PHPInfo() 页面可访问以及 PHPInfo() 在其他页面中的披露可访问敏感文件重定向响应主体太大重定向响应 BODY 有两个响应通过 HTTP 使用不安全的身份验证方案通过 HTTP 传输的密码通过 HTTP 提供的密码表单暴力破解获取认证通过 HTTP 获取的基本身份验证凭证薄弱电子邮件地址泄露内部IP泄露目录列表版本公开内部路径泄露访问被拒绝的资源MS Office信息披露自动完成已启用MySQL 用户名泄露默认页面安全性Cookie 未标记为安全Cookie 未标记为 HTTPOnly堆栈跟踪披露编程错误信息披露数据库错误信息披露  
> ![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq74HibxKz1WvJAjedarj1VGbVSwI4GdNfUeIyLiap1Vz2RmOoS6nibwJicWzwbMJqnaukiaib4RXxgAIfhQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
02  
  
# 更新介绍  
  
  
```
此更新包括对内部代理的更改。内部扫描代理的当前版本为 25.1.0。内部身份验证验证程序代理的当前版本为 25.1.0。
#新功能
现在，单击扫描摘要屏幕中的预设扫描图标会将您重定向到具有过滤视图的 “最近扫描” 页面，从而改进导航和对相关扫描详细信息的访问
#改进
修复了 2FA 页面上代码文本字段在页面加载时未自动聚焦的问题
为 HTTP 日志文件引入了可配置的保留期，允许 Root 用户指定日志之前的天数
实施了限制以防止修改漏洞签名类型
增强了 UI，以便在 API Hub 规范链接到扫描配置文件时突出显示菜单，使用户更容易识别关联的配置文件
将 Chromium 从版本 121 更新到版本 131，以增强性能和兼容性
通过分析误报提高弱密码的检测准确性
实施了一项集成，可在启动 DAST 扫描时自动从 Mend 检索最新的容器安全结果
管理员现在可以将代理组分配给团队，以更好地控制代理和可以使用它们的团队。了解更多。
已解决的问题
更正了角色的 OTP 配置附件，确保单独的密钥并防止共享更改
解决了内部代理服务在 UI 中禁用后停止的问题。现在，即使从 Web 应用程序中禁用了代理，该服务也保持活动状态。
更新了 SharedAssemblyInfo 文件以反映正确的版权详细信息
修复了禁用的扫描无意中运行，导致中断的问题
修复了用户无法更新超过 40 个字符的网站名称的错误
修复了在导入无效定义文件时 Invicti REST API 不返回错误的问题
解决了在启用“阻止产品中显示任何敏感信息”设置后，Invicti 扫描/报告 API 端点上遇到的“内部服务器错误”
修复了以下问题：当用户无权更新状态时，向问题添加注释时，“问题”状态被无意中删除
修复了通知电子邮件中的“通知设置”超链接重定向不正确的问题
解决了代理验证程序在 Linux 环境中使用证书时遇到错误的问题
修复了由于集成错误而在 ServiceNow 中创建重复票证的问题
修复了严重性趋势图表无法在单个网站仪表板上正确呈现的问题
Node.js v6 已达到其生命周期结束 （EOL），并且已从 Azure Pipelines 中删除对此版本的支持
解决了扫描期间登录页面重新出现的覆盖率问题
#其他更新
将支持电子邮件地址重定向到 http://support.invicti.com/ 链接
将 Chromium 从版本 121 更新到版本 131，以增强性能和兼容性
通过分析误报提高弱密码的检测准确性
已解决的问题
解决了在启用“阻止产品中显示任何敏感信息”设置后，Invicti 扫描/报告 API 端点上遇到的“内部服务器错误”
解决了代理验证程序在 Linux 环境中使用证书时遇到错误的问题
解决了扫描期间登录页面重新出现的覆盖率问题
```  
  
  
  
03  
  
# 近日星球新增资源/漏洞汇总  
  
  
POC/资源已在星球公开更新中，加入星球获取#内部星球资源更新如何发现导致账户接管的参数篡改漏洞针对前端加密爆破的方法及实战案例百度技术培训中心存在越权取消订单漏洞记录第一次尝试小程序支付漏洞挖掘某小程序高危漏洞广州华镒智能科技有限公司Jeewms存在SQL注入漏洞0day移动应用getPicServlet存在任意文件的读取漏洞内训宝企业培训平台 scorm 任意文件上传导致RCE漏洞1dayPHPCMS演示站index存在SQL注入漏洞CS_CounterStrike1.6.1最新版CS/Webshell等免杀工具分享全网最全的SRC资产表更新2025POC漏洞库3000+的0day/1day漏洞更新SRC漏洞挖掘培训视频更新  
  
  
04  
  
# 使用/安装方法  
  
  
1.解压打开Netsparkey.exe  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4SC6V1mtSrzj7q5M24icn02NVTrZkuz9qmeuia32ttrlWrBcJqekLkhibCyxMibLCsJoC5zap4to6nicw/640?wx_fmt=png "")  
  
2.选择URl进行测试即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4SC6V1mtSrzj7q5M24icn02AEWq0CDO7VYXtdiaaIw76vgdYCfVKYOy6nl1YTc0jlUIvrTTqrNpmiaw/640?wx_fmt=png "")  
  
  
****  
  
05  
  
# 内部星球介绍  
  
  
          
如果你想学习更多**渗透挖洞技术/技巧**欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源，最新**1day0day漏洞威胁情报，**报包含网上一些**付费工具BurpSuite漏洞检测插件**，Fofa高级会员，Ctfshow等等各种账号会员共享。具体  
详情直接点击下方链接进入了解，需要加入的直接点击下方链接了解即可，觉得价格高的师傅可后台回复"   
**星球**  
 "有优惠券名额有限先到先得！  
内部  
包含了  
网上需付费的  
**0day/1day漏洞库**，后续资源会更丰富在加入还是低价！  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247485481&idx=2&sn=b56317ebe3490c7bce5a889c3643e1cd&chksm=cf16ae99f861278fc9e1a86cb7814fb031c853ecb1e121614504e0709e04be8d46d11073ebca&scene=21#wechat_redirect)  
[👉](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247485481&idx=2&sn=b56317ebe3490c7bce5a889c3643e1cd&chksm=cf16ae99f861278fc9e1a86cb7814fb031c853ecb1e121614504e0709e04be8d46d11073ebca&scene=21#wechat_redirect)  
[点击了解加入-->>内部VIP知识星球福利介绍V1.3版本-星球介绍](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247485481&idx=2&sn=b56317ebe3490c7bce5a889c3643e1cd&chksm=cf16ae99f861278fc9e1a86cb7814fb031c853ecb1e121614504e0709e04be8d46d11073ebca&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247485481&idx=2&sn=b56317ebe3490c7bce5a889c3643e1cd&chksm=cf16ae99f861278fc9e1a86cb7814fb031c853ecb1e121614504e0709e04be8d46d11073ebca&scene=21#wechat_redirect)  
  
  
  
06  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250117获取软件Invicti-Professional**  
  
**解压密码HackTwo**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq74HibxKz1WvJAjedarj1VGbicSoib1KWNlCRUicibAzgjVUZ32G0vmD1lsmHLkCiahiaBibqS3eeiaKTQrWcg/640?wx_fmt=png&from=appmsg "")  
  
  
# 最后必看  
  
  
    本工具及文章技巧仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。  
为  
避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。  
  
  
    在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。  
如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。  
本工具来源于网络，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
    在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。  
  
  
  
  
# 往期推荐  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483949&idx=1&sn=cae68096be06be4f0ea746ee5908dc79&chksm=cf16a49df8612d8b0b5cc2e49e6367cc91b7fd1f6d71c555d6631dbd3bd883d5242972e506b9&scene=21#wechat_redirect)  
  
**1.**[内部VIP知识星球福利介绍V1.3版本介绍](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247485481&idx=2&sn=b56317ebe3490c7bce5a889c3643e1cd&chksm=cf16ae99f861278fc9e1a86cb7814fb031c853ecb1e121614504e0709e04be8d46d11073ebca&scene=21#wechat_redirect)  
  
  
[2.](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483899&idx=1&sn=8f428144e749c1f115d39bae69072604&chksm=cf16a74bf8612e5dbc086b8af8a08b195481f367a8904f89ac44e66f06703afe54f1c6c641d6&scene=21#wechat_redirect)  
  
**4.8-CobaltStrike4.8汉化+最新插件集成版发布**  
  
**3.最新BurpSuite2024.9.2专业版中英文版下载**  
  
**4.**[最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
**5.最新Nessus2024.10.7主机漏洞扫描/探测工具下载**  
  
**6.**[最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
###### 渗透安全HackTwo  
###### 想了解星球福利回复:星球  
  
  
微信号：关注公众号获取  
  
扫码关注 了解更多    
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜  
欢的朋友可以点赞转  
发  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/tqRiaNianNl1mGavBwp9Mf5RO17Jib6HN2NRSYwVT0jk8EzYYGOCRUxicpRHooD7KBlfkawia1zgicxnwMXlqxhFowCpwANhQJxA6A/640 "")  
  
  

#  WEB漏洞扫描器Invicti-Professional-V25.4（自动化爬虫扫描）更新   
原创 城北  渗透安全HackTwo   2025-04-17 16:02  
  
前言  
  
**Invicti 专业 Web 应用程序安全扫描器**  
  
自动、极其准确且易于使用的 Web 应用程序安全扫描程序，可自动查找网站、Web 应用程序和 Web 服务中的安全漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5EOjNAdfFHywrcHWTuSFjfVjicrbicEhXH7sia8vkR4mj6YGyzv7a9XToVzI0icD0AicJUHVnmJzBDKicA/640?wx_fmt=png&from=appmsg "")  
  
Invicti Professional Edition 是一款商业 Web 应用程序安全扫描器。它旨在自动查找和修复 Web 应用程序中的 SQL 注入、跨站脚本 (XSS) 和跨站请求伪造 (CSRF) 等漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7HMtibJc6mxaz1McHOW3YhsTlSrxzib7oEANX8ic4BrO2iat2Dib41LYBdWDgmTVB77uyUKC7AmiaicAw5Q/640?wx_fmt=png&from=appmsg "")  
  
它可以扫描托管在各种平台上的 Web 应用程序，包括 Windows、Linux 和 macOS。它提供了一系列功能来帮助开发人员和安全专业人员识别和修复其 Web 应用程序中的漏洞，包括可以识别各种漏洞的自动扫描程序，以及允许用户手动测试漏洞的手动测试工具。它可以作为独立产品或云服务提供。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5EOjNAdfFHywrcHWTuSFjfLzaEMA5O5EH2HJic7ib9qDstAJ7aj7aWQ0v5joiavy4X7XH8keY9w1UEg/640?wx_fmt=png&from=appmsg "")  
  
**一些基本的安全测试应包括测试：**  
  
- SQL注入  
  
- XSS（跨站脚本）  
  
- DOM跨站脚本攻击  
  
- 命令注入  
  
- 盲命令注入  
  
- 本地文件包含和任意文件读取  
  
- 远程文件包含  
  
- 远程代码注入/评估  
  
- CRLF / HTTP 标头注入 / 响应分割  
  
- 打开重定向  
  
- 帧注入  
  
- 具有管理员权限的数据库用户  
  
- 漏洞 - 数据库（推断的漏洞）  
  
- ViewState 未签名  
  
- ViewState 未加密  
  
- 网络后门  
  
- TRACE / TRACK 方法支持已启用  
  
- 禁用 XSS 保护  
  
- 启用 ASP.NET 调试  
  
- 启用 ASP.NET 跟踪  
  
- 可访问的备份文件  
  
- 可访问的 Apache 服务器状态和 Apache 服务器信息页面  
  
- 可访问的隐藏资源  
  
- 存在漏洞的 Crossdomain.xml 文件  
  
- 易受攻击的 Robots.txt 文件  
  
- 易受攻击的 Google 站点地图  
  
- 应用程序源代码公开  
  
- Silverlight 客户端访问策略文件存在漏洞  
  
- CVS、GIT 和 SVN 信息和源代码公开  
  
- PHPInfo() 页面可访问以及 PHPInfo() 在其他页面中的披露  
  
- 可访问敏感文件  
  
- 重定向响应主体太大  
  
- 重定向响应 BODY 有两个响应  
  
- 通过 HTTP 使用不安全的身份验证方案  
  
- 通过 HTTP 传输的密码  
  
- 通过 HTTP 提供的密码表单  
  
- 暴力破解获取认证  
  
- 通过 HTTP 获取的基本身份验证  
  
- 凭证薄弱  
  
- 电子邮件地址泄露  
  
- 内部IP泄露  
  
- 目录列表  
  
- 版本公开  
  
- 内部路径泄露  
  
- 访问被拒绝的资源  
  
- MS Office信息披露  
  
- 自动完成已启用  
  
- MySQL 用户名泄露  
  
- 默认页面安全性  
  
- Cookie 未标记为安全  
  
- Cookie 未标记为 HTTPOnly  
  
- 堆栈跟踪披露  
  
- 编程错误信息披露  
  
- 数据库错误信息披露  
  
  
  
  
01  
  
# 更新介绍  
  
  
```
此更新包含对内部代理的更改。内部扫描代理的当前版本为 25.4.0。内部身份验证验证器代理的当前版本为 25.4.0。
新功能
添加了一个选项，当漏洞被标记为误报并在之后恢复时，可以防止重新打开问题跟踪器问题（阅读更多）。
改进
具有空值或默认值的请求不会发送到 DeepInfo
在“帐户常规”设置中的“数据隐私和安全”部分中引入了一个新设置，用于在下载扫描数据时修改 X-AMZ-Expires 参数
增强了“配置新代理”页面，以包含授权验证代理的更多详细信息（阅读更多）
更新了针对过时 AngularJS 版本的修复细节
[重大变化]：更新了 Docker 代理的压缩方法和文件扩展名；确保引用旧格式的任何自动化或脚本都得到相应更新。
已解决的问题
修复问题注释字段无法更新的问题
修复了 DotNet IAST 传感器中低效的算法复杂性
解决了尝试添加用户时出现无效字符响应的问题
解决了在新扫描页面上将目标 URI 编辑为以多个斜杠 (///) 结尾时出现的“无效目标 URI”错误
解决了扫描配置文件未通过支持帐户更新的问题
修复了 JIRA 集成的限制
修复了在密码验证期间按“Enter”而不是单击“检查”按钮会触发完整扫描而不是预期的登录验证的问题
更新了 Chromium 和 Node.js 版本，解决了与 Chromium 相关的问题，包括 Chromium 数量的意外增加。
即使排除的 URL 是目标，排除 URL 规则现在也能正常运行
修复了从 JSON 响应中检索 OAuth2 令牌数据的问题
```  
  
  
  
02  
  
# 使用/安装方法  
  
  
1.解压打开Netsparkey.exe  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4SC6V1mtSrzj7q5M24icn02NVTrZkuz9qmeuia32ttrlWrBcJqekLkhibCyxMibLCsJoC5zap4to6nicw/640?wx_fmt=png "")  
  
2.选择URl进行测试即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4SC6V1mtSrzj7q5M24icn02AEWq0CDO7VYXtdiaaIw76vgdYCfVKYOy6nl1YTc0jlUIvrTTqrNpmiaw/640?wx_fmt=png "")  
  
  
****  
  
  
03  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250418获取Invicti-Professional**  
  
**👉点击加入内部VIP星球享受VIP资源****👈**  
  
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
  
  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）******  
  
**2.******  
**4.8-CobaltStrike4.9‍汉化+最新插件集成版发布**  
  
**3.最新Nessus2024.10.7版本下载**  
  
**4.**  
**最新xray1.9.11高级版下载Windows/Linux**  
  
**5.记一次挖洞springboot未授权到反弹shell|挖洞技巧**  
  
###### 渗透安全HackTwo  
###### 想了解星球福利回复:星球  
  
  
微信号：关注公众号获取  
  
扫码关注 了解更多    
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜  
欢的朋友可以点赞转  
发  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/tqRiaNianNl1mGavBwp9Mf5RO17Jib6HN2NRSYwVT0jk8EzYYGOCRUxicpRHooD7KBlfkawia1zgicxnwMXlqxhFowCpwANhQJxA6A/640 "")  
  
  

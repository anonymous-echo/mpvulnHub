#  最新Invicti-Professional-V24.11 WEB漏洞扫描器更新|近期漏洞合集更新   
原创 城北  渗透安全HackTwo   2024-11-20 16:00  
  
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
新功能
与 Mend SAST 集成：在 Invicti Enterprise 中显示 Mend SAST 结果和 DAST 结果，以便您可以在一个列表中优先考虑所有应用程序安全测试修复 →了解更多
API 安全性：添加了与 Azure API 管理的集成以获取 Swagger2 和 OpenAPI3 规范文件 →了解更多
API Security 现在支持使用 MuleSoft Anypoint Exchange 的 RAML 规范
新的安全检查
更新了 ActiveMQ 的检测 – 远程代码执行 ( CVE-2023-46604 ) 和 TorchServe 管理 API SSRF ( CVE-2023-43654 )
添加了对多个 JavaScript 库的检测
添加了对 Masa CMS 的检测（ CVE-2022-47002和CVE-2021-42183 ）
改进
数据库优化
将无持续时间限制的扫描更改为仅客户支持请求选项
报告“推荐人策略中使用的未知选项”漏洞的改进
改进了使用移动视图时全局仪表板上“最近扫描”按钮组的行为
修复
修复了零配置 API 发现中的超时错误
修复了一些措辞不一致的问题以及对用户界面的其他细微改进
扫描取消、失败或中止时删除站点地图数据
解决了常规设置页面配置中的问题
解决了用户会话未按照指定配置超时的问题
修复了基于布尔的 MongoDB 注入检测的误报问题
现在可以正确报告基于布尔的 MongoDB 注入的过时版本
设置为隐藏的漏洞配置文件现在仍将在隐藏漏洞之前完成的扫描的扫描报告中报告
修复了使用自定义报告策略编辑扫描配置文件时的错误
解决了导出选定所有属性的团队成员数据的问题
解决了自定义报告策略中缺少漏洞配置文件的问题
```  
  
  
03  
  
# 近日星球新增漏洞汇总  
  
  
POC已在星球公开每日更新中，漏洞在星球获取(每周一至周五推送更新)懂微百择唯·供应链 RankingGoodsList2 SQL注入致RCE漏洞索贝融媒体search存在SQL注入漏洞通达OA qyapp.vote.submit.php存在SQL注入漏洞资产管理运营系统(资产云)存在前台文件上传漏洞任子行网络安全审计系统 log_fw_ips_scan_jsondata SQL注入漏洞PHPCMS演示站index存在SQL注入漏洞SRM智联云采系统statusList存在SQL注入漏洞Palo Alto Networks PAN-OS身份认证绕过导致RCE漏洞信呼oa weak-password弱口令漏洞通达OA前台add.php存在未授权访问漏洞宝兰德BES中间件spark接口远程代码执行漏洞任我行协同CRM普及版 CommonDictEdit SQL注入漏洞 Altenergy电力系统控制软件 status_zigbee SQL注入漏洞(CVE-2024-11305) FortiManager身份认证绕过漏洞(CVE-2024-47575)东胜物流 certupload 存在任意文件上传帕拉迪堡垒机sslvpnservice.php存在SQL注入漏洞SRM智联云采系统inquiry存在SQL注入漏洞通达OA前台submenu.php存在SQL注入漏洞Mlflow create 任意文件读取漏洞九思OA dl.jsp 任意文件读取漏洞WordPress Authentication Bypass via Account Takeover（CVE-2024-50483）盲盒抽奖小程序系统http_request存在任意文件读取漏洞D-Link NAS设备sc_mgr.cgi存在RCE命令执行漏洞微信公众号商家收银台小程序系统存在前台SQL注入漏洞赛普EAP企业适配管理平台Handler Upload.aspx文件上传导致命令执行漏洞全新优客API接口管理系统 doc 存在SQL注入漏洞预警监控平台newLogin存在SQL注入漏洞H3C ER8300G2-X.cfg信息泄露漏洞(CVE-2024-32238)东胜物流软件 GetDataListCA 存在SQL注入漏洞API接口调用多用户管理系统Ajax存在前台SQL注入漏洞珠海市安克电子技术有限公司医疗急救管理系统Service.asmx存在SQL注入漏洞D-Link NAS设备account_mgr.cgi-未授权RCE漏洞Japan太阳能系统DataCube3终端测量系统存在任意文件上传漏洞Xlight FTP Server整数溢出漏洞(CVE-2024-46483)ZKBioSecurity存在shiro反序列漏洞EyouCMS文件包含RCE漏洞  
  
  
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
  
  
**公众号回复20241121获取软件Invicti-Professional**  
  
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
  
  

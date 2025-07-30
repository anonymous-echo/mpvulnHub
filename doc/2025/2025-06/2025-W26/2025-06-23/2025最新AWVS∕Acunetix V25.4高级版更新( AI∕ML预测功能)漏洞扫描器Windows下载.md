> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247492621&idx=1&sn=480d4244338efa136786fb91bf7d0dad

#  2025最新AWVS/Acunetix V25.4高级版更新( AI/ML预测功能)漏洞扫描器Windows下载  
原创 城北  渗透安全HackTwo   2025-06-23 16:00  
  
前言  
  
Acunetix Premium  
 是一种 Web 应用程序安全解决方案，用于管理多个网站、Web 应用程序和 API 的安全。集成功能允许您自动化 DevOps 和问题管理基础架构。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4thV1ia5M2mMA4u1DZVH4NOdFzicLv06HUAQ5W1iaDGeN6pGkWo7G5tQltVgtpykhVjAIkkiclStt5BA/640?wx_fmt=png&from=appmsg "")  
  
**Acunetix Premium：**  
全面的 Web 应用程序安全解决方案  
  
Web 应用程序对于企业和组织与客户、合作伙伴和员工的联系至关重要。随着 Web 应用程序变得越来越复杂，安全威胁的风险也随之增加。Acunetix Premium 是一种 Web 应用程序安全解决方案，旨在识别和缓解 Web 应用程序中的漏洞，确保敏感数据的安全和保护。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4thV1ia5M2mMA4u1DZVH4NOt0G0ZfFu7TfkDEiaVS742tBYVSaswaFXyNdIRSSywQyMYs6BDWxCV1w/640?wx_fmt=png&from=appmsg "")  
  
**Acunetix Premium**  
的主要功能之一是能够自动扫描 Web 应用程序是否存在安全漏洞。自动扫描过程结合使用 Web 应用程序扫描技术（包括深度数据包检查和指纹识别）来识别潜在漏洞并提供有关每个风险的详细信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4thV1ia5M2mMA4u1DZVH4NO8U0o7o4mZpyNNazDkicbicA1qrQCpJfFDW7ouiaickabav7k2DnTLQOycw/640?wx_fmt=png&from=appmsg "")  
  
**Acunetix Premium**  
还包括一个报告仪表板，可提供 Web 应用程序安全状态的概述，包括发现的漏洞数量、严重程度和风险级别。此报告仪表板使组织可以轻松跟踪和修复漏洞，确保其 Web 应用程序保持安全。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4thV1ia5M2mMA4u1DZVH4NOjct0icjZh0KE8McYoY7Utc485Hptmr0ONRDib5toiaxoOf9TzXQDqz3ag/640?wx_fmt=png&from=appmsg "")  
  
  
  
01  
  
# 更新介绍  
  

```
新功能
实施 Web 应用程序以安全存储和检索预请求脚本的密码
添加了 NTA 与 NGINX 的集成（阅读更多）
改进
除二级域名外，所有字段均已实现默认限制设置为 1000，且无标志
在与 Azure Boards 集成时实现了自定义字段 Parent 选项
实施代理，用于安全存储和检索预请求脚本的密码
具有空值或默认值的请求不会发送到 DeepInfo
在“帐户常规”设置中的“数据隐私和安全”部分中引入了一个新设置，用于在下载扫描数据时修改 X-AMZ-Expires 参数
增强了“配置新代理”页面，以包含授权验证代理的更多详细信息（阅读更多）
更新了针对过时 AngularJS 版本的修复细节
[重大变化]：更新了 Docker 代理的压缩方法和文件扩展名；确保引用旧格式的任何自动化或脚本都得到相应更新。
增强了隔离网络中本地托管的 Web 应用程序，以防止通过 Google reCAPTCHA 进行不必要的重新路由
已解决的问题
解决了技术仪表板上的一个问题
使用“不包含”条件时，“所有问题”中的“标签”过滤器现在可正常工作
已解决在“目标群组”页面上筛选目标列表时未显示结果的问题。此问题与“查看目标列表”权限相关。
解决了 TestBasicAuthCredentials 过程中的通信问题并改进了 HTTP 连接处理
解决了并非所有属性都从“问题”页面正确导出的问题
修复了扫描摘要中错误请求响应的问题
修复 WordPress 插件 Contact Form 7 的命名问题
修复了 LoginRequiredUrl 和 Pre-Request 脚本请求导致 HTTP 请求瓶颈的问题
修复了 OAuth2 授权请求中不必要包含代码参数的问题
扫描引擎现在可以正确处理从浏览器收到的合并请求标头
解决了使用云代理进行扫描在延长运行时间后偶尔会失败并出现“代理不可用”错误的问题
将 APIHub npm 包更新至最新版本
解决了多个页面的扫描身份验证问题
解决了与屏幕截图和登录过程相关的问题
修复了选择特定目标时仪表盘小部件活动为空的问题
修复问题更新端点恢复为默认漏洞的问题
修复了在更新计划 API 端点中删除首选代理组的问题
修复了验证器代理的自动更新问题，增加了对不应包含在范围内的 URL 的控制
升级了快捷方式（Clubhouse）集成
修复问题注释字段无法更新的问题
修复了 DotNet IAST 传感器中低效的算法复杂性
解决了尝试添加用户时出现无效字符响应的问题
解决了在新扫描页面上将目标 URI 编辑为以多个斜杠 (///) 结尾时出现的“无效目标 URI”错误
解决了扫描配置文件未通过支持帐户更新的问题
修复了 JIRA 集成的限制
修复了在密码验证期间按“Enter”而不是单击“检查”按钮会触发完整扫描而不是预期的登录验证的问题
更新了 Chromium 和 Node.js 版本，解决了与 Chromium 相关的问题，包括 Chromium 数量的意外增加
即使排除的 URL 是目标，排除 URL 规则现在也能正常运行
修复了从 JSON 响应中检索 OAuth2 令牌数据的问题
修复了计划扫描中无效目标 URI 导致的异常
修复了启动 InvictiProxy 时代理凭据未加密的问题
```

  

```


```

  

```


```

  
  
02  
  
# 使用/安装方法  
  
  
1.hosts文件必须修改为如下所示,添加如下配置到host文件中:  

```
127.0.0.1  erp.acunetix.com
127.0.0.1  erp.acunetix.com.
::1  erp.acunetix.com
::1  erp.acunetix.com.


127.0.0.1  telemetry.invicti.com
127.0.0.1  telemetry.invicti.com.
::1  telemetry.invicti.com
::1  telemetry.invicti.com.
```

  
2.在如下位置替换两个文件:  

```
license_info.Json文件和wa_data.dat文件C:/ProgramData/Acunetix/shared/license/
```

  
3.第三步将以下路径  

```
C:/ProgramData/Acunetix/shared/license/
```

  
整个文件夹设置为只读或  
两个证书文件属性设置为只读  
。  
  
若破解失败,再次替换  

```
license_info.Json文件和wa_data.dat文件
```

  
注意:还需替换wvsc.exe到安装根目录下。  
  
  
4.选择URl进行测试即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4thV1ia5M2mMA4u1DZVH4NOSEbXjaQD3VSBxDwNfdX7spbQotPicCL9PrxXKvvrcT7pKCLtCCNUc5A/640?wx_fmt=png&from=appmsg "")  
  
**具体详细步骤看PDF安装文档**  
  
  
  
03  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250624获取软件**  
  
**👉点击加入内部VIP星球享受VIP资源****👈******  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6Yhrn00WXYSKboLvFicKoZycO6QxnteUNvVhRG2s1qakxLZORFg0ibG8gQljqZAQh6qb5llDSbpfsA/640?wx_fmt=png&from=appmsg "")  
  
****  
****  
  
# 最后必看  
  
  
    本工具及文章技巧仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。  
为  
避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。  
  
  
    在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。  
如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。  
本工具来源于网络，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
    在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。  
  
  
  
  
# 往期推荐  
  
  
**1.部VIP星球福利介绍V1.4版本-星球介绍(0day推送/AI)**  
  
**2.最新BurpSuite2025.6专业版**  
  
**3.最新Nessus2025.6.9版**  
  
**4.CS4.9.1.1-CobaltStrike4.9.1.1免杀版发布**  
  
######   
  
###### 渗透安全HackTwo  
###### 获取更多资源可加入内部星球  
  
  
微信号：关注公众号获取  
  
  
扫码关注 了解更多  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜  
欢的朋友可以点赞转  
发  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/tqRiaNianNl1mGavBwp9Mf5RO17Jib6HN2NRSYwVT0jk8EzYYGOCRUxicpRHooD7KBlfkawia1zgicxnwMXlqxhFowCpwANhQJxA6A/640 "")  
  
  

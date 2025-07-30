#  2024最新AWVS/Acunetix Premium v24.1.24高级版漏洞扫描器Windows/Linux下载   
原创 城北  渗透安全HackTwo   2024-01-21 08:35  
  
前言  
  
>   
> Acunetix Premium  
 是一种 Web 应用程序安全解决方案，用于管理多个网站、Web 应用程序和 API 的安全。集成功能允许您自动化 DevOps 和问题管理基础架构。  
>   
> **Acunetix Premium：**  
全面的 Web 应用程序安全解决方案  
>   
> Web 应用程序对于企业和组织与客户、合作伙伴和员工的联系至关重要。随着 Web 应用程序变得越来越复杂，安全威胁的风险也随之增加。Acunetix Premium 是一种 Web 应用程序安全解决方案，旨在识别和缓解 Web 应用程序中的漏洞，确保敏感数据的安全和保护。  
>   
> **Acunetix Premium**  
为 Web 应用程序安全测试提供功能齐全的解决方案，包括自动扫描、手动渗透测试以及用于跟踪和修复漏洞的报告仪表板。该解决方案旨在为 Web 应用程序和 API 提供全面的安全覆盖。  
>   
> **Acunetix Premium**  
的主要功能之一是能够自动扫描 Web 应用程序是否存在安全漏洞。自动扫描过程结合使用 Web 应用程序扫描技术（包括深度数据包检查和指纹识别）来识别潜在漏洞并提供有关每个风险的详细信息。  
>   
> **Acunetix Premium**  
的手动渗透测试功能允许安全专家手动测试 Web 应用程序是否存在安全漏洞，从而提供额外的安全覆盖层。此手动测试提供了对 Web 应用程序安全性的全面评估，并且可以发现自动扫描可能无法检测到的漏洞。  
>   
> **Acunetix Premium**  
还包括一个报告仪表板，可提供 Web 应用程序安全状态的概述，包括发现的漏洞数量、严重程度和风险级别。此报告仪表板使组织可以轻松跟踪和修复漏洞，确保其 Web 应用程序保持安全。  
> ![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6Yhrn00WXYSKboLvFicKoZynlSu9FbK9USx5gX5T3lSKTNtDicGzMFRqO8aNcNQlC682SbCCFJOO7Q/640?wx_fmt=png&from=appmsg "")  
  
>   
>   
  
  
  
01  
  
# 更新介绍  
  
  
```
新功能
添加了 CVSS 4.0 漏洞分类
添加了对 PCI DSS 4.0 的支持
新的安全检查
Google ProtocolBuffers：CVE-2022-1941
改进
在“扫描摘要”页面上添加了对代理警告消息的描述
更新了有关团队管理员角色功能的消息传递
改进了请求正文评级算法
改进Postman集合解析算法
改进了 Boolean MongoDB 的漏洞计算器
解决了添加客户端证书以设置扫描的问题
修复
修复了阻止客户添加回之前删除的目标的错误
增加了 Jira 和 Snow 集成 URL 验证正则表达式的字符长度，以确保其适应顶级域名 (TLD)
原本自动恢复的暂停计划扫描现在将保持暂停状态，直到手动恢复
取消了之前对发现功能中支持的二级域名数量的限制
修复了将问题从“已修复”（已确认）更新为“已接受风险”状态时发生的错误
修复了仪表板上显示的数字的差异
修复了代理自动更新程序的问题
修复了 SSO 登录过程的行为问题
添加了编辑成员时 SSO 用户缺少的控件
修复了Acunetix 360和 ServiceNow之间的通信错误
修复了阻止管理员创建新通知或编辑内置通知的错误
修复了导致验证者不使用扫描策略代理设置的问题
修复了身份验证验证程序客户端证书身份验证路径错误
修复了 Invicti 爬虫无法正确获取 JS 端点的问题
解决了从链接导入 API 文档的问题
修复了 Jenkins 插件中导致“构建失败时停止扫描”选项无法正常工作的错误
```  
  
  
  
02  
  
# 使用/安装方法  
  
  
1.hosts文件必须修改为如下所示,添加如下配置到host文件中:  
```
127.0.0.1  erp.acunetix.com
127.0.0.1  erp.acunetix.com.
::1  erp.acunetix.com
::1  erp.acunetix.com.

127.0.0.1  telemetry.invicti.com
127.0.0.1  telemetry.invicti.com.
::1  telemetry.invicti.com
::1  telemetry.invicti.com.
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6Yhrn00WXYSKboLvFicKoZyNq9ZeoZichgDfhHF5tUUEGZ0Nj2n6j8IoSRK0LQ2J0COric1kLrMhn1g/640?wx_fmt=png&from=appmsg "")  
  
**具体详细步骤看PDF安装文档**  
  
  
  
03  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20240121获取软件解压密码HackTwo**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6Yhrn00WXYSKboLvFicKoZycO6QxnteUNvVhRG2s1qakxLZORFg0ibG8gQljqZAQh6qb5llDSbpfsA/640?wx_fmt=png&from=appmsg "")  
  
后台回复"  
星球"有优惠券，加入知识星球享受内部VIP资源（后续价格只涨不降）  
  
**点击了解-->>内部VIP知识星球福利介绍V1.2版本-元旦优惠**  
  
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
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483949&idx=1&sn=cae68096be06be4f0ea746ee5908dc79&chksm=cf16a49df8612d8b0b5cc2e49e6367cc91b7fd1f6d71c555d6631dbd3bd883d5242972e506b9&scene=21#wechat_redirect)  
  
**1. 内部VIP知识星球福利介绍V1.2版本-元旦优惠**  
  
[2. 2023HW的110+个poc发布直接下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483899&idx=1&sn=8f428144e749c1f115d39bae69072604&chksm=cf16a74bf8612e5dbc086b8af8a08b195481f367a8904f89ac44e66f06703afe54f1c6c641d6&scene=21#wechat_redirect)  
  
  
**3.最新Nessus2024.01.11.1版本漏洞扫描/探测工具下载Windows**  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247484088&idx=1&sn=b50f6fe8086606ae6fac85ca9fd07666&chksm=cf16a408f8612d1e63492c941ff2c408fa2061d6a5fcc6146f57e5c147b0dc9f948488f9a526&scene=21#wechat_redirect)  
  
  
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
  
  

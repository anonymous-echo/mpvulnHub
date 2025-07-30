#  【已复现】ShowDoc item_id SQL注入漏洞   
 黑伞安全   2024-06-04 20:18  
  
> 微信公众号：**黑伞安全**关注可了解更多的网络安全技术分享。如有问题或建议，请公众号留言;**如果你觉得挖不到src漏洞，希望黑伞安全知识星球对你有帮助，欢迎加入**  
> ****  
> **回复：showdoc 领取poc**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicS9usrxnuCcZ3G1fGx3O9zYZa9f0616p8y08g4nnOtXWFOMPWfKDlaLomcGicprIl2d2xeqf0icx2aA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
ShowDoc 是一个开源的在线文档协作平台，它支持Markdown、图片等多种格式，方便团队成员共同编辑和分享文档。企业常见使用场景是使用其进行接口文档、内部知识库管理。2024年6月，ShowDoc官方发布新版本修复了一个SQL注入漏洞。鉴于该漏洞无前置条件，易于利用，且默认情况下可暴破用户token获取系统后台权限，建议所有使用该系统的企业尽快升级修复，以确保系统安全。  
**漏洞描述**  
  
   
Description   
  
  
  
**0****1**  
  
漏洞成因该漏洞源于系统未使用有效的安全措施处理用户输入，并将用户的输入直接拼接进SQL语句中执行。这一过程导致了SQL注入漏洞的产生。漏洞影响该漏洞可利用SQL注入暴破用户token，进而使用管理员权限登录后台，从而获得接口文档、附件及LDAP等配置信息。处置优先级：高漏洞类型：SQL注入漏洞危害等级：高权限认证要求：无需任何权限系统配置要求：默认配置可利用用户交互要求：无需用户交互利用成熟度：POC/EXP已公开批量可利用性：不可使用通用原理POC/EXP进行检测/利用修复复杂度：低，官方提供升级修复方案影响版本 Affects 02version < 3.2.6解决方案 Solution 03临时缓解方案1. 加强服务器和应用的访问控制，仅允许可信IP进行访问。另外如非必要，不要将该系统开放在互联网上。2. 使用WAF等安全设备针对该应用的异常请求进行拦截。升级修复方案官方已发布新版本修复漏洞，建议访问官方Github页面（https://github.com/star7th/showdoc/releases）获取3.2.6及以上版本。漏洞复现 Reproduction 04  
**产品支持**  
  
   
Support   
  
  
  
**06**  
  
  
**云图**  
：默认支持该产品的指纹识别，同时支持该漏洞的版本匹配检测。  
  
**洞鉴**  
：以自定义POC的形式支持该漏洞的版本匹配检测  
  
**雷池**  
：默认支持检测该漏洞的利用行为。  
  
**全悉**  
：默认支持检测该漏洞的利用行为。  
  
  
  
**时间线**  
  
   
Timeline   
  
  
  
**07**  
6月3日 官方发布新版本修复漏洞6月4日 长亭安全应急响应中心发布通告  
参考资料：  
  
[1]. https://github.com/star7th/showdoc/commit/84fc28d07c5dfc894f5fbc6e8c42efd13c976fda  
  
  
  
**长亭应急响应服务**  
  
  
  
  
全力进行产品升级  
  
及时将风险提示预案发送给客户  
  
检测业务是否收到此次漏洞影响  
  
请联系长亭应急服务团队  
  
7*24小时，守护您的安全  
  
  
第一时间找到我们：  
  
邮箱：support@chaitin.com  
  
应急响应热线：4000-327-707  
  
如果你是一个长期主义者，欢迎加入我的知识星球,我们一起冲，一起学。每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGoa1Yh6UHSvgToDQcqx7RLLnJIWwnw3z5JvaexDaclyMwMial9BMOBqkJESSKALIQHIL6T2xTV9GKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  

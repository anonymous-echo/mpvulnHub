#  GitHub警告其企业服务器存在满分认证绕过漏洞   
看雪学苑  看雪学苑   2024-05-22 17:59  
  
近日，GitHub披露了其企业服务器中的一个认证绕过漏洞，可能允许攻击者绕过认证并获取对敏感存储库及数据的未授权访问。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKOFClNXBEWWNG7FIMh2Em31ySj1p62ZBvvZLq0kk6Rr4ibvgp8qgC1N4L7CTMZzlhVMnNZdbpFQ/640?wx_fmt=png&from=appmsg "")  
  
  
据了解，该认证绕过漏洞(CVE-2024-4985，CVSS评分为10分)影响的是GitHub Enterprise Server（GHES）——GHES是一个用于软件开发的自托管平台，允许组织使用Git控制存储和构建软件，以及自动化部署流程。该平台主要是为寻求安全和可定制的源代码管理环境的企业量身定制，安装在组织自有服务器或私有云上，支持协作开发并提供强大的安全性和管理控制。  
  
  
漏洞存在于GHES的SAML单点登录(SSO)认证机制的可选加密断言功能中，这一功能原本旨在增强安全性，但当攻击者能够伪造SAML响应时，其便成为了一个弱点，能够冒充合法用户并潜在获取管理员权限。  
  
  
该漏洞的主要危险在于攻击者能够未经授权访问GHES实例。通过伪造SAML响应，攻击者可以有效绕过认证机制并为账户授予站点管理员权限。对于使用受影响配置的组织，利用漏洞的后果可能非常严重，如未经授权访问源代码、数据泄露和潜在的开发操作中断等。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EsKOFClNXBEWWNG7FIMh2EpyaaE7iaLJ8vgh6dRObYD1Ta6Eg3cfm88qjoGp2zrea1zicpZ4RzXujw/640?wx_fmt=png&from=appmsg "")  
  
  
该问题影响GHES 3.13.0之前的所有版本，GitHub迅速采取了行动进行修复，已发布了GHES 3.9.15、3.10.12、3.11.10、3.12.4版本的补丁，强烈建议受影响的管理员立即更新或采取缓解措施，以便减轻受损风险。  
  
  
  
编辑：左右里  
  
资讯来源：GitHub、Cybersecuritynews、Bleepingcomputer  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  

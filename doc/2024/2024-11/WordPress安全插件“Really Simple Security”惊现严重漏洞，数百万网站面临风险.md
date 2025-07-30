#  WordPress安全插件“Really Simple Security”惊现严重漏洞，数百万网站面临风险   
看雪学苑  看雪学苑   2024-11-18 09:59  
  
> WordPress平台的安全插件“Really Simple Security”（前称“Really Simple SSL”）近日被曝存在严重的身份验证绕过漏洞，该漏洞可能使攻击者获得对受影响站点的完全管理访问权限，影响范围广泛，安全形势严峻。  
  
  
  
  
“Really Simple Security”是WordPress平台上广受欢迎的安全插件，提供SSL配置、登录保护、双因素身份验证层和实时漏洞检测等功能。然而，该插件在处理两因素REST API操作中用户身份验证时存在缺陷，导致严重的身份验证绕过漏洞CVE-2024-10924。  
  
  
Wordfence安全研究员István Márton于2024年11月6日发现了这一漏洞，并称其为Wordfence 12年历史上报告的最严重漏洞之一。问题出在插件的“check_login_and_get_user()”函数，该函数在验证用户身份时未能正确处理“login_nonce”参数，导致攻击者可以绕过身份验证。  
  
  
该漏洞影响“免费”、“专业版”和“专业多站点”版本中从9.0.0到9.1.1.1的插件版本。由于该缺陷可以通过自动化脚本被大规模利用，可能导致大规模的网站接管活动。截至2024年11月17日，WordPress.org统计网站显示大约有450,000次下载，导致3,500,000个网站可能面临该漏洞。  
  
  
开发者已通过发布9.1.2版本修复了该漏洞，并与WordPress.org协调执行了强制安全更新。尽管如此，网站管理员仍需检查并确保他们运行的是最新版本，以保护网站免受潜在的安全威胁。  
  
  
  
资讯来源：bleepingcomputer  
  
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
  

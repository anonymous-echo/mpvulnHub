#  CVSS评分10.0，思科披露其BroadWorks平台身份认证绕过漏洞   
看雪学苑  看雪学苑   2023-09-08 17:59  
  
9月6日，思科公司发布了一则安全公告，称其BroadWorks应用交付平台和BroadWorks Xtended服务平台中存在一个CVSS评分10.0的身份认证绕过漏洞，该漏洞可能允许未经身份验证的远程攻击者伪造访问受影响系统所需的凭据。  
  
  
思科BroadWorks是一个面向企业和消费者的云通信服务平台，而上述两个组件用于应用程序管理和集成。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HGXDXO9Pd5Kv9AKjNq2N6afhU7K6d3eibqjPSow9y4M6GicBa9aIDeFO1FiaUmEibIFtKiaYnQ8Wv8jKw/640?wx_fmt=png "")  
  
  
据了解，该漏洞是由用于验证 SSO 令牌的方法所致，攻击者可以利用该漏洞通过伪造凭据对应用进行身份验证。成功利用漏洞可能允许攻击者进行欺诈或以伪造账户的权限级别执行命令。如果该账户是管理员账户，攻击者将能够查看机密信息、修改客户设置或修改其他用户的设置。要利用此漏洞，攻击者需要具有与受影响的Cisco BroadWorks系统关联的有效用户ID。  
  
  
假如以下任何一个应用程序在BroadWorks应用交付平台和BroadWorks Xtended服务平台上处于活动状态，则会受到此漏洞的影响：  
  
AuthenticationService  
  
BWCallCenter  
  
BWReceptionist  
  
CustomMediaFilesRetrieval  
  
ModeratorClientApp  
  
PublicECLQuery  
  
PublicReporting  
  
UCAPI  
  
Xsi-Actions  
  
Xsi-Events  
  
Xsi-MMTel  
  
Xsi-VTR  
  
  
除了思科安全公告中提到的这两个组件之外，该漏洞不会影响BroadWorks的其他任何组件，因而其他产品的用户无需采取任何行动。  
  
  
针对此漏洞，并没有任何可供采用的缓解措施。好消息是，思科已发布了解决此漏洞的软件更新，并且目前尚未发现有关此漏洞的恶意利用。  
  
  
对于持有服务合同的客户，可以通过常规的软件更新渠道获得安全修复程序。对于没有服务合同的客户，则可以通过与思科技术支持中心（https://www.cisco.com/c/en/us/support/web/tsd-cisco-worldwide-contacts.html）联系来获取升级。  
  
  
  
编辑：左右里  
  
资讯来源：cisco  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
撞库         
  
撞库是黑客通过收集互联网已泄露的用户和密码信息，生成对应的字典表，尝试批量登  
陆其他网站后，得到一系列可以登录的用户。  
  
很多用户在不同网站使用的是相同的帐号密码，因此黑客可以通过获取用户在 A 网站  
的账户从而尝试登录 B 网址，这就可以理解为撞库攻击。  
  
  
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
  

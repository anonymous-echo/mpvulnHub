#  ZDI研究人员披露四个Microsoft Exchange中的0day漏洞   
看雪学苑  看雪学苑   2023-11-08 18:00  
  
11月3日，趋势科技的ZDI研究人员披露了四个Microsoft Exchange中的零日漏洞，攻击者可以远程利用这些漏洞执行任意代码或泄露敏感信息。  
  
  
ZDI于2023年9月7日、8日向微软报告了这些漏洞，但微软对此表示，ZDI披露的四个Exchange漏洞要么已经修复，要么不需要立即关注。ZDI则转而根据其负责任披露政策选择公开披露这些漏洞。以下是ZDI披露的漏洞列表：  
  
  
ZDI-23-1578 - Microsoft Exchange ChainedSerializationBinder  
  
该漏洞为未经信任数据反序列化远程代码执行漏洞  
  
  
此漏洞允许远程攻击者在受影响的Microsoft Exchange安装上执行任意代码。利用此漏洞需要进行身份验证。具体缺陷存在于ChainedSerializationBinder类中。问题在于缺乏对用户提供的数据的适当验证，这可能导致未经信任数据的反序列化。攻击者可以利用此漏洞在SYSTEM上下文中执行代码。  
  
  
ZDI-23-1579 - Microsoft Exchange DownloadDataFromUri  
  
ZDI-23-1580 - Microsoft Exchange DownloadDataFromOfficeMarketPlace  
  
ZDI-23-1581 - Microsoft Exchange CreateAttachmentFromUri  
  
这三个都为服务器端请求伪造信息泄露漏洞  
  
  
这些漏洞允许远程攻击者在受影响的Microsoft Exchange安装上泄露敏感信息。利用这些漏洞都需要进行身份验证。问题在于在访问资源之前缺乏对URI的适当验证。攻击者可以利用这些漏洞在Exchange服务器上下文中泄露信息。  
  
  
对于第一个数据反序列化问题，微软表示该漏洞实际上已经得到修复。应用了8月份的安全更新的客户已经受到保护。  
  
  
余下的问题被描述为服务器端请求伪造（SSRF）漏洞，可能导致信息泄露。对于这些安全漏洞，微软指出，利用它们需要事先获得电子邮件凭据。对于其中两个漏洞，微软还指出，没有提供证据表明它们可以被利用来提升特权或获取敏感客户信息。  
  
  
微软的发言人说道：“我们向这位发现者表示感谢。我们已经审查了这些报告，并发现它们要么已经得到解决，要么不符合我们的严重性分类准则下的立即修复标准，我们将评估在未来的产品版本和更新中适当地解决它们。”   
  
  
  
编辑：左右里  
  
资讯来源：ZDI、securityweek  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
利用（Exploit）         
  
利用信息系统中的漏洞的行为。也用于描述一种用于破坏网络安全性的技术。  
  
  
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
  

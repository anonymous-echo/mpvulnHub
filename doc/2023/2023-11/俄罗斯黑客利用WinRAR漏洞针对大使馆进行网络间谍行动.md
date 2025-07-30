#  俄罗斯黑客利用WinRAR漏洞针对大使馆进行网络间谍行动   
看雪学苑  看雪学苑   2023-11-23 18:05  
  
乌克兰国家安全与国防委员会(NSDC)报告称，其网络安全研究人员发现，俄罗斯背景的黑客最近在利用WinRAR的一个漏洞针对大使馆和国际组织进行网络间谍活动。  
  
  
这些攻击被归咎于一个知名黑客组织APT29（别名UNC3524、NOBELIUM、Cozy Bear、SolarStorm等）。该组织被认为与俄罗斯外交情报局（SVR）有所联系。  
  
  
乌克兰国家网络安全协调中心（NCSCC）分析了起始于今年9月的这次活动。APT29在此前的行动中使用过类似的工具和战术，例如今年4月针对基辅大使馆的行动。最近的行动主要目标是渗透阿塞拜疆、希腊、罗马尼亚和意大利的大使馆，以及世界银行、欧洲委员会、欧洲理事会、世卫组织、联合国等国际机构。  
  
  
据了解，APT29在攻击中利用了最近发现的Windows文件压缩工具WinRAR的一个漏洞（CVE-2023-38831），该漏洞允许攻击者通过利用特制的ZIP存档执行任意代码。这个漏洞已被修补，但那些未更新版本的用户仍然面临着风险。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EbpexWkOQuY3TVkuGu02ESajmg6uYLvUzzxgWADRhdicGnkVibFoDxvzV3HzmdzY6JRW9BImcfEO7w/640?wx_fmt=png&from=appmsg "")  
  
  
在本案例中，攻击者会向攻击目标发送一封钓鱼邮件，声称有一辆外交车待售。CVE-2023-38831漏洞使攻击者能够在zip存档中插入与良性文件同名的恶意文件夹。当用户点击钓鱼邮件中的RAR附件时，它将执行一个脚本来显示一份待售汽车的PDF文件，同时下载并执行一个PowerShell脚本。  
  
  
NDSC解释说：“在用户尝试打开无害文件的过程中，系统无意中处理了与文件同名的隐藏恶意内容的文件夹，从而导致任意代码执行。”  
  
  
在这次攻击活动中，攻击者还引入了一种新的与恶意服务器通信的技术。他们使用了一个名为Ngrok的合法工具，Ngrok通常用于网站开发和测试，为本地Web服务器提供临时公共URL，但网络犯罪分子部署它来掩盖他们的活动并与受损系统进行通信，以规避检测。  
  
  
  
编辑：左右里  
  
资讯来源：bleepingcomputer、therecord  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
鱼叉式网络钓鱼（Spear phishing）  
  
鱼叉式网络钓鱼是一种网络攻击，旨在使用一种非常具体且个性化的消息从受害者中提  
取敏感数据，这些消息的设计看起来像是来自收件人认识和/或信任的人的消息。  
  
该消息通常发送给个人或公司，并且由于计划周密，因此非常有效。攻击者花费时间和  
资源来收集有关受害者的信息（兴趣，活动，个人历史等），以创建鱼叉式网络钓鱼消息（通  
常是电子邮件）。  
鱼叉式网络钓鱼使用紧迫感和熟悉感（似乎来自您认识的人）来操纵受害  
者，因此目标用  
户没有时间仔细检查信息。  
  
  
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
  

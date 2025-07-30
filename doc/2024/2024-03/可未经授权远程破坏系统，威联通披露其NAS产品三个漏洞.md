#  可未经授权远程破坏系统，威联通披露其NAS产品三个漏洞   
看雪学苑  看雪学苑   2024-03-11 18:00  
  
3月9日，知名网络附加存储（NAS）设备制造商威联通（QNAP）发布了一则安全公告，披露其NAS产品（如QTS、QuTS hero、QuTScloud和myQNAPcloud）中存在三个漏洞，攻击者能够利用这些漏洞通过网络来破坏系统安全或执行恶意代码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FWNwxPhtD0Vr9iayV1xJ0f3092CQakJibl88HBHwvQ3sUasx4E65bmJibLiag5iaGdmYoPeuzNrAicOEyA/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞详情如下：  
  
CVE-2024-21899：不正确的身份验证机制允许未经授权的用户通过网络（远程）破坏系统的安全性。  
  
CVE-2024-21900：此漏洞可能允许经过身份验证的用户通过网络在系统上执行任意命令，可能导致未经授权的系统访问或控制。  
  
CVE-2024-21901：此漏洞可能允许经过身份验证的管理员通过网络注入恶意SQL代码，从而破坏数据库的完整性并操纵其内容。  
  
  
第一个漏洞（CVE-2024-21899，CVSS评分9.8）需要特别注意，因为它允许在未经认证的情况下远程执行，并被标记为“低复杂性”。而其他两个漏洞都需要攻击者在目标系统上经过认证，风险则较低。  
  
  
如下图所示，这些漏洞影响QNAP产品的左列版本，可通过将产品升级到右列版本来进行修复：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FWNwxPhtD0Vr9iayV1xJ0f34uR7ic8M4BVF4Mc9zlq8BiaAO46cm5soS1BB45c4RxWkR48s1LuUSHBQ/640?wx_fmt=png&from=appmsg "")  
  
  
要更新QTS、QuTS hero和QuTScloud，用户需以管理员身份登录，转到“控制面板 > 系统 > 固件更新”，然后在“实时更新”下单击“检查更新”以启动自动安装过程。  
  
  
要更新myQNAPcloud，需以管理员身份登录QTS、QuTS hero 或 QuTScloud，打开“应用中心”，点击搜索框并输入“myQNAPcloud” + ENTER键，接着单击更新按钮开始更新。  
  
  
NAS设备通常存储着大量有价值的数据，常与互联网保持连接，并且很可能在使用过时的操作系统/固件。由此NAS设备经常成为数据窃取和勒索的目标。所以NAS所有者最好始终保持软件更新，如非必要不将其暴露在互联网上。  
  
  
  
编辑：左右里  
  
资讯来源：QNAP、bleepingcomputer  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
 桥（bridge:）  
  
连接速度、线缆类型或拓扑结构不同但是采用协议仍然相同的网络所使用的网络设备。  
桥是第 2 层设备。  
  
  
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
  

#  TP-Link智能灯泡存在漏洞，黑客可以窃取WiFi密码   
看雪学苑  看雪学苑   2023-08-23 18:03  
  
近日，来自卡塔尼亚大学和伦敦大学的研究团队在一篇论文中指出，TP-Link的畅销产品Tapo L530E智能灯泡及其Tapo应用程序中存在四个漏洞，可能导致攻击者能够窃取目标用户的WiFi密码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G6kPt9ianXBq4P70TL9k4N7XmdPHAicMAuYm4rfSgwJaZ6Q6boxdRz177sVcGUxnepB8VC3e3ibDJSA/640?wx_fmt=png "")  
  
  
论文上写道，如今物联网（IoT）设备的数量不断增加，已经超过了138亿台，并预计将在2025年翻倍。这也导致了一个庞大的攻击面，给黑客带来了大量的入侵点，同时也给研究人员和工程师带来了安全和隐私挑战。  
  
  
例如该论文所研究的智能灯泡TP-Link Tapo L530E，在全球范围内畅销，并且其TP-Link Tapo智能设备管理应用程序在Google Play上已有1000万次安装。对这类智能灯泡的劫持可能会带来一些安全隐患，如给小偷提供了窥探受害者行为习惯的机会，借以分辨目标住所当前是否空置。  
  
  
研究人员在进行渗透测试后发现，TP-Link Tapo L530E智能灯泡的身份验证未得到充分考虑，实施的加密措施未能实现机密性。因此，附近的攻击者不仅可以随意操作灯泡，还可以操作用户在Tapo账户上拥有的所有Tapo系列设备。此外，攻击者还可以获取受害者的Wi-Fi密码，从而大大提高了其可能造成的危害。  
  
  
根据CVSS v3.1评分系统，四个漏洞中两个严重程度为高，两个严重程度为中等：  
  
漏洞1：智能灯泡与Tapo应用的身份验证不足；  
  
漏洞2：硬编码的短共享密钥；  
  
漏洞3：对称加密过程中缺乏随机性；  
  
漏洞4：消息的新鲜度不足。  
  
  
攻击实验表明，攻击者能够以各种方式利用该智能灯泡：  
  
  
例如，利用漏洞1和2来冒充灯泡并从Tapo应用中获取用户的Tapo凭据和Wi-Fi凭据，在进一步获取连接到该网络的所有其他设备的访问权限。同时，攻击者还可利用获取的凭据进行中间人攻击。  
  
  
漏洞3的存在意味着即使攻击者不了解每条消息中的明文内容，但他理解某些加密消息对目标设备的后果。因此，攻击者能够随意重复使用这些消息来操作设备。结合漏洞4，攻击者可能对目标发动拒绝服务（DoS）攻击。  
  
  
研究人员按照Tp-Link的漏洞研究计划（VRP）的要求，已向Tp-Link上报了他们发现的所有四个漏洞。Tp-Link承认了所有漏洞，称他们已经开始在应用程序和灯泡固件层面上修复这些漏洞，并计划适时发布修复程序。  
  
  
  
编辑：左右里  
  
资讯来源：arxiv  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
花指令     
  
通过加入不影响程序功能的多余汇编指令，使得杀毒软件不能正常的判断病毒文件的构  
造。说通俗点就是“杀毒软件是从头到脚按顺序来识别病毒。如果我们把病毒的头和脚颠倒  
位置，杀毒软件就找不到病毒了”。  
  
  
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
  

#  WhatsApp Windows版本存在严重漏洞：点击文件会直接执行Python和PHP脚本   
看雪学苑  看雪学苑   2024-07-30 17:59  
  
WhatsApp作为全球最流行的即时通讯应用之一，拥有超过20亿用户，每天往来数十亿条消息。然而，最近安全研究人员发现了WhatsApp Windows客户端的一个严重漏洞，该漏洞允许攻击者发送Python和PHP脚本，这些脚本在接收者打开时会被直接执行，而不发出任何警告。  
  
  
这一漏洞由安全研究员Saumyajeet Das发现。根据其研究，WhatsApp允许用户发送某些文件类型而不进行有效的安全检查。通常情况下，WhatsApp会阻止一些被认为高风险的文件类型，如.EXE、.DLL和.VBS等，但却没有将.PYZ（Python ZIP应用）、.PYZW（PyInstaller程序）和.EVTX（Windows事件日志文件）列入黑名单。这意味着，只要接收者的计算机上安装了Python或PHP，恶意脚本就可以被轻易执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8G2nMPJ7zumttib3WJQoNLMyd0bSZggblqd5Vwcrebdia4cK067O1mgocQHPQicX3oYfLNPMkyVw5uEQ/640?wx_fmt=png&from=appmsg "")  
  
  
根据测试，WhatsApp对于这些文件类型的处理方式与其他高风险文件截然不同。当用户尝试打开这些文件时，WhatsApp不会显示任何警告，而是直接执行。这一漏洞的存在，使得攻击者可以通过发送恶意脚本，轻易地在受害者的计算机上执行代码，远程控制其设备，造成严重的安全隐患。  
  
  
在Das于6月3日向Meta（WhatsApp的母公司）报告这一问题后，Meta于7月15日回应称，此前已另有研究人员报告了相同的问题。然而，令研究员感到失望的是，WhatsApp并未对此漏洞采取任何修复措施。Meta的发言人表示，他们并不认为这是一个需要由他们来特别解决的问题，并强调用户在使用WhatsApp时应保持警惕，不要随意打开陌生人发送的文件。  
  
  
这种态度引发了安全研究人员的强烈不满。Das表示，WhatsApp明明只需将.PYZ和.PYZW文件类型添加到黑名单，就能有效防止潜在的利用，但他们却没这样做。他认为，WhatsApp应当更加重视用户的安全，及时解决安全隐患，以增强用户对平台的信任。  
  
  
在网络安全领域，攻击者利用WhatsApp进行恶意活动的案例并不鲜见。假如成功利用这一漏洞，攻击者不仅可以窃取用户的个人信息，还可以在用户的设备上安装其他恶意软件，进一步扩大攻击范围。另外，由于Python和PHP在开发和数据处理中的广泛应用，还会给企业和开发者带来潜在的风险。攻击者利用这一漏洞，可以向特定目标发送恶意脚本，进行数据窃取或系统破坏。  
  
  
  
编辑：左右里  
  
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
  

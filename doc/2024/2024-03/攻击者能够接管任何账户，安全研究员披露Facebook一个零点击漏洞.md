#  攻击者能够接管任何账户，安全研究员披露Facebook一个零点击漏洞   
看雪学苑  看雪学苑   2024-03-01 17:59  
  
两天前，来自尼泊尔的安全研究员Samip Aryal披露了Facebook的一个零点击漏洞，该漏洞允许攻击者完全接管任何Facebook账户，并且无需受害者点击任何内容。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HhmzzZl1cjPI7D2FDXMhdiceGx2icdr3CdMDKDicYnPJoA0SRKB629tAxvgfNfLBuIgpIdx69Xa3Ilw/640?wx_fmt=gif&from=appmsg "")  
  
  
Samip Aryal表示，当他在Facebook的登录页面上寻找未触及/隐藏/未被注意到的端点时，通过使用多个不同的用户代理，他在密码重置流程中发现了验证码的一些有意思的特征：  
  
① 该验证码有效期比预期中要长，为两小时；  
  
② 在此期间每次请求发送的都是相同的验证码；  
  
③ 多次错误的输入尝试并不会使验证码失效。  
  
  
考虑到该验证码长度仅为6位数，  
Samip Aryal从中看到了进行暴力破解攻击的机会。  
  
  
Samip Aryal根据上述信息并凭借其对Facebook身份验证流程的广泛了解，发现接管账户的方法相对简单：  
  
  
首先选择任一Facebook账户，尝试以该用户身份登录并请求密码重置（忘记密码）；然后从可用的重置选项中选择“通过Facebook通知发送代码”。  
这将创建对易受攻击端点的POST请求。  
作为POST请求的一部分，可以在请求消息的正文中向服务器发送任意类型的任意数量的数据。  
  
  
从000000到999999的可能性似乎很多，但由于该端点没有速率限制，攻击者在大约一小时内便可遍历完，匹配代码会以302状态代码进行响应。通过  
使用正确的验证码重置账户密码，攻击者  
便可接管该账户。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HhmzzZl1cjPI7D2FDXMhdicZbd2fap2k4MjE6lBBFQMlwgFYTcDnZVRancmHbVfA4sCpDIyLoRlfQ/640?wx_fmt=png&from=appmsg "")  
  
  
凭借报告此漏洞的贡献，Samip Aryal一举登上了2024年Facebook名人堂排名第一的位置。  
  
  
报告链接：  
https://infosecwriteups.com/0-click-account-takeover-on-facebook-e4120651e23e  
  
  
  
编辑：左右里  
  
资讯来源：infosecwriteups  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
暴力攻击 (Brute Force Attack)  
  
暴力攻击是尝试所有可能性以破解加密或认证系统的技术。  
  
  
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
  

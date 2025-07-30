#  可绕过安全警告并自启Python脚本，电报修复其Windows桌面客户端中的零日漏洞   
看雪学苑  看雪学苑   2024-04-16 18:02  
  
过去几天，X和一些黑客论坛上关于Telegram for Windows中的远程代码执行漏洞的传言不绝于耳。一些帖子声称这是一个零点击漏洞，Telegram否认了这些说法，并表示演示视频很可能是一个恶作剧。  
  
  
第二天，XSS黑客论坛上有人又分享了一个漏洞利用POC，证明了Telegram for Windows源代码中的一个拼写错误可以被利用来发送Python .pyzw文件，继而绕过安全警告。该漏洞导致.pyzw文件在被点击时会自动被Python执行，而非像其他可执行文件那样收到Telegram的警告。更糟糕的是，POC中还将Python文件伪装成了一个附带缩略图的视频，非常容易欺骗用户点击该虚假视频观看。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HWLbu3juiaxmwJDQwmbiccibBDAzJqn7hTkwR6pLTQ7LaU0Y9IibAAXjzeEWtIH6CTDoBaLrKaNSH6XA/640?wx_fmt=png&from=appmsg "")  
  
  
如Telegram所说，该漏洞确实并非零点击漏洞，但仍有修复的必要。目前官方已在Telegram for Windows中修复了这一问题，以防止Python脚本在被点击时自动启动。  
  
  
漏洞成因：  
  
  
Telegram桌面客户端跟踪与风险文件相关的文件扩展名列表（如.exe），当有人在Telegram中发送这些文件类型，并且用户点击文件时，Telegram会先显示以下安全警告：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HWLbu3juiaxmwJDQwmbiccibBQP9L0gPOoYQ5KZdyYlaVjqRiaZqeaynzznMgCASksE99hmV1lQvI54g/640?wx_fmt=png&from=appmsg "")  
  
  
然而，在Telegram中共享的未知文件类型会自动在Windows中启动，并让操作系统决定使用何种程序，而当Windows安装了Python时，它会将.pyzw文件扩展名与Python可执行文件关联起来，导致双击文件时Python会自动执行脚本。  
  
  
Telegram的开发人员意识到这些类型的可执行文件应当被视为风险，并将其添加到可执行文件扩展名列表中。然而，在添加扩展名时他们犯了一个拼写错误，输入的是‘pywz’而非正确的‘pyzw’。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HWLbu3juiaxmwJDQwmbiccibBnE6NRksvEm5je4zjO0W7XyzImh0ybYu7sewXnIv3l94tfX5vZY5tag/640?wx_fmt=png&from=appmsg "")  
  
  
因此，当这些文件上传至Telegram并被用户点击时，若该用户Windows中安装了Python，它们将被Python自动启动，从而允许攻击者绕过安全警告并在攻击目标的Windows设备上远程执行代码。  
  
  
该漏洞于4月10日报告给了Telegram，并且官方表示已在‘data_document_resolver.cpp’源代码文件中更正了扩展名的拼写。同时，Telegram还在服务器端进行了修复，将.untrusted扩展名附加到pyzw文件上。  
  
  
  
编辑：左右里  
  
资讯来源：bleepingcomputer、X  
  
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
  

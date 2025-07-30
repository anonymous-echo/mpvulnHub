#  SRC中的重置密码漏洞及案例   
 Z2O安全攻防   2025-02-25 13:12  
  
**免责声明：**  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者及本公众号不为此承担任何责任。  
  
02  
  
# 文章正文  
  
  
### 1.密码重置链接不过期  
  
当用户请求更改密码时，他们会收到一个密码重置链接来重置密码，这是正常行为。但密码重置链接也应在一段时间后过期。如果链接不过期，并且可以多次使用密码重置链接来重置密码，那么这可以被视为一个漏洞。  
  
第一种情况：  
```
1、访问https://site.com/users/forgotten_password 并发送密码重置链接到您的邮箱。2、检查您的邮箱收件箱，您会看到类似这样的重置令牌链接：https://site.com/users/new_password?reset_token=your-reset-tokenand，点击链接更改密码。 3、您可以多次使用此链接重置密码。影响：密码重置链接在更改密码后不过期。案例：https://hackerone.com/reports/898841
```  
  
第二种情况：  
```
1、访问https://infogram.com/forgot 并请求密码重置链接。2、不要使用链接，将其保存在邮箱收件箱中。3、过一段时间后重复步骤1。4、这次使用步骤3中请求的密码重置链接，即第二个链接。5、更改密码后，使用步骤1中捕获的密码重置链接。6、您会发现即使在更改密码后，密码重置链接仍未过期。影响：如果网站存在令牌问题，那么步骤3中发出的重置密码令牌仍然可用且未过期。如果受害者在网吧或攻击者的设备上打开邮件并忘记注销，那么攻击者可以访问该系统并重置他的账户密码。案例：https://hackerone.com/reports/283550
```  
  
第三种情况：  
```
1、创建账户或使用现有账户。2、确认您的邮箱地址。3、现在退出您的账户并请求账户的密码重置码。4、不要使用发送到您邮箱的代码。5、在新浏览器中重新登录您的账户。6、进入账户设置并更改您的密码。7、现在检查邮箱中我们在步骤3中请求的密码重置码。8、使用该重置密码码更改您的密码。9、您可以看到您的密码已被更改。 重置码在更改密码后未过期。影响：如果网站存在令牌问题，那么步骤3中的重置密码令牌仍然可用且未过期。如果受害者在网吧或攻击者的设备上打开邮件并忘记注销，那么攻击者可以访问该系统并重置他的账户密码。案例：https://hackerone.com/reports/948345
```  
  
第四种情况：  
```
1、将密码重置链接发送到您的邮箱。2、不要打开密码链接，只需复制并粘贴到任何编辑器中。3、打开您的账户。4、进入您的账户设置。5、在账户下，您将看到账户概览。6、转到邮箱和密码选项并更改邮箱并验证。7、更改邮箱后，转到您复制的密码重置链接。8、更改您的密码。9、砰！密码已更改。影响：即使受害者认为他/她的账户受到威胁并决定更改他/她的邮箱，攻击者仍然可以更改密码。案例：https://hackerone.com/reports/685007
```  
  
第五种情况：  
```
1、攻击者访问https://card.starbucks.com.sg/forgetPassword.php 并输入他账户的邮箱。2、链接被发送到攻击者的邮箱收件箱，他点击链接同时使用代理监控请求（Burp）。3、攻击者然后修改邮箱，将受害者的邮箱放入下图所示的这两个请求中（1.PNG  & 2.PNG）。4、提交请求后，密码将被更改，受害者的密码将被更改为期望的密码。影响：这种攻击不需要受害者执行任何操作，但攻击者仍然可以接管账户并泄露受害者的个人信息以及星巴克卡，该卡可用于购买商品。攻击者还可以捕获会话ID。案例：https://hackerone.com/reports/315879
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nKLPlJmaH82BgBNrnDM3UGGR1jE1Z5bvfP2rCMafbdGibKxKWLSK4cWSbwBcT27c2R9PzoGrXiauyA/640?wx_fmt=png&from=appmsg "null")  
  
image-20241226224835264  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nKLPlJmaH82BgBNrnDM3UGibk7ye6DKRpYd2XZdBJiaj7m6hTuia2uaicjAkuw9aUPdYgz3dCHhs8eNw/640?wx_fmt=png&from=appmsg "null")  
  
image-20241226224912993  
  
第六种情况：  
```
不使用与会话对应的用户电话号码或邮箱（从请求中获取电话号码/邮箱）。1、Web应用在更改某些敏感字段之前会向邮箱发送验证码。2、在Burp中拦截请求并找到POST请求中的邮箱参数（例如：邮箱：victim@gmail.com）。3、将邮箱更改为另一个Gmail（例如：attacker@gmail.com）。4、砰！验证码已发送至attacker@gmail.com
```  
### 2.通过Referer泄露密码重置令牌  
  
1、访问https://ucp.nordvpn.com/lost-password 页面。 2、输入您的邮箱并点击重置密码。 3、检查邮箱并点击密码重置链接。 4、在密码重置页面点击下方提供的社交媒体链接，并使用Burp Suite捕获请求。 5、检查Referer头部是否泄露了密码重置令牌？  
```
GET /nordvpn/ HTTP/1.1Host: www.facebook.comUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8Accept-Language: en-US,en;q=0.5Accept-Encoding: gzip, deflateConnection: closeReferer: https://ucp.nordvpn.com/reset-password/7ac4b7c4654797e8f2a061676314b0959e7de179d33a73dfaa0152b1ec617f46/Cookie: fr=1oATYBf0BJ0DXndaC.AWV1Ag1KKbwlzMPBUI8vUz2NaP0.BduttV.ZM.F3B.0.0.BdwUoa.AWWnaTR3; sb=Vdu6XRBcBVULAbruWmZbgfPF; datr=Vdu6Xar5xVM18qIAfGd61Mh3; c_user=100003539320116; xs=4%3AcaHYJilvx4Lkqg%3A2%3A1572948495%3A6163%3A4671Upgrade-Insecure-Requests: 1
```  
  
**影响：**  
 例如，用户A忘记了他的密码，他访问了忘记密码页面并重置密码，然后通过电子邮件收到了链接并打开了密码重置页面。然后用户A突然想起了他的密码，并决定使用Facebook，他打开了NordVPN的Facebook页面或点击了社交媒体页面，然后链接将在Referer头部泄露。这允许控制特定网站的人员更改用户的密码（CSRF攻击），因为这些人知道用户的重置密码令牌。  
  
其他影响 - 账户接管可能 操作NordVPN社交媒体页面的人员也可以利用这一点，如果他们启用了页面分析，他们可能可以看到用户从哪里引用到他们的页面，从那里他们可以看到密码重置链接并可以为受害者重置密码。  
  
**案例：**  
  
https://hackerone.com/reports/751581  
### 3. 通过响应泄露密码重置令牌  
1. 1. 发送密码重置链接请求。  
  
1. 2. 拦截响应。  
  
1. 3. 查看响应中是否返回了重置密码链接。  
  
**示例请求：**  
```
POST /access/forgotPassword HTTP/1.1 Host: api.xprogram.comUser-Agent: Mozilla Accept: application/json, text/plain, */* Accept-Language: en-US,en;q=0.5 Content-Type: application/json;charset=utf-8 Referer: https://app.xprogram.com/account/forgot-password  Content-Length: 52 origin: https://app.xprogram.com  Cookie: redacted=yes;Connection: close {“email”:”foobar@gmail.com”}
```  
  
**示例响应：**  
```
HTTP/1.1 200 OK{“name”:”send-email”,”resetPasswordLink”:”https://app.xprogram.com/account/reset-password?token=xxxxxxxxxzzzzzzzzyyyyyyyy&#34;  , “many-other-parameters”:”many values”}
```  
  
案例：  
  
https://medium.com/@yassergersy/account-take-over-via-reset-password-f2e9d887bce1  
### 4.通过操纵邮箱参数重置密码。通过响应泄露密码重置令牌  
  
在为受害者用户请求密码重置链接时，我们可以尝试以下参数操纵，以在攻击者邮箱中获得受害者的重置链接副本。  
```
双重参数（即HPP / HTTP参数污染）：email=victim@xyz.tld&email=hacker@xyz.tld抄送：email=victim@xyz.tld%0a%0dcc:hacker@xyz.tld使用分隔符：email=victim@xyz.tld,hacker@xyz.tldemail=victim@xyz.tld%20hacker@xyz.tldemail=victim@xyz.tld|hacker@xyz.tld无域名：email=victim无顶级域名（TLD）：email=victim@xyzXML：尝试XXE！JSON表格：json{"email":["victim@xyz.tld","hacker@xyz.tld"]}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nKLPlJmaH82BgBNrnDM3UGPQSxoX2JFMFC4LSVVWe2YLMicPicMyibfCrEPJm7mqndPib1tuPK5RLBWg/640?wx_fmt=png&from=appmsg "null")  
  
Capture  
  
**案例：**  
  
https://hackerone.com/reports/1175081  
  
### 5. Host Header中毒  
  
实现密码重置功能的常见方式是生成一个密令并发送包含该令牌的链接的电子邮件。 如果攻击者能够更改Host头部，那么他们就可以将令牌重定向到他们的网站或服务器，这可能导致密码重置中毒。  
1. 1. 拦截请求并更改Host头部为attacker.com。  
  
1. 2. 现在检查您的邮件，如果您收到了包含attacker.com的URL的密码重置链接，那么它就易受密码重置中毒的影响。  
  
直接将Host更改为任何网站大多数时候是不起作用的。您可以尝试以下方法绕过这个问题。  
  
添加X-Forwarded-Host头部：  
```
Host: attacker.comX-Forwarded-Host: target.com或：Host: bing.comX-Forwarded-Host: target.com或：Host: target.comHost: attacker.com您可以使用ngrok服务器作为您的攻击者服务器！
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nKLPlJmaH82BgBNrnDM3UGPMBkRznWJoeuyWuXvWSKCX1iczAnjth2eGDUXNHF3zbcobreiaLzwJpA/640?wx_fmt=png&from=appmsg "null")  
  
Capture  
  
**案例：**  
  
https://shahjerry33.medium.com/otp-bypass-developers-check-5786885d55c6  
  
https://hackerone.com/reports/226659  
### 6. 密码重置无速率限制  
  
速率限制用于控制进出网络的流量量。 基本上，没有速率限制意味着没有机制来保护您在短时间内发出的请求。 因此，尝试发送大量请求，如果没有阻止您，那么您可以将其视为漏洞。  
1. 1. 启动Burp Suite并拦截密码重置请求。  
  
1. 2. 发送到 intruder。  
  
1. 3. 使用空负载。  
  
**案例：**  
  
https://hackerone.com/reports/838572  
### 7. 通过密码重置页面进行用户枚举  
  
用户名枚举是攻击者试图从Web应用程序中检索有效用户名的活动。 您可以在登录页面、注册表单页面或密码重置页面上检查这种类型的漏洞。  
1. 1. 转到密码重置页面。  
  
1. 2. 输入一个存在的用户名，不会有错误，并将被重定向到登录页面。  
  
1. 3. 输入一个不存在的用户名，会有错误提示，如“用户账户不存在”等。  
  
**案例：**  
  
https://hackerone.com/reports/77067  
### 8. 密码重置页面的HTML注入  
  
HTML注入也称为内容欺骗，也称为内容注入，或“任意文本注入”或虚拟篡改。  
  
步骤如下：  
  
打开应用程序的创建新账户页面，输入您的邮箱和密码。 在名字参数中，插入HTML注入载荷  
```
( <a href="attacker.com"><h1>Please click here to login to your account<h1></a> )
```  
  
**案例：**  
 https://hackerone.com/reports/111094  
  
建立了一个  
src专项圈子  
，内容包含**src漏洞知识库**  
、**src挖掘技巧**  
、**src视频教程**  
等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuY6DfYOuUzWiaPBBq4L5bV9ZRMpUcFktl9oiazJicibKEVwZoWo5dEaXGHIoa6yOEkfnicbMibJDALxuk1w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  

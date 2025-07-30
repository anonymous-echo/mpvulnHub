#  通过 X-Forwarded-Host 泄露密码重置令牌   
 Ots安全   2024-12-28 06:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tafB0xYPklyy3vJbLgTZccNiamcJcKiaFbyrxKIfj3nXdaJC04pPeP0qicLIXCKoDodiaLL8WLT2ubU0zA/640?wx_fmt=webp&from=appmsg "")  
  
这是我的第一篇博客，如果您发现任何拼写错误，请在接下来的几分钟内耐心等待。这篇博客是关于一个漏洞的，我在 Hackerone 的私人程序中发现了这个漏洞，它允许我接管任何用户的帐户。但在开始这篇博客之前，我想提供一些有关 Host 标头的基本信息。  
  
**HTTP 主机标头是什么？永久链接**  
  
HTTP Host 标头是自 HTTP/1.1 起强制的请求标头。它指定用户想要访问的域名。  
  
例如，如果用户访问 https://example.com，那么他们的浏览器将发出包含以下主机标头的请求：  
  
```
GET / HTTP/1.1

Host: example.com
```  
  
  
几天前，我在 Hackerone 上收到一条通知，说我被邀请加入一个私人项目。所以我接受了邀请，开始搜索这个私人项目。在开始搜索这个私人项目时，我花了 5-6 天的时间寻找跨站点脚本 (XSS)、IDOR、SQL 注入、登录页面缺陷、信息泄露和子域接管，但我仍然一无所获。  
  
休息了几个小时后，我再次开始搜索该域名，但这次我发现了一个有趣的功能，这是我上次没有看到的。这个有趣的功能就是密码重置功能。所以我心想让我们来试试这个密码重置功能。  
  
我不能透露目标的名称，因为它是一个私人程序。因此，我们假设目标是site.com。他们的密码重置功能如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafB0xYPklyy3vJbLgTZccNiagBS5BezLpYpHFr8dT5Z3Px3R0iaqGZ9ZVnUQ5dmEEVtQlaiaCbWCI2JA/640?wx_fmt=png&from=appmsg "")  
  
我注意到，每当我们输入电子邮件并点击重置密码时，我们都会收到一封带有密码重置令牌链接的密码更改电子邮件。  
  
密码重置令牌链接如下所示：  
  
```
https://site.com/action-token?key=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIzZWM2ODU2Z
```  
  
  
这次我决定拦截密码重置请求，并且启动了我的 ngrok 服务器。  
  
原始请求如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafB0xYPklyy3vJbLgTZccNia2b2UxPntdrBcAwTM1F4iceA5CMsIx9iawzzc3IpTstqbk3K1mSXeJ0vA/640?wx_fmt=png&from=appmsg "")  
  
burpsuite 中的密码重置请求图像  
  
然后我在原始请求中添加了另一个标头“X-Forwarded-Host”，其中包含我的 ngrok 服务器域。所以现在修改后的请求如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafB0xYPklyy3vJbLgTZccNiaZKDQibchwgthfFy6xfBwNibnVtHjztKBzAWCGBAqMbX2YAppDkbbyibKw/640?wx_fmt=png&from=appmsg "")  
  
带有“X-Forwarded-Host”标头的密码重置请求图像  
  
现在我收到了一封更改密码的电子邮件，但带有我的 ngrok 服务器域。密码重置令牌链接如下所示：  
  
```
https://95saf4ct71g.ngrok.io/action-token?key=wia2lkIiA6ICciOiJIUzI1NiIsInR5cCIgODU2ZeyJhbGiA
```  
  
  
您还可以看到，我只需在密码重置请求中添加标头“X-Forwarded-Host”即可成功更改主机。  
  
然后我注意到，如果我在密码重置页面输入受害者的电子邮件并拦截该请求，如果我添加另一个带有我的恶意域的标头“X-Forwarded-Host”。那么受害者将收到一封带有我的恶意域的密码重置令牌链接的电子邮件。当受害者点击该链接时，他将重定向到我的网站，他的所有令牌都将泄露给我。然后我可以使用他泄露的令牌更改受害者的密码。是的，这个漏洞的影响是完全接管帐户。  
  
所以现在我可以通过重置密码来完全接管在 site.com 上拥有帐户的任何人的帐户。  
  
因此，我没有浪费任何时间，成功提交了这个漏洞并提供完整的概念证明，然后 Hackerone 的私人计划奖励我 1000 美元。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafB0xYPklyy3vJbLgTZccNiaetrRdgpEdz0yL4drKKiaOyWNvKhpulZtkhvxjsdxc8fmvya850X4OQA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

#  XSS 到 RCE   
 Ots安全   2024-05-18 13:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
我最近看到一篇有趣的文章，介绍了威胁行为者将易受攻击的网站转换为强大的有效负载登陆页面的策略。该帖子可以在这里找到：https://www.bleepingcomputer.com/news/security/phishing-campaign-uses-upscom-xss-vuln-to-distribute-malware/。通过一些变体，您可以使用 XSS 漏洞加载外部 JavaScript 文件，该文件会创建一个您可以控制的“新页面”。这种策略的好处是，您的登陆页面 URL 仍然可以指向您的客户端域，但它可以加载您想要的任何 HTML 代码、下载有效负载文件、伪装成真实站点等。  
  
XSS 的影响并不总是类似于会话窃取，有时它是一个全新的向量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafeCNaUVXUAw6ww5h6sDYA6ndhOBTibdEJUwYQO08wg5yOuBE8sYhVXSlOgt8g04qerhqjApa3MHxA/640?wx_fmt=png&from=appmsg "")  
  
首先，您需要找到某种 XSS 漏洞，您可以通过将用户定向到特定 URL 来触发该漏洞。这可以通过基于 URL 参数的反射 XSS 或可以从特定 URL 触发的存储 XSS 之类的方式来完成。无论哪种方式，您都需要某种 URL 来引导用户单击。我已经建立了一个容易受到 XSS 攻击的基本公司网站。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafeCNaUVXUAw6ww5h6sDYA6nxHUBiaVZnicichkWnols5ibiamHlut16s8xSpKFd7Mm2eHicS1wSZCPMF7Q/640?wx_fmt=png&from=appmsg "")  
  
通过构造，XSS 很容易被触发。  
```
/index.php?xss=<script>alert(1)</script>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafeCNaUVXUAw6ww5h6sDYA6tozmDFy9abMsm1T26SZ1S1CO8FJ5s1x2FDDcUOkqdeOnGu1jyt06DQ/640?wx_fmt=png&from=appmsg "")  
  
由于我们想要托管一个新的登陆页面，因此我们必须克隆一个网站才能使用。我更喜欢使用 SingleFile，它是一个浏览器扩展。它只会将页面克隆为单个 HTML 文件，您可以将其用作登陆。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafeCNaUVXUAw6ww5h6sDYA6WhQGwic4UIbcgoOnIiad1sNts31liciaNm5qToDg6DDP6bicwjPb3TJibFZg/640?wx_fmt=png&from=appmsg "")  
  
在本例中，我将克隆该网站，以便可以根据需要编辑 HTML，SingleFile 会为您下载所有内容。  
  
使用以下 bash 语句进行快速转换会将您的 HTML 文件转换为可用的 JS 文件。当然，您可能希望将其他 JS 注入到会话中，或者自动下载您的有效负载文件。我个人喜欢提供一个链接，上面写着“如果您的下载没有开始，请单击此处”，但不是自动下载（用于垃圾邮件检查器）。有了创造力，你就可以做任何你想做的事情。  
```
sed 's/"/\\x22/g' SINGLEFILE_OUTPUT_FILE.html | sed -z 's/\n//g' | awk '{print "htmlstring = \"" $0 "\";"}' > JS_OUTPUT_FILE.js

echo -e "\n document.write(htmlstring); \n" >> JS_OUTPUT_FILE.js
```  
  
在这种情况下，我可以简单地通过 XSS 向量将克隆的 HTML 代码加载到我的目标网站中，这样它看起来就像真实的一样。我编辑了登录页面以匹配文件下载借口，并提供了一个链接到我的有效负载的“单击此处”按钮。由于 XSS 是基于 URL 的，因此我可以将其放入电子邮件中并引导用户访问它。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafeCNaUVXUAw6ww5h6sDYA6ndhOBTibdEJUwYQO08wg5yOuBE8sYhVXSlOgt8g04qerhqjApa3MHxA/640?wx_fmt=png&from=appmsg "")  
  
非常时尚的登陆页面，加载在客户端网络域上。由于 URL 参数有时看起来很粗略，有时我会包含一些假参数，例如download=OnboardingDocument.docx&cookie=<snip>掩盖实际的 XSS 负载。  
  
**限制**  
  
在使用这种技术进行交互时，我发现了一些奇怪的限制：  
- 内容安全策略标头：这可以限制加载外部外部 JS 文件。然而，有时可以通过简单地将整个 JS 有效负载包含在原始 XSS 变量中来绕过这一点。但难度明显更大。  
  
- 存储的 XSS：我从未尝试过类似的方法，但我认为只要您可以通过 URL 将用户定向到您的 XSS 登陆，仍然可以执行。  
  
- 奇怪的 HTML 技巧：根据 XSS 所在的位置，页面将加载到 HTML 的包含部分（如 div/表格/等）中，这看起来根本不正确。您可以通过关闭原始站点 HTML 并注释掉下面的内容来解决此问题，但这是一个相当老套的修复。要修复此类问题，您必须施展一些 HTML 魔法。  
  
```
原文地址：
https://whynotsecurity.com/blog/xss-to-rce/
```  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

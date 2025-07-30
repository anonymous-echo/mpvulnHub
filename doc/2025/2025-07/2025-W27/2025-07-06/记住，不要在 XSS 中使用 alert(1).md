> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247487049&idx=1&sn=0431eff40c4f13bca4cec21369e2ac93

#  记住，不要在 XSS 中使用 alert(1)  
原创 玲珑安全  玲珑安全   2025-07-06 13:09  
  
> 未经许可，不得转载。  
  
## 引言  
  
跨站脚本攻击（Cross-site scripting，简称 XSS）是一类安全漏洞，实质是在网站中注入恶意脚本代码，从而影响其他用户的正常使用。这类漏洞也是漏洞赏金计划中常见且可报告的安全问题之一。  
  
通过注入包含 alert(1) 的 XSS 载荷，可以在载荷执行时弹出窗口，弹窗的出现即表明载荷已被执行。根据代码运行的位置，可能存在进一步注入恶意代码的潜在风险。  
## alert(1)  
  
使用 alert(1) 作为 XSS 载荷的主要优势在于其高度的可视化特性。注入该代码后，可以直观地观察其执行时机，这在输入项较多的网页中尤为便捷。  
  
而且通过更改 JavaScript alert() 函数的参数，可快速定位哪些位置的 XSS 注入成功。  
  
![]( "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsdnI2DfYQ0QbQzeCyncrdyfyXgv68aygt3qu1vErfmBFQn9s3kNCDpg/640?wx_fmt=png&from=appmsg "")  
  
  
使用 alert(1) 还有另一优势，即某些前端浏览器 JavaScript 框架的模板引擎允许使用受限形式的 JavaScript，例如打印作用域变量或进行简单数学运算。由于框架限制，攻击者无法真正注入恶意代码，但仍能使用 window.alert(1)，因为 window 对象对网页功能必不可少。  
  
同样，window 对象包含攻击者最感兴趣的信息，如 window.localStorage 或 window.document.cookie。在此情形下，成功执行 alert() 可能意味着发现的 XSS 漏洞具有较高严重性，值得报告。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVls5CLqQqhhRYEbfb9rmhcu4XbzXcNS4VTKeP5QWxBYmYmkohnlBTDQlw/640?wx_fmt=gif&from=appmsg "")  
  
  
然而，受限的 JavaScript 模板引擎现今使用频率大幅下降。随着时间推移，开发者逐渐认识到这些模板过于难用，需依赖多种修复手段和绕过方式规避限制。  
  
虽然弹窗看似是良好的注入判定依据，显示 XSS 是否具备真正利用价值，但事实并非如此。弹窗出现并不必然证明存在安全漏洞。  
  
接下来以 Google 的 Blogger 服务为例说明原因。  
## 在 Google Blogger 中实现 XSS  
  
进入 Blogger 并探索其功能，发现可以注入部分 HTML 和 JavaScript。具体操作为：创建新博客文章，进入左侧边栏“布局”（Layout）菜单，点击“添加小工具”（Add Gadget），选择“HTML/JavaScript”。  
  
此功能允许注入包含 alert(1) 的脚本：  

```
<script>alert(1)</script>
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsiatmNFU1QPjJgGOuON1mPJhT0ebpmcKdkwqOyUE5aR71q4bPAdoFTqw/640?wx_fmt=gif&from=appmsg "")  
  
  
目前我们尚不清楚脚本执行位置，故继续在 Blogger 平台完成文章，输入测试文本后点击页面右上角“预览”按钮查看效果。  
  
随后 alert(1) 载荷触发，浏览器地址栏显示 URL 为：  

```
https://www.blogger.com/blog/post/edit/preview/...
```

  
表面看该站点属于漏洞赏金范围，是否意味着我们发现了漏洞？  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsc6NPpy9CW8QGkjGW8J9xPlicKZtIXjOFT7u1YdDmfy9XumAfLdJfYyg/640?wx_fmt=gif&from=appmsg "")  
  
  
情况并非如此，以下进行分析。  
  
将 alert(1) 改为 alert(document.domain) 后，用于显示实际注入代码的域名，结果我们发现显示在眼前的是 usersubdomain.blogspot.com，而非 blogger.com。  
  
使用开发者工具查看网页源码，发现 blogger.com 通过 iframe 嵌入 usersubdomain.blogspot.com 网站，载荷实际执行于后者域名，解释了弹窗显示的并不是 blogger.com 域名。  
  
此处引出重要问题：Google 为何使用两个不同域名实现 Blogger 服务？答案是为了防范 XSS 攻击。  
  
相关资料表明，Google 通过沙箱机制保障自身及用户安全：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVls4rIHjWOAxAoHhF6p5tefm0AhjPcGs8uHicTp8Gqvlf9EMAib3Qkl7QnQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
## 沙箱机制  
  
Google 明确使用多个沙箱域名安全托管各类用户生成内容。许多沙箱专门隔离用户上传的 HTML、JavaScript 或 Flash 小程序，确保这些内容无法访问用户数据。  
  
用户 Cookie 存储于 blogger.com 域下，来自 usersubdomain.blogger.com 的 XSS 攻击因同源策略无法访问这些 Cookie。同源策略规定，脚本只有在两个网页具有相同来源时，方可访问彼此内容。本例中，博客运行于沙箱，其脚本仅能访问沙箱内容，无法访问其他用户沙箱，因为这些网页并非同源。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsGQklwanss30f9wib3CRO5JNW44aMJ5Pflcu3PxYa5jEhQ7xkJdthYtA/640?wx_fmt=gif&from=appmsg "")  
  
  
实际渗透测试中，建议使用 alert(document.domain) 或 alert(window.origin) 载荷，准确获知 XSS 实际执行域名，辅助判断漏洞是否真实存在安全隐患。  
## 沙箱 iframe  
  
除了使用沙箱域名，iframe 也可被沙箱化。  
  
Google 实现了一个 JSONP 沙箱，创建了一个可含 XSS 载荷的 iframe，同时为该 iframe 设置了 sandbox 属性。为什么要这样做？接下来让我们一探究竟。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsm2aQrxZlewTD2wJhuoyhEBy7XEfVJVXb4PKQeb7XzQ3PCJuDA0ic0ow/640?wx_fmt=gif&from=appmsg "")  
  
  
我们设计了一个工具，可通过 eval 函数执行 JavaScript 表达式：  

```
function unsafe(t) {
    document.getElementById(&#34;result&#34;).innerText = eval(t);
}
```

  
输入表达式 1+2，返回结果为 3，符合预期：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlswQ583brLul6kQpW8xONsfDjFo6aibuvMclZ6sGWQ7yylIxIbnzkvtiaQ/640?wx_fmt=gif&from=appmsg "")  
  
  
定义一个秘密会话令牌：  

```
document.secret =&#34;SESSION_TOKEN&#34;;
```

  
注入 alert(document.secret) 可窃取该令牌：  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlstf03jqDiaLmDpeO3FUX3D3Mlx3icaBlAM788rWWUc7ljxUwRArPRcr0A/640?wx_fmt=gif&from=appmsg "")  
  
  
稍作修改代码，使脚本在 iframe 内执行。新 unsafe 函数如下：  

```
function unsafe(t) {
    var i = document.getElementById('result'); // 获取 <iframe>
    i.srcdoc = &#34;<body><script>document.write(&#34; + t + &#34;);<\/script></body>&#34;;
}
```

  
并且为 iframe 设置 sandbox 属性：  

```
<iframe id=&#34;result&#34; sandbox=&#34;allow-scripts allow-modals&#34;></iframe>
```

  
计算 1 + 2 的功能依然是正常的：  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsrWwJ4OLAQvIHOicWWRa07nZdKgFYqmqvcWYyIS10cdPvw6s5L13FicaQ/640?wx_fmt=gif&from=appmsg "")  
  
  
执行 alert(1) 时也弹出了窗口，但这是否说明该代码与先前示例同样存在漏洞？  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsiaSLRClYD9eTOoGI6vFFUSr1pIcFxXR5BGmU2JA3jiavdwRKaNstXjkA/640?wx_fmt=gif&from=appmsg "")  
  
  
为了验证这一点，尝试执行 alert(document.secret) 以获取秘密会话令牌，结果显示：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsae0dXQsZATReicBtTuEpCqbn7WzpHPodyficXygKfaTdVOdJibdsficNyw/640?wx_fmt=gif&from=appmsg "")  
  
  
返回 undefined。  
  
同时，执行 alert(window.origin) 或 alert(document.domain) 后的结果均为空：  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsqEMFXwU8Wf5krcfVOhPQAXbfRR6yn6cS3okvywYEC1CiaLXsYthXXDw/640?wx_fmt=gif&from=appmsg "")  
  
  
该情况与 Google Blogger 中沙箱子域相似，iframe 与嵌入网页相互隔离，无法访问秘密会话令牌。  
  
此结果进一步验证 alert(document.domain) 和 alert(window.origin) 的价值：在判定是否存在可提交的有效安全漏洞时极为重要。  
## 控制台日志  
  
当我们发现注入发生在沙箱 iframe 内时，通常 sandbox 属性未启用 allow-modals。例如在 sites.google.com，创建网页并尝试嵌入 HTML 和 JavaScript：  

```
<script>alert(1)</script>
```

  
然而，注入后无任何响应。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsEuTsbApUv7IXjgVJMIS9P5H4eIh2SDBnQpcWKficdoBkVst9n5nmDJw/640?wx_fmt=gif&from=appmsg "")  
  
  
借助浏览器开发者工具控制台日志，我们发现 alert(1) 被沙箱 iframe 阻止：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsHQmvTFZN0xOoKJBfG9xPTrtvxdoGPGGQpiczzVlk9aIIfvWrpBKpMqA/640?wx_fmt=png&from=appmsg "")  
![]( "")  
  
  
在这种情况下，推荐使用如下方式：  

```
<script>console.log(&#34;XSSTEST&#34;)</script>
```

  
这样可以观察 XSS 载荷是否及在哪被执行。  
  
如下图所示，载荷被执行了。那么这算是一个漏洞吗？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsiarDfaKJRPwKeW3GaoSnbicSM6NGaaZUns32HTNupEVpqDng0e4mfYJQ/640?wx_fmt=png&from=appmsg "")  
![]( "")  
  
  
修改脚本为：  

```
<script>console.log(&#34;XSSTEST&#34;+ window.origin)</script>
```

  
我们发现，载荷依旧在沙箱域中执行：  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsUTRbHlaZQ0mjKE4FEqMT04RmkwL4n8pku5iabSaDnc0w5RGXQqCriaFw/640?wx_fmt=gif&from=appmsg "")  
## 结语  
  
本文展示了使用 alert(document.domain) 和 alert(window.origin) 可告知 XSS 载荷实际执行的域或 iframe。各示例均显示载荷执行于隔离沙箱环境，意味着无法访问任何敏感对象，包括秘密会话令牌或其他用户信息。  
  
那么，为何仍需关注沙箱 iframe 或子域中的 XSS 注入？既然此类漏洞通常不符合漏洞赏金条件，研究的意义又是为何？  
  
以一个嵌入且沙箱化了 JSONP iframe 的网站为例，该网站通常会通过 postMessage 与 iframe 进行通信，因此可利用网站与 iframe 之间消息传递机制的方式，将 XSS 载荷传递到主网站并在那里执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsadE7x4PbCqVZk6iaylADRywSnGdURibfx0VZcW00W41n4iaeSYpNgrZaA/640?wx_fmt=gif&from=appmsg "")  
  
  
这基本上称为沙箱逃逸（sandbox escape），因为漏洞根源不在沙箱内首次 XSS 注入，而在于能成功逃逸沙箱并在主站触发 XSS。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfP1wx4aGjqT1lmtWHVkMqfa5Ee8UVlsQvdicHiaTjibGeiaicJGDwcLvJdKm29Ek2IECpINe5bibCZqhqK4Dfreu9pw/640?wx_fmt=gif&from=appmsg "")  
  
  
总之，Google 允许沙箱子域内存在 XSS，单凭简单 alert 不足以证明发现严重 XSS 漏洞。应始终使用 alert(document.domain) 或 alert(window.origin) 等载荷，确认 XSS 实际执行的域名。  
  
****  
**培训咨询v**  
  
  
**linglongsec**  
  
****  
****  
****  
**SRC漏洞挖掘培训**  
  
****  
玲珑安全第一期SRC漏洞挖掘培训  
  
  
玲珑安全第二期SRC漏洞挖掘培训  
  
  
玲珑安全第三期SRC漏洞挖掘培训  
  
  
玲珑安全第四期SRC漏洞挖掘培训  
  
  
玲珑安全第五期SRC漏洞挖掘培训  
  
  
玲珑安全第六期SRC漏洞挖掘培训  
  
  
****  
**往期漏洞分享**  
  
  
[入侵全球最大的航空公司和酒店奖励平台](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486932&idx=1&sn=2637bc5362a6baebe08c97de465d8ab7&scene=21#wechat_redirect)  
  
  
  
[啊？谁把我黑了？？（二）](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486901&idx=1&sn=e37d94d6331114f0a1f78f4f40c8fb5c&scene=21#wechat_redirect)  
  
  
  
[啊？谁把我黑了？？（一）](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486885&idx=1&sn=c40e614c67e8829e30bbc6df7f7a1ba2&scene=21#wechat_redirect)  
  
  
  
[仅凭车牌号，黑客如何远程控制起亚汽车？](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486873&idx=1&sn=43f50a3cc083c19519786a2febe161cb&scene=21#wechat_redirect)  
  
  
  
[黑进斯巴鲁——只需车牌号，10秒接管车辆](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486860&idx=1&sn=468f0cbffdbbc77dba97f69d9d73dc04&scene=21#wechat_redirect)  
  
  
  
[要挂科了？那就黑一下教务处系统吧...](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486677&idx=1&sn=66f24e57c29ed5efa98599452843fd71&scene=21#wechat_redirect)  
  
  
  
[价值10w的Google点击劫持漏洞](https://mp.weixin.qq.com/s?__biz=Mzg4NjY3OTQ3NA==&mid=2247486716&idx=1&sn=360e3382bd90ee5e9748403f5a97ee0e&scene=21#wechat_redirect)  
  
  
  
  
**玲珑安全B站公开课**  
  
https://space.bilibili.com/602205041  
  
  
  
**玲珑安全QQ群**  
  
191400300  
  
  

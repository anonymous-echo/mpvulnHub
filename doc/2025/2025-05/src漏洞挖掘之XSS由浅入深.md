#  src漏洞挖掘之XSS由浅入深   
Poseidon  神农Sec   2025-05-12 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
原文链接：  
https://xz.aliyun.com/news/17955  
  
作者：  
Poseidon  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**XSS由浅入深**  
  
### XSS漏洞原理  
  
  
跨站脚本攻击（  
**Cross Site Scripting**  
，简称 XSS），当应用程序将用户提交的数据发送到浏览器的页面中，但未经过适当的验证或转义时，就会引发跨站脚本（XSS）漏洞。这种漏洞利用了浏览器的  
**特性**  
，而不是缺陷。浏览器的同源策略确保只有发布 Cookie 的网站才能读取该网站的 Cookie，这一机制用于保护用户的隐私和安全。然而，XSS 漏洞可以突破这一保护，攻击者可以通过注入恶意脚本来窃取用户的 Cookie，劫持用户的 Web 行为，甚至结合 CSRF（跨站请求伪造）进行针对性的攻击，进一步导致用户信息泄露或账户劫持等严重安全问题。  
  
### 漏洞类型  
  
  
根据恶意脚本的传播方式和触发原理，XSS 漏洞通常可分为三类：  
**反射型（Reflected XSS）**  
、  
**存储型（Stored XSS）**  
 和   
**DOM 型（DOM-based XSS）**  
。这三类漏洞在攻击机制上有所不同，下面分别进行说明。  
  
##### 反射型 XSS（Reflected XSS）  
  
  
反射型 XSS 多出现在搜索框、登录页面等用户输入内容会被立即回显的位置。攻击者将恶意脚本注入到 URL 中，诱导用户点击特定链接，从而触发脚本执行。  
  
  
**特点：**  
  
- 脚本不会被存储在服务器上，仅在一次请求-响应周期中生效；  
  
- 需要用户主动点击攻击者构造的恶意链接；  
  
- 常用于窃取 Cookie 或进行钓鱼欺骗。  
  
**利用反射型 XSS 进行 Cookie 窃取通常需要满足两个条件：**  
  
1. 用户点击了攻击者精心构造的 URL；  
  
1. 目标网站存在反射型 XSS 漏洞，并在页面中回显了未转义的用户输入。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUyfJibrFuXct36T9fHqkwdicpjPiaWJsopXOxqlqtQL9m1h8wZ7HMf3a8OS6iao5wzR6AvjzAJuKbeYg/640?wx_fmt=png&from=appmsg "")  
  
##### 存储型 XSS（Stored XSS）  
  
  
存储型 XSS 是最危险的一类，攻击者将恶意脚本提交到服务器端，脚本会被存储在数据库、日志或其他持久化介质中，并在其他用户访问相关内容时被加载和执行。  
  
  
**常见触发场景：**  
  
- 留言板、评论系统、论坛帖子、用户签名等交互区域；  
  
- 管理员后台浏览用户内容时自动触发。  
  
**危害：**  
  
- 可批量影响所有访问该页面的用户；  
  
- 可造成蠕虫式传播、管理员权限劫持等严重后果；  
  
- 攻击持续时间长，难以察觉。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUyfJibrFuXct36T9fHqkwdic8XJibHFqibEsA5SYgRoQzkiczMKWDB2dZAJhiaeZrsajAsGjPiadRlMYqLQ/640?wx_fmt=png&from=appmsg "")  
  
##### DOM 型 XSS（DOM-based XSS）  
  
  
DOM 型 XSS 是基于浏览器中的文档对象模型（DOM）进行攻击的一种方式，脚本注入和执行完全发生在客户端，服务端并不直接参与。  
  
  
**特点：**  
  
- 攻击入口仍通过 URL 参数传递；  
  
- 恶意代码不出现在 HTML 源码中，而是在浏览器解析 DOM 时动态执行；  
  
-  主要依赖客户端 JavaScript 中的不安全操作（如   
document.write()  
、  
innerHTML  
、  
eval()  
 等）；   
  
```
```  
  
如果攻击者访问页面时将 URL 设置为：  
  
```
```  
  
脚本中的   
document.write()  
 会将   
<script>alert(1)</script>  
 动态写入页面，从而被执行。  
  
  
**注意：**  
DOM 型 XSS 与反射型类似，也需要用户点击特定 URL，但漏洞本质存在于前端 JavaScript 代码中。  
  
### 攻击面  
  
##### 示例  
  
  
XSS 漏洞出现的原因很简单，主要是浏览器将用户输入的数据误当作 JavaScript 代码执行。下面通过一个简单的示例来引出 XSS 可能出现的典型场景。  
  
```
```  
  
在该示例中，用户提交的   
keyword  
 参数被直接嵌入到 HTML 页面中，既未经过任何过滤，也未进行 HTML 实体转义。若攻击者在搜索框中输入以下内容：  
  
```
```  
  
页面最终渲染出来的 HTML 将变成如下所示：  
  
```
```  
  
此时脚本将被立即执行，弹出一个提示框。这个 payload 仅用于演示 XSS 漏洞的可执行性。实际上，攻击者可以利用这一漏洞执行任意 JavaScript 代码，例如窃取用户的 Cookie 信息：  
  
```
```  
  
当用户访问被注入恶意脚本的页面时，浏览器会自动请求攻击者搭建的服务器，并在 URL 中附带当前用户的 Cookie。攻击者即可借此获取用户的身份凭证，从而进行进一步的账号冒用或操作伪造。关于此类攻击可能带来的更多危害，将在下文的“漏洞危害”章节中进行详细说明。  
  
##### 表单输入字段  
  
```
```  
  
如果用户输入：  
"><script>alert('XSS')</script>  
，页面将执行恶意脚本。  
  
##### URL 参数注入  
  
```
```  
  
后台返回页面  
  
```
```  
  
若无转义处理，脚本将直接执行。  
  
###### 示例  
  
  
💥  
name  
 参数会直接显示在页面上。  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUyfJibrFuXct36T9fHqkwdicO7YhOgicIicycfhqibUYnmGXyJKLJoccZlrogEHmCMoviatAx71jenWpxQ/640?wx_fmt=png&from=appmsg "")  
  
  
payload  
  
```
```  
  
##### HTTP 请求头注入  
  
  
攻击者伪造请求头  
  
```
```  
  
后台记录日志的代码  
  
```
```  
  
若管理后台页面展示日志时未转义，管理员浏览时将触发 XSS。  
  
###### 示例  
  
  
💥添加  
referer: "type="test" onclick="alert('test')  
出现提示。  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUyfJibrFuXct36T9fHqkwdic8khFmkty2FxmQkP6jzXM6dkDIEdtc2uf6sezI2wH9u8mqZ3fh3SWfQ/640?wx_fmt=png&from=appmsg "")  
  
##### 存储型 XSS  
  
  
💥类似这样的留言功能可能会出现xss漏洞。  
  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUyfJibrFuXct36T9fHqkwdic7d4vzbZZZsiarLfYxe138njTPOhctTlFkTjicO4Iiahmw6ENzK9xrMJVQ/640?wx_fmt=png&from=appmsg "")  
  
  
攻击者提交评论内容  
  
```
```  
  
后台将评论存入数据库  
  
```
```  
  
前台渲染  
  
```
```  
  
所有访问该评论的用户都将被攻击。  
  
##### 错误信息中回显用户输入  
  
```
```  
  
攻击者输入  
  
```
```  
  
错误页直接触发脚本执行。  
  
### 漏洞危害  
  
  
在前文介绍 XSS 漏洞攻击面时，已简要提及了一些潜在危害。本节将对这些危害及其具体的利用方式进行更系统、深入的说明。同时，将结合前述攻击面，进一步分析攻击者如何利用这些入口实施实际攻击，从而帮助全面理解 XSS 漏洞的严重性与攻击路径。  
  
##### 窃取用户 Cookie  
  
  
搜索框、评论区等功能常将用户输入回显到页面上，如果未进行 HTML 转义处理，攻击者可注入恶意脚本。具体的漏洞  
  
```
```  
  
用户访问恶意页面后，其 Cookie 信息将被发送给攻击者，进而导致 session 劫持、账号被盗。  
  
##### 钓鱼欺骗  
  
  
用户昵称、签名、自我介绍等内容常常在资料页展示，如果直接输出，攻击者可伪造任意界面或按钮。  
  
```
```  
  
用户误以为是系统提示，主动提交账号密码等信息。  
  
##### 后台攻击  
  
  
攻击者在存储型 XSS 场景中，发布含有恶意脚本的评论内容。当管理员在后台浏览时，脚本将在高权限上下文执行。  
  
```
```  
  
攻击者借助管理员权限操作系统数据，甚至可注入更多脚本实现蠕虫式传播。  
  
##### 页面劫持  
  
  
网站常从 URL 中读取参数动态生成页面内容，如新闻标题、跳转地址等。如果未正确处理，也可能被注入脚本。  
  
```
```  
  
实现页面跳转、加载恶意代码、强制浏览挖矿脚本或其他攻击内容。  
  
  
高交互性诱导操作  
  
  
现代前端框架有时使用服务端渲染，若模板中包含未清洗的变量，会形成 DOM 型 XSS。  
  
```
```  
  
结合 CSRF，可自动完成资金转移、信息更改等敏感操作。  
  
### XSS漏洞攻防  
  
  
本节将介绍常见的 XSS 防御方法及其绕过技巧，内容相对较多，仅对原理感兴趣的读者可选择跳过。  
  
#### 漏洞查找  
  
##### 基本验证  
  
  
将以下代码作为 Fuzz 测试样本，尝试提交到所有可能接收用户输入的地方，如 HTTP 头、URL 参数、前端表单等。  
  
```
```  
  
如果发现攻击字符串原样出现在响应中，则可能存在 XSS 漏洞。  
  
  
许多应用会尝试通过黑名单等简单方式进行初步过滤来阻止 XSS 攻击，但这类防御往往不够严密，可以通过编码或构造变形的方式进行绕过，例如：  
  
```
```  
  
当利用基于 DOM 的 XSS 漏洞时，攻击载荷不会出现在服务器的响应内容中，而是被直接保存在浏览器端的 DOM 结构中，并通过客户端的 JavaScript 脚本进行处理和执行。  
  
  
在这种情况下，以上所提的基本验证方式（如检测响应中是否出现攻击字符串）将无法发现此类 XSS 漏洞。因为漏洞的触发完全发生在客户端执行 JavaScript 的过程中，而非依赖于服务端的返回内容。  
  
##### 反射型 XSS 查找  
  
###### 1.基本的反射型 XSS 测试  
  
  
将以下恶意脚本注入页面的各个参数中，观察是否被反射回页面并执行：  
  
```
```  
  
若字符串原样出现在页面响应中，可能存在反射型 XSS。  
  
###### 2.常见注入位置与方法  
  
  
2.1 标签属性值  
  
  
假设返回页面中有以下内容：  
  
```
```  
  
注入方式：  
  
```
```  
  
2.2 JavaScript 字符串上下文  
  
  
返回内容示例：  
  
```
```  
  
注入方式：  
  
```
```  
  
2.3 URL 属性  
  
  
返回内容：  
  
```
```  
  
注入方式：  
  
```
```  
###### 3.利用常见标签和属性触发脚本执行  
  
  
3.1 无需用户交互的事件属性  
  
```
```  
  
3.2 脚本伪协议注入  
  
```
```  
###### 4.HTML 绕过技巧  
  
  
4.1 标签名绕过  
  
-  大小写混淆：  
<iMg onerror=alert(1) src=a>  
  
-  插入 NULL 字节：  
<%00img onerror=alert(1) src=a>  
  
- 空格替代字符：  
  
```
```  
  
4.2 属性名绕过  
  
```
```  
  
4.3 属性分隔绕过  
  
```
```  
  
4.4 属性值编码绕过  
  
```
```  
  
4.5 可编码属性  
  
- href=  
  
- action=  
  
- formaction=  
  
- location=  
  
- on*=  
  
- name=  
  
- background=  
  
- poster=  
  
- src=  
  
- code=  
  
- data=  
（仅支持 base64）   
  
###### 5.绕过字符集与长度限制  
  
  
5.1 使用非标准编码：  
  
- UTF-7  
  
- US-ASCII  
  
- UTF-16  
  
5.2 拆分跨站脚本（用于绕过长度限制）  
  
```
```  
  
执行结果为：  
  
```
```  
###### 6.JavaScript 层面的绕过技巧  
  
  
6.1 Unicode 编码关键字  
  
```
```  
  
或结合   
eval()  
：  
  
```
```  
  
6.2 替代点操作符   
.  
  
```
```  
##### 存储型XSS查找  
  
  
保存型 XSS 漏洞的检测过程与反射型 XSS 相似，但存在一些关键的区别。在进行测试时，必须牢记这些区别，以确保能够尽可能多地发现漏洞。  
  
###### 提交特殊字符串后进行反复检查  
  
  
提交特殊的恶意字符串后，除了在常规输入位置测试外，还必须反复检查应用程序的每个页面和功能，确保没有遗漏任何潜在的 XSS 漏洞。  
  
###### 检查管理员区域  
  
  
如果应用程序有管理员访问区域，建议特别关注这一部分。确认是否有任何非管理员用户能够控制的数据。如果管理员能够访问并查看日志等，攻击者可能会通过恶意 HTML 脚本注入这些日志中并加以利用。  
  
###### 检查带外通道  
  
  
不仅要关注常规的输入输出路径，还需要检查所有可控的带外通道，如 HTTP 消息头等，确保它们不会成为潜在的 XSS 漏洞入口。  
  
##### DOM型的XSS漏洞查找  
  
  
基于 DOM 的 XSS 漏洞检测不同于反射型和保存型 XSS 漏洞，因为漏洞发生在客户端 JavaScript 中，而不是服务器端。在这种攻击中，恶意脚本会被存储在浏览器的 DOM 中，而非 HTTP 响应中返回。为了检测这种漏洞，以下是一些有效的步骤和工具。  
  
###### 检查客户端 JavaScript 中的危险 DOM API  
  
  
一种有效的检测方法是，检查所有客户端 JavaScript 代码，查看是否使用了任何可能导致 XSS 漏洞的 DOM 属性和 API。可以通过工具   
**DOMTracer**  
 自动执行此测试过程，帮助识别潜在的漏洞。  
  
  
**需要关注的 DOM 属性和 API**  
  
  
以下是一些可能导致漏洞的 DOM 属性和 API，攻击者可以通过这些 API 来访问和操控浏览器中的 DOM 数据：  
  
- document.location  
  
- document.URL  
  
- document.URLUnencoded  
  
- document.referrer  
  
- window.location  
  
在每一个使用这些 API 的地方，仔细检查代码，特别注意如何处理来自用户输入的数据。如果用户能够控制这些数据并将其传递到以上 API 中，则可能导致 XSS 漏洞。  
  
###### 关注危险的 JavaScript 操作  
  
  
以下是一些可以执行恶意脚本的 JavaScript 函数，它们可能被用于动态地将用户可控的数据写入页面或执行代码。需要仔细检查这些 API 和操作的使用：  
  
- document.write()  
  
- document.writeln()  
  
- document.body.innerHTML  
  
- eval()  
  
- window.execScript()  
  
- window.setInterval()  
  
- window.setTimeout()  
  
特别是在这些 API 中，检查是否存在将用户输入的数据直接传递进去的情况，若传递未经验证的用户输入，则可能导致 XSS 漏洞。  
  
###### 注意 URL 中的片段  
  
  
另一个可能的漏洞来源是 URL 中的片段（fragment）。服务器通常不会解析 URL 中   
#  
 后的内容，因此，恶意用户可以在 URL 片段中注入数据，并通过客户端 JavaScript 访问这些数据。如果应用程序错误地处理这些片段数据，就可能导致 XSS 漏洞。  
  
#### 漏洞防御  
  
##### 反射型与存储型 XSS  
  
  
反射型与存储型 XSS 漏洞的根本原因在于用户可控的数据未经适当的验证与净化就被复制到应用程序的响应中。为了防止这类漏洞，应用程序应该采取以下措施：  
  
###### 确认输入  
  
- **数据长度控制**  
：确保输入数据不会过长，限制数据的最大长度。   
  
- **合法字符限制**  
：确保数据仅包含预期的合法字符。例如，用户名只允许字母和数字，电子邮件地址只允许合法的邮箱格式。   
  
- **正则表达式匹配**  
：对输入数据进行正则表达式检查，确保它符合特定的格式。   
  
根据应用程序希望接收的数据类型，可以针对姓名、电子邮件地址、账号等字段，应用不同的确认规则。尽量采取限制性的输入规则，减少可能的攻击面。  
  
###### 确认输出  
  
- **HTML 编码**  
：如果应用程序将用户或第三方提交的数据插入到响应中，必须对这些数据进行 HTML 编码。这样可以确保恶意代码被净化，防止它被当作 HTML 或 JavaScript 代码执行。   
  
###### 消除危险插入点  
  
- **避免直接插入用户数据到 JavaScript**  
：尽量避免在现有的 JavaScript 代码中直接插入用户可控的数据。如果确实需要插入，确保对数据进行严格处理。   
  
- **避免嵌入用户输入到标签属性中**  
：尤其是当标签属性需要 URL 作为值时，避免直接插入用户输入的 URL。   
  
###### 允许有限的 HTML  
  
  
一些应用程序（如博客、论坛的富文本编辑器）允许用户以 HTML 格式提交数据。这种情况下，应用程序应使用专门的框架（如 OWASP AntiSamy 项目）来确认用户提交的 HTML 标记，确保其中不包含任何可能执行 JavaScript 的代码。  
  
##### DOM 的 XSS 漏洞  
  
  
与反射型和存储型 XSS 漏洞不同，基于 DOM 的 XSS 漏洞不需要用户数据出现在服务器的响应中，而是发生在客户端的 JavaScript 代码中。为了防止这种类型的漏洞，以下是一些有效的防护方法：  
  
###### 确认输入  
  
- **客户端验证**  
：确保将要插入到文档中的数据仅包含字母、数字与空白符。可以使用 JavaScript 对输入进行验证，例如：   
  
```
```  
- **服务端验证**  
：对 URL 数据进行严格的确认，包括：   
  
- 查询字符串中只有一个参数。  
  
- 参数名的大小写检查。  
  
- 参数值仅包含字母和数字。  
  
###### 确认输出  
  
- **HTML 编码**  
：在将用户可控的 DOM 数据插入到文档之前，确保进行 HTML 编码，防止恶意脚本执行。例如，使用 PHP 或 JavaScript 对数据进行编码：   
  
```
```  
#### 参考链接  
  
1.  XSS漏洞（全网最详细）  
https://blog.csdn.net/qq_61553520/article/details/130268475  
  
1.  Web 安全头号大敌 XSS 漏洞解决最佳实践  
https://cloud.tencent.com/developer/article/1790802  
  
1.  XSS跨站脚本漏洞  
https://wiki.wgpsec.org/knowledge/web/xss.html  
  
1.  XSS靶场  
http://ctf.aabyss.cn/xss-labs/index.php  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**内部圈子详情介绍**  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```  
  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于800人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQrFWcBesgFeibmAaLTXbl25YKcjTuT0F7X8qBLgI7JaOjU1DxsgxfyicbBDibicKwvIhjia1Jm33NQaA/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满800人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXzIXhsuibSCxH9DL0qbmoy9fgFDcSWC6Yyg3eJsoE70q5jJ1OiaSQYcFsw/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  

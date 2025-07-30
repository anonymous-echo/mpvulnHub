#  【海外SRC赏金挖掘】诺基亚漏洞！！ 403ByPass (三) -- 修改请求方式实现403绕过   
原创 thakor_jd  fkalis   2024-10-04 10:40  
  
# 海外SRC赏金挖掘专栏  
> **在学习SRC，漏洞挖掘，外网打点，渗透测试，攻防打点等的过程中，我很喜欢看一些国外的漏洞报告，总能通过国外的赏金大牛，黑客分享中学习到很多东西，有的是一些新的信息收集方式，又或者是一些骚思路,骚姿势，又或者是苛刻环境的漏洞利用。于是我打算开启这个专栏，将我认为优秀的文章进行翻译，加入我的理解和笔记，方便我自己学习和各位师傅共同进步，我争取做到日更，如果各位师傅觉得有用的话，可以给我点个关注~~ 如果师傅们有什么好的建议也欢迎联系我~~ 感谢各位师傅的支持~~**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7pTY4CibicHmG6uHuL0eiasl9l6xI2MDRZaKhicsPUAdzslV95G055uvHibw/640?wx_fmt=png&from=appmsg "")  
# 正文部分  
> 原文作者：https://medium.com/@thakor_jd  
  
  
## 总结  
> **当遇到403页面的时候，可以尝试修改请求方式，例如将GET修改为POST，****GET修改为TRACE**  
**可能会有奇效，从而实现403Bypass**  
  
  
<table><thead style="line-height: 1.75;background: rgba(0, 0, 0, 0.05);font-weight: bold;color: rgb(63, 63, 63);"><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">序号</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">方法</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">描述</td></tr></thead><tbody><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">1</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">GET</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">从服务器获取资源。用于请求数据而不对数据进行更改。例如，从服务器获取网页、图片等。</span></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">2</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">POST</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">向服务器发送数据以创建新资源。常用于提交表单数据或上传文件。发送的数据包含在请求体中。</span></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">3</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">PUT</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">向服务器发送数据以更新现有资源。如果资源不存在，则创建新的资源。与 POST 不同，PUT 通常是幂等的，即多次执行相同的 PUT 请求不会产生不同的结果。</span></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">4</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">DELETE</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">从服务器删除指定的资源。请求中包含要删除的资源标识符。</span></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">5</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">PATCH</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">对资源进行部分修改。与 PUT 类似，但 PATCH 只更改部分数据而不是替换整个资源。</span></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">6</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">HEAD</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">类似于 GET，但服务器只返回响应的头部，不返回实际数据。用于检查资源的元数据（例如，检查资源是否存在，查看响应的头部信息）。</span></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">7</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">OPTIONS</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">返回服务器支持的 HTTP 方法。用于检查服务器支持哪些请求方法，通常用于跨域资源共享（CORS）的预检请求。</span></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">8</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">TRACE</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">回显服务器收到的请求，主要用于诊断。客户端可以查看请求在服务器中的处理路径。</span></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">9</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">CONNECT</span></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><span style="color: rgb(51, 51, 51);">建立一个到服务器的隧道，通常用于 HTTPS 连接。客户端可以通过该隧道发送加密的数据。</span></td></tr></tbody></table>  
## 漏洞复现  
#### 信息收集  
  
通过子域名收集（amass、sub-finder、asset finder），我发现了一个诺基亚的子域名 https://subs.nokia.com ，但是访问403  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicdbC1TLMicaRBDLfGFwBffT27LlKFEx9z1Bs5CnjzxO1YSdCRxZu8WXjLHvfdRuty9HjUtPyUhBvsQ/640?wx_fmt=other&from=appmsg "null")  
#### 尝试目录扫描和文本注入  
  
我尝试了简单的内容欺骗，如 iFrame 注入/文本注入，就像这样的 https://subs.nokia.com/!!Site-is-an-down-visit-evil.com [或“/>INJECTION]  
 但遗憾的是它没有奏效  
  
然后，我进行了目录扫描，尝试访问 https://subdomain.nokia.com/.htaccess，它给出了 403 错误而不是 404“NOT FOUND”，这意味着 .htaccess 文件存在于此子域中。  
> https://subs.nokia.com /.htaccess  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicdbC1TLMicaRBDLfGFwBffT2oMJgEgjoPq6HFSBVxyjmUzQHIQeqiby0mXTrLzw6NCic4BCaQ4voY4mw/640?wx_fmt=other&from=appmsg "null")  
#### 尝试常规的403bypass方法  
  
有许多不同的方法可用于旁路 403，但首先我使用了一些基本和常见的方法，例如使用 /（斜杠）、/;等 但是运气不好，并没有成功绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicdbC1TLMicaRBDLfGFwBffT2W0kibVVJHzAhTLhRmBdcvibYIIH1VTItx1DMJniaGiazP0icvPICW2XfuJw/640?wx_fmt=other&from=appmsg "null")  
  
此外，您可以自动化该过程，GitHub 上有很多自动化 403 绕过工具可用  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicdbC1TLMicaRBDLfGFwBffT23LibEXykibMFI02icYNObicBNZ0NFHq7F5licwSsNduO2AfxvUiaLkrrPauA/640?wx_fmt=other&from=appmsg "null")  
#### 修改请求方式实现403bypass  
> **更改请求的方法，如 GET → POST、GET → TRACE 等。**  
  
1. 1. 首先使用burp 将请求方法 **GET 更改为 POST ，**但它仍然显示 403  
  
1. 2. 然后我再次将其更改为 **GET → TRACE**，成功绕过，实现403bypass  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicdbC1TLMicaRBDLfGFwBffT2UJhBKr3tO5aUHhEiauY8raZf4sRiapfPxuTaM3BUApBhNshBkMwDGS8Q/640?wx_fmt=other&from=appmsg "null")  
  
# 知识星球  
  
**具体的星球介绍可以看一下这里~~**  
  
[WingBy小密圈，他来了！](https://mp.weixin.qq.com/s?__biz=MzkyODcwOTA4NA==&mid=2247484765&idx=1&sn=01366a5d13fb4be7f9c0e69e565d64ff&chksm=c215e5eef5626cf8c87fcca7d784068772d364a12aa4b4a224aebd1e69bddf52fec0f791d000&token=276602823&lang=zh_CN&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7lPF38IqibU9Az906W6RHJBQhf2OR32Ks7sd8Xh4ric0VFRNR2lXmFwKA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicdCvkAftp00C0F9g6uLYXGnpAWQmOBwrqRUI6V26tvWqFJib6PmZO9fiaY0nia2An9JmtL5mMibqIAH5w/640?wx_fmt=jpeg&from=appmsg "null")  
  
**注意：帮会和星球是为了考虑大家的方便习惯，福利和内容是一致的，后续更新也是一致的~~~只需要进行一次付费就可以啦~~（建议还是使用帮会）**![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicf197vbRopEgYNZjbmJ00wHzicThAsLt7xehsSWC5JKY3NSEMkWbGolb0oSJmLlQlqHTic5bVyFgeBg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
# 项目合作  
  
  
**有甲方大大，或者厂商师傅，或者其他的项目，欢迎咨询，我以及团队始终将客户的需求放在首位，确保客户满意度~~**  
  
****  
**目前主要的服务范围：**  
****  
> **1. 渗透测试、漏洞扫描**  
  
**2. 代码审计**  
  
**3. 红蓝攻防**  
  
**4. 重保以及其他攻防类项目**  
  
**5. 红队武器化开发以及蓝队工具开发**  
  
**6. CTF相关赛事的培训等**  
  
**7. cnvd，cnnvd，edu，cve等证书**  
  
**8. nisp，cisp等证书**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7ZJRQaUkzj4SdzlE2LemzRDG7yrl4rP4cFunhhibibX3CzGEPwFQzqIkw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  

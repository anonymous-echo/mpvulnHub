#  在ChatGPT中挖掘XSS漏洞实现任意账户接管   
 Z2O安全攻防   2025-03-26 20:38  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
#   
# 背景介绍  
  
在本篇文章中，国外安全研究人员Ron将介绍他在ChatGPT中发现的两处XSS漏洞以及其它一些漏洞，如果将它们组合在一起的话，甚至可能导致账户被接管。由于ChatGPT 使用了 NextJS（一种流行的 React 框架），因此研究人员对于寻找 XSS 漏洞一开始是持怀疑态度的，然而，当探索它的功能和客户端代码时，最初的想法开始逐渐改变…  
# 最初发现  
  
ChatGPT 允许用户上传文件并提出针对有关文件的问题，回答时 ChatGPT 可能会引用这些文件，并包含一个可点击的引用图标，让你返回原始文件或网站以供参考。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibiciblRN5MSKKqvPH4rH5gBgMefENcbDmicsn1UyJiakEwPZ0Rd5dUTBVKvg/640?wx_fmt=png&from=appmsg "易受攻击的代码")  
  
上面的代码处理引用了  
点击事件  
，它将文件的内容处理成一个 blob，然后使用window.open  
函数打开它，根据文件内容类型，该方法可能存在安全风险。  
  
研究人员通过上传包含文本和 JavaScript 的 HTML 文件对此进行了测试， ChatGPT 对其进行了处理并提供了引用，当单击引文时，HTML 内容通过 blob URL 显示在了屏幕上，但内容安全策略 (CSP) 阻止了 Payload。  
# CSP 绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibicvkicjy3CQyEicMa6ftjIF8OHK11mBiaW4pUEGxtZF8CiaEzZ4ZH6xyugiaw/640?wx_fmt=png&from=appmsg "ChatGPT CSP 策略")  
  
在研究 CSP 策略时，研究人员注意到本应动态的随机数值却是静态的， nonce 是一个唯一的字符串，可以让特定的 HTML 元素绕过 CSP 限制，通常，该值会随着每个请求而变化，然而，这里却没有改变。  
  
使用另一个帐户和不同的 IP 地址进行测试证实了该问题，然后，研究人员上传了一个新的 HTML 文件，其中的脚本标签包含了这个 nonce 属性，这次，脚本在点击引用后成功被执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibicibfa3WhDtkIooJLt7Q5CjkxV6m94Jq3nu0ZSLPetV88gibibw3boefDpg/640?wx_fmt=png&from=appmsg "")  
# 挑战和限制  
  
利用此漏洞并不简单，它要求用户上传有害文件并以提示 ChatGPT 引用该文件的方式进行操作，然后用户需要点击引用才能触发XSS，研究人员研究了 ChatGPT 的共享对话功能，认为这是使该漏洞可以共享的一种可能方法，研究人员的计划是与目标用户共享对话链接，让他们点击引用，从而触发 XSS！  
  
然而这种方法没有达到预期的效果，在 ChatGPT 对话中上传的文件只能由上传这些文件的帐户访问，尝试从另一个帐户访问这些文件会导致 404 错误。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibicYw9icwHwotia1UpLic9RKQ4106Q2ibJJ8tvaT5iaKBFm0DREyfxYnmmmXjQ/640?wx_fmt=png&from=appmsg "")  
# 新方法  
  
OpenAI 推出的 GPT 附带知识文件，这些文件通过一个 API 运行，该 API 与用户上传文件所用的 API 非常相似，但有一个值得注意的附加功能——“gizmo_id”参数。  
  
通过探索，研究人员发现当GPT设置为公开时，任何帐户都可以访问和下载这些知识文件，只要他们有必要的信息——GPT ID和关联的文件ID。  
  
研究人员认为这可能会是一个功能级别的授权漏洞，因为它允许任何 ChatGPT 用户下载公共 GPT 知识文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibicVica541rj1ur7195YPdLKvQxbia9iaXAnLawP1YNjV7lMverhPqBb9H0w/640?wx_fmt=png&from=appmsg "GPT 文件API")  
  
这就为漏洞利用提供了新的可能性，如果能让共享对话请求的是公共文件，而不是原始上传文件，就能利用 XSS 漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibicvZougLuRAhVLtdrRA8YzTumL0KoTk6vj6BTPU7RZng8szuXicsh0qvQ/640?wx_fmt=png&from=appmsg "对话请求正文")  
  
这个结构与之前创建的共享 ChatGPT 对话的“pageProps”对象中看到的助理元数据很相似。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibicFFsfBl77yELBWbbSFqtvkH460uFYXqno6B7PdOl38D7YUoqsDibOEvw/640?wx_fmt=png&from=appmsg "助手消息元数据")  
  
研究人员在助理消息元数据中看到了引文对象，其中包括上传文件 ID，这与最初讨论的用于获取文件内容的易受攻击的代码所使用的 ID 相同。那么如果可以控制此元数据，就有可能使此漏洞可共享。  
# 尝试角色和大规模分配  
  
研究人员首先尝试将对话中的角色从“用户”更改为“助手”，令人惊讶的是，ChatGPT 接受了这一更改并继续生成响应，接下来，研究人员尝试调整元数据以匹配在“pageProps”对象中看到的引用结构，此方法同样有效，表明存在“批量分配”漏洞。  
  
当应用程序不加区别地将用户提供的数据分配给内部对象或变量时，就会出现批量分配漏洞，如果应用程序没有正确过滤或限制可以分配的数据，则可能会发生这种情况。  
  
在这种情况下，便可以使用输入数据来操作 ChatGPT 应用程序的各个方面（特别是引文元数据），而这些方式通常对普通用户来说是禁止的。  
# 漏洞利用  
  
首先向“/backend-api/conversation”端点创建了一个新请求，模拟助手并注入自定义引用对象，需要将文件 ID 设置为“file-Cbn7djQD1W20s3h5JM8NfFs8/download?gizmo_id=g-ghPiYIKcD#”，强制 ChatGPT 客户端使用 GPT API。  
  
然后创建并共享了一个对话，当使用另一个 ChatGPT 帐户进行测试时，单击对话中的任何引用都会从公共 GPT 中下载知识文件，从而触发了 XSS。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibicQR0lnohR0VSSKQsPsR2XicVyicbkqdh0NGr6xIZicMbAWQfcus5vjAjag/640?wx_fmt=png&from=appmsg "")  
  
研究人员第一时间向 OpenAI 报告了该漏洞，他们的回应是删除 blob 创建并更改逻辑以直接打开下载 URL。漏洞修复后，研究人员检查了涉及“context_connector”、“元数据”和“download_url”的附加功能，发现这些组件没有出现任何新的漏洞，因为对话元数据无法直接控制这些值。  
# 另一个XSS漏洞  
  
研究人员通过检查与 ChatGPT 如何处理网站引用呈现相关的其他功能时，注意到了以下代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibicibC06j84TbR2ibPVAZPpRrxystoN6PaZm22YT4WFAjlDGWoYCMiaWDJwA/640?wx_fmt=png&from=appmsg "")  
  
在检查代码时，注意到引文元数据对象（在代码中引用为“em”）直接用于设置引文链接的“href”属性（即“em.url”），这是一个危险信号，因为可以通过冒充助手来操纵元数据。  
# 初步尝试和新的挑战  
  
为了测试该漏洞，研究人员建立了一个新对话，在此设置中，研究人员操作了引文元数据，将其 URL 值设置为 JavaScript 协议 URL，例如javascript:alert(1)  
，然而，利用并未成功。  
  
虽然成功地将锚标记的 href  
 属性设置为 JavaScript URL，但该标记还包含一个 target=”_blank”  
 属性，此属性只能使用键盘快捷键来利用。  
  
在PoC中，研究人员将共享的 ChatGPT 对话嵌入到“iframe”中，并使用 CSS 对其进行定位，以便任何点击都会无意中触发引用链接，为了使 iframe 不可见，还需将不透明度设置为零。  
  
在这个不可见的 iframe 上，研究人员添加了“  
按住 ⌘ 并单击以在新选项卡中打开我  
”的文本描述，遵循这些说明的用户会在不知情的情况下在 chat.openai.com 上执行任意 JavaScript。  
# SameSite Cookie 与存储分区  
  
另一个障碍涉及 SameSite cookie 和存储分区，这是一种旨在通过限制浏览器跨不同来源管理 cookie 和其他类型存储的方式来保护网络隐私和安全的安全措施。  
  
在上面的场景中，当用户访问嵌入了链接到 ChatGPT 共享对话的 iframe 的恶意网站时，这些措施将阻止对 ChatGPT 会话 cookie 和 LocalStorage 的访问，从而有效地将他们从 iframe 中的帐户注销。  
  
这些安全功能旨在防止跨站点请求伪造 (CSRF) 攻击和各种形式的侧信道跨站点跟踪攻击，例如定时攻击、XS 泄漏和跨源状态推断 (COSI) 攻击。值得注意的是，这些措施的威胁模型不包括跨站点脚本（XSS），这是我们在这种情况下利用的漏洞。  
  
通过创建包含 HTML 内容的 Blob 对象并使用 chat.openai.com 上下文中的 URL.createObjectURL 方法为其生成 URL，研究人员便能够将父窗口导航到此 Blob URL。  
  
这就成功绕过了 SameSite cookie 限制和存储分区，因为从 chat.openai.com 内部发起的导航被视为同源请求，因此不受典型的跨源限制，  
# 任意账户接管  
  
![image-20240223105609942]()  
# Payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibicJEH1rlPP9MRdSiaNMDXjEGgGrMbuEr2yRGZK3XcjDjupl8sibBEH67qw/640?wx_fmt=png&from=appmsg "")  
# OpenAI的修复  
  
发现这些漏洞后，研究人员立即与 OpenAI 分享了PoC，他们的响应速度非常快，通过添加引用 URL 的客户端验证，在几个小时内便修复了 XSS 问题。  
  
你可以看到在渲染引文链接时添加并使用了“eF”方法，验证了只能使用“https”、“mailto”和“tel”协议。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jk0aSsZ6ZQlQ8b2UY1ibmeibic9RXhSKiauRGxVnrVUQfIkast8bY4fceJ3HfuICNNEQJGr6uKHEsZghg/640?wx_fmt=png&from=appmsg "")  
  
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
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuaOib1oRicRQ1dYx14RnT9uhEjFceecKIiclqyoqH5LapbCL4T3KucgeHFqMjicR3es1gice8e3fdCQMIQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  

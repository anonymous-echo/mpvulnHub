#  Ollama AI模型发现六大漏洞，能导致DoS攻击、模型中毒   
 信息安全大事件   2024-11-06 19:51  
  
据The Hacker News消息，网络安全研究人员披露了 Ollama 人工智能模型中的六个安全漏洞，攻击者可能会利用这些漏洞执行各种操作。  
  
Ollama 是一个开源应用程序，允许用户在 Windows、Linux 和 macOS 设备上本地部署和操作大型语言模型 （LLM）。迄今为止，该模型在 GitHub 上的项目存储库已被分叉 7600 次。  
  
研究员在一份报告中指出，这些漏洞可能允许攻击者通过单个   
HTTP 请求执行广泛的恶意操作，包括拒绝服务 （DoS） 攻击、模型中毒、模型盗窃等。  
  
这   
6 个漏洞的简要描述如下:  
- CVE-2024-39719（CVSS 评分：7.5）：攻击者可以使用 /api/create 端点利用该漏洞来确定服务器中是否存在文件（已在版本 0.1.47 中修复）  
  
- CVE-2024-39720（CVSS 评分：8.2）：越界读取漏洞，可通过 /api/create 端点导致应用程序崩溃，从而导致 DoS 情况（已在 0.1.46 版本中修复）  
  
- CVE-2024-39721（CVSS 分数：7.5）：在将文件“/dev/random”作为输入传递时，重复调用 /api/create 端点时，会导致资源耗尽并最终导致 DoS 的漏洞（已在 0.1.34 版本中修复）  
  
- CVE-2024-39722（CVSS 分数：7.5） ：api/push 端点中的路径遍历漏洞，暴露了服务器上存在的文件以及部署 Ollama 的整个目录结构（已在 0.1.46 版本修复）  
  
- 无   
CVE 标识符，未修补 漏洞：可通过来自不受信任的来源的 /api/pull 终端节点导致模型中毒  
  
- 无   
CVE 标识符，未修补 漏洞：可能导致通过 /api/push 终端节点向不受信任的目标进行模型盗窃  
  
对于上述两个未解决的漏洞，Ollama 的维护者建议用户通过代理或 Web 应用程序防火墙过滤哪些端点暴露在了互联网上。  
  
研究人员称，发现了   
9831 个运行 Ollama 面向互联网的独特实例，其中大多数位于美国、中国、德国、韩国、中国台湾、法国、英国、印度、新加坡和中国香港。其中有四分之一的服务器被认为容易受到这些漏洞的影响。  
  
另外，云安全公司Wiz在四个多月前披露了一个影响Ollama的严重漏洞（CVE-2024-37032），该漏洞可被利用来实现远程代码执行。  
  
研究人员表示，因为Ollama 可以上传文件，并具有模型拉取和推送功能，因此将未经授权的Ollama暴露在互联网上，就相当于将Docker套接字暴露在公共互联网上，从而容易被攻击者利用。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006286" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  

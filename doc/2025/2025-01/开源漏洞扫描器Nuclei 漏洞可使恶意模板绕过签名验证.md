#  开源漏洞扫描器Nuclei 漏洞可使恶意模板绕过签名验证   
Rhinoer  犀牛安全   2025-01-17 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlOwnRTS97ZzG5EC7PzumDZpcckk4bf9Z5NFYaqGecyXDs2lwrUt6iaRkfXM39kODkd6yOibxN6d79w/640?wx_fmt=png&from=appmsg "")  
  
开源漏洞扫描器 Nuclei 中现已修复的一个漏洞可能允许攻击者绕过签名验证，同时将恶意代码潜入在本地系统上执行的模板中。  
  
Nuclei 是由 ProjectDiscovery 创建的流行开源漏洞扫描程序，可以扫描网站中的漏洞和其他弱点。  
  
该项目采用基于模板的扫描系统，该系统包含超过 10,000 个 YAML 模板，可扫描网站中已知的漏洞、错误配置、暴露的配置文件、Webshell 和后门。  
  
YAML 模板还包括一个 代码协议，可用于在扩展模板功能的设备上本地执行命令或脚本。  
  
每个模板都用摘要哈希“签名”，Nuclei 使用该摘要哈希来验证模板未被修改以包含恶意代码。  
  
该摘要哈希以以下形式添加到模板的底部：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlOwnRTS97ZzG5EC7PzumDZj3t94hclgXtzS4rC4ibnibHoHVAlWl6beU5zn0f0ss3Eibya9qu7Koib6w/640?wx_fmt=png&from=appmsg "")  
  
漏洞可绕过 Nuclei 签名验证  
  
Wiz 的研究人员发现了一个新的Nuclei漏洞，编号为 CVE-2024-43405 ，即使模板被修改以包含恶意代码，该漏洞也可以绕过 Nuclei 的签名验证。  
  
该缺陷是由基于 Go 正则表达式的签名验证以及 YAML 解析器在验证签名时处理换行符的方式引起的。  
  
在验证签名时，Go 的验证逻辑将其视为\r同一行的一部分。但是，YAML 解析器将其解释为换行符。这种不匹配允许攻击者注入绕过验证但在 YAML 解析器处理时仍会执行的恶意内容。  
  
另一个问题是 Nuclei 如何处理多个# digest:签名行，因为该过程仅检查模板中第一次出现的#digest：，而忽略模板中稍后发现的任何其他签名行。  
  
可以通过在初始有效摘要之后添加包含恶意“代码”部分的其他恶意“#digest：”有效负载来利用此漏洞，然后在使用模板时注入并执行该代码部分。  
  
Wiz 研究员 Guy Goldenberg 解释道：“利用对不匹配的换行符解释的了解，我们制作了一个模板，利用 Go 的正则表达式实现和 YAML 解析器之间的差异。”  
  
“通过使用 \r 作为换行符，我们可以在模板中包含第二个 #digest: 行，以逃避签名验证过程，但会被 YAML 解释器解析和执行。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlOwnRTS97ZzG5EC7PzumDZc7ibGbWIWyOTp6SNGLduRBYct4omRsBLIN91kPEUYQVDy81gsE5dmHg/640?wx_fmt=png&from=appmsg "")  
  
Wiz 于 2024 年 8 月 14 日负责任地向 ProjectDiscovery 披露了该漏洞，并于 9 月 4 日在 Nuclei v3.3.2 中修复了该漏洞。  
  
如果您正在使用旧版本的 Nuclei，强烈建议您更新到最新版本，因为该错误的技术细节已公开披露。  
  
Goldenberg 还建议在虚拟机或隔离环境中使用 Nuclei，以防止恶意模板的潜在攻击。  
  
  
信息来源 ：  
BleepingComputer  
  

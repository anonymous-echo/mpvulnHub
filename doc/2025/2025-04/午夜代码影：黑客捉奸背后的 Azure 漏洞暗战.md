#  午夜代码影：黑客捉奸背后的 Azure 漏洞暗战   
勤奋的运营姐姐  EnhancerSec   2025-04-11 07:39  
  
## 前因  
  
凌晨两点，私家侦探林默的电脑屏幕在昏暗的房间里泛着幽幽蓝光。他盯着客户发来的信息，嘴角勾起一丝冷笑，“三天内，拿到我丈夫和那个女人的聊天记录，钱不是问题。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGiaegtmMk7glF8I6ws1iaFD4h949iatCeXKQichsqmtyhcariaAD4cBXsufQ/640?wx_fmt=jpeg&from=appmsg "")  
  
客户的丈夫是某知名社交平台“蜜语“的CTO，而平台最近刚迁移到Azure云，采用了一套自动化CI/CD流水线——这正是林默的突破口。  
## 漏洞浮出水面  
  
三天前，林默在暗网论坛偶然刷到一篇帖子，大概内容如下：  
  
“Azure DevOps Pipelines通过代码化模板定义CI/CD流程，整合密钥管理、构建部署等任务模块，提升部署效率。其核心安全风险在于：若攻击者控制Pipelines，可利用变量/参数注入漏洞，向运行器注入Shell命令，劫持构建环境并窃取全生命周期凭据。由于默认权限宽松，普通用户可编辑变量组，同名变量会覆盖模板硬编码值，加剧命令注入风险。若运行器未按环境隔离权限，单一代理机可能持有开发、测试、生产环境的“神级”凭据，导致漏洞影响呈指数级扩散——攻击者可横向渗透云环境、第三方服务，甚至篡改生产数据。此漏洞同时威胁云托管和自托管运行器，是OWASP CI/CD安全Top10中的高危场景。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGXv8APJFe7xDKQCwibSQTIbZ9dfZXjsbyyRylbqrMCnEibibJV4ibl4uCjw/640?wx_fmt=jpeg&from=appmsg "")  
  
并且帖子还详细描述了如何通过篡改流水线的运行时参数，将恶意命令注入构建脚本，从而控制Azure构建代理机。  
  
“这不就是蜜语平台用的那套系统？”林默心跳加速。  
## 代码中的致命陷阱  
  
他连夜对平台发起攻击，并且写下了漏洞原理和攻破过程：  
### pipelines 示例  
  
其中包括来自运⾏时参数、变量组和硬编码模板变量的输⼊，这些变量将用于以下示例  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGgAPa8jzDibNrHMdZJvoFSrl3Q7OlK4wu7ZM1m4QLDFVAiaYfmJCMrVuw/640?wx_fmt=png&from=appmsg "")  
### 运行时参数命令注入  
  
如果用户有权运⾏在管道脚本或 Azure CLI 任务内联脚本中定义和使 用运⾏时用户控制的字符串参数的管道，那么这些参数可用于注⼊在构建运⾏器上执⾏的脚本。以下屏幕截图显示了通过运⾏时参数执⾏的命令注⼊的示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGyWHgq2RQSpnu227B9VLJZAylIURpEkkHtVEqvKJxdg6yhxYqtvfeOw/640?wx_fmt=png&from=appmsg "")  
以下运⾏器日志显示了运⾏器上的结果命令执⾏：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGuafrOR3Skzf9ib2XuxrmQkTG25QRYia5JLlC9kucHcFictIXNHbXU0Dxw/640?wx_fmt=png&from=appmsg "")  
### 变量组变量命令注入  
  
如果用户有权使用 Pipelines 脚本或 Azure CLI 任务内联脚本中使用的任何变量编辑变量组，那么变量组可用于注⼊在构建运⾏器上执⾏的脚本。要么可以编辑现有变量，要么可以创建⼀个与模板中硬编码的 相同名称的新变量。 以下屏幕截图显示了通过变量组执⾏的命令注⼊的示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGPuh7naicagL8ibiczRZBibRW8Cybkr7JhuZjpU1ozyn4gedak6PLCwrb9g/640?wx_fmt=png&from=appmsg "")  
以下运⾏器日志显示了运⾏器上的结果命令执⾏：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGb9un1DtWQogVTekNHPiaiaMe4sibrse3Xo7DhaB70ZOWgvNSNhZDSYmKw/640?wx_fmt=png&from=appmsg "")  
### 实例  
  
以下输出是通过换⾏有效负载作为运⾏时参数来实现的。我们让Pipelines 运⾏env 命令 ，输出当前环境变量  
```
'this is newline escaping via the API'\nenv
```  
  
然后将此请求发送到 Azure DevOps API，该 API 运行管道并给出如下所示的输出。  
```
POST                         /...redacted.../ebc7628f-3f9b-4e4b-b460- ca00c225cc11/_apis/pipelines/5/runs HTTP/2Host: dev.azure.comCookie: ...redacted... Content-Length: 187...ommitted for brevity...{"stagesToSkip":[],"resources":{"repositories":{"self":{"refName":"re fs/heads/main"}}},"templateParameters":{"testParameter":"'this     is newline escaping via theAPI'\nenv"},"variables":{}}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGBuLIZuvRia0wZgPGSQibgh7HuJpK1gA1VvwG8xVVdOPXCeqoLTevpbNg/640?wx_fmt=png&from=appmsg "")  
### 漏洞根本原因  
  
未验证的用户变量直接注入脚本，低权限攻击者通过Azure DevOps执行恶意命令，窃取凭据、源码及云环境密钥。  
  
在自托管的运⾏器中，管道变量替换在函数中进⾏，在Agent.Worker.dll 中，其中变量直接在脚本中替换。在将变量或参数替换为脚本时，服务器和运⾏器都不会实现任何形式的危险字符过滤，这使得这种攻击成为可能。  
  
执⾏变量 替换的字符串 值随后被加载 到 INPUT_SCRIPT 环境变量中，并执⾏ Node.JS 任务运⾏器：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGZG85NfEVhBzJOaciaeHjEGlGSOMhnlA5yjnOzVMc15oXwicIj3AMb24w/640?wx_fmt=png&from=appmsg "")  
在⽅法输⼊时，输⼊⽂本包含原始脚本数据：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRG1I9Fhaiay58bhJGKJ6UGnhfN34sAygIFm1jIGzMkAUVCmAYHib2CXWGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRG1Zlvw6xH3dcAnJKEGER0hWicO7wAFUpsHy9BJX9VTRnZ2Tq8SVT57xw/640?wx_fmt=png&from=appmsg "")  
⽅法返回后，输⼊的参数被替换为各自的值：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGofiboXzxOHCwxccbxU5FNlAZtQib7QvDWnkuwJmibtQyANgndVibZic1ialw/640?wx_fmt=png&from=appmsg "")  
一小时后，林默轻松登录蜜语后台，导出了目标人物的私密聊天记录。  
  
然而，屏幕上的内容让他瞳孔骤缩——聊天记录里不仅有出轨证据，还涉及平台用户数据的非法交易。客户丈夫的“情人”，竟是竞争对手公司的商业间谍。  
## 良心抉择  
  
林默将证据匿名发送给客户，同时把漏洞详情提交给了微软安全响应中心。当晚，“蜜语平台惊天数据泄露！CTO出轨牵出黑产链”的标题冲上热搜。  
  
但林默删除了暗网上的漏洞利用教程。他望着窗外渐亮的天色，低声自语：“代码能杀人，也能救人……这一次，我选后者。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGSIGl8TW2ZgEsveW6F3hKmVvHGR1AtZLicoibj8Yxe7R1YiasjRRjheHMw/640?wx_fmt=jpeg&from=appmsg "")  
  
“在数字世界的暗面，每一行代码都可能成为子弹。” —— 林默的加密日记，2025年某夜。  
## 想要了解更多？快来加入我们吧！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DLnxHnM3icnL6MRrMvEic6WptI2K0sLLRGDhUf8IsibX9IBQ9tGdg1UbUjPu03ic04K5cKOnt69icAoPQpgQOCLFiaTQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  

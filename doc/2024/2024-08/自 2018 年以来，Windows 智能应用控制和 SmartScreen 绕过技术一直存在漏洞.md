#  自 2018 年以来，Windows 智能应用控制和 SmartScreen 绕过技术一直存在漏洞   
 网络安全应急技术国家工程中心   2024-08-13 15:21  
  
智能应用程序控制是一种基于信誉的安全功能，它使用 Microsoft 的应用程序智能服务进行安全预测，并使用 Windows 的代码完整性功能来识别和阻止不受信任（未签名）或潜在危险的二进制文件和应用程序。  
  
它取代了 Windows 11 中的 SmartScreen，后者是 Windows 8 中引入的一项类似功能，旨在防止潜在的恶意内容（未启用智能应用控制时，SmartScreen 将接管）。  
  
当用户尝试打开标有 Web 标记 (MotW) 标签的文件时，这两个功能都会被激活。  
  
Elastic Security Labs 发现，Windows 智能应用控制和 SmartScreen 中存在设计缺陷，处理 LNK 文件时存在一个漏洞（称为 LNK 踩踏），该漏洞使攻击者能够启动程序而不会触发安全警告，可以帮助威胁者绕过旨在阻止不受信任的应用程序的智能应用程序控制安全控制。该缺陷至少自 2018 年以来就一直受到利用。  
  
LNK 破坏涉及创建具有非标准目标路径或内部结构的 LNK 文件。当用户点击此类文件时，explorer.exe 会自动修改 LNK 文件以使用正确的规范格式。  
  
但是，这也会从下载的文件中删除 MotW（Web 标记）标签，Windows 安全功能使用该标签来触发安全检查。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ich98LA1IDzRMwoZMWmJN6Td5922qTWYiazic1DPAhPf7zeRAibmjhGiauIgV74fibia3nQ6OxRGTCbXysA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
打开下载的文件时发出警告  
  
为了利用此设计缺陷，可以在目标可执行文件路径后附加一个点或空格（例如，在二进制文件的扩展名“powershell.exe”之后），或者创建包含相对路径的 LNK 文件，例如“\target.exe”。  
  
当用户单击链接时，Windows 资源管理器将查找并识别匹配的 .exe 名称，更正完整路径，通过更新磁盘上的文件删除 MotW，然后启动可执行文件。  
  
Elastic Security Labs 认为，这一弱点多年来一直被滥用，因为它在 VirusTotal 中发现了多个旨在利用该弱点的样本，其中最早的样本是在六年多前提交的。  
  
它还与微软安全响应中心分享了这些发现，该中心表示该问题“可能会在未来的 Windows 更新中得到修复”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/wpkib3J60o2ich98LA1IDzRMwoZMWmJN6TicDnic8dU95c7UtvicptREDHvUfhr7dmwpmRSichENJicevpMnWJichDnUtg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
智能应用控制 LNK 踩踏演示  
  
Elastic 安全实验室还描述了攻击者可以利用来绕过智能应用控制和 SmartScreen 的其他弱点，包括：  
  
·签名恶意软件：使用代码签名或扩展验证 (EV) 签名证书对恶意负载进行签名。  
  
·声誉劫持：查找并重新利用声誉良好的应用程序来绕过系统。  
  
·声誉植入：将攻击者控制的二进制文件部署到系统上（例如，具有已知漏洞的应用程序或仅在满足某些条件时触发的恶意代码）。  
  
·声誉篡改：在二进制文件中注入恶意代码而不会失去相关声誉。  
  
Elastic Security Labs 认为 Smart App Control 和 SmartScreen 存在一些基本的设计缺陷，可能导致初始访问时没有安全警告，且用户交互最少。  
  
安全团队应在其检测堆栈中仔细审查下载，而不能仅依赖操作系统原生的安全功能来保护这一领域。目前，Elastic Security Labs 研究员已发布用于检查文件智能应用控制信任级别的开源工具。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/microsoft/windows-smart-app-control-smartscreen-bypass-exploited-since-2018/  
  
  
  
原文来源  
：嘶吼专业版  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

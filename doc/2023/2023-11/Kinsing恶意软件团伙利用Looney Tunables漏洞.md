#  Kinsing恶意软件团伙利用Looney Tunables漏洞   
布加迪  嘶吼专业版   2023-11-09 12:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
Aqua Nautilus的研究人员近日成功拦截了Kinsing入侵云环境的试验性活动。利用一种基本但很典型的PHPUnit漏洞利用攻击（Kinsing活动的一个部分），我们发现了这伙威胁分子手动操纵Looney Tunables漏洞（CVE-2023-4911）的事实。据我们所知，这是正式记录的首起此类漏洞攻击。有意思的是，攻击者还通过从云服务提供商（CSP）提取凭据来扩大云原生攻击的范围。我们在这篇博文中将深入探讨Kinsing活动及其运作，着重介绍这起攻击的新奇之处，并强调面对这些不断演变的威胁，保持警惕和提高意识的重要性。  
# Kinsing威胁分子：简要概述  
  
Kinsing威胁分子对云原生环境构成了重大威胁，尤其是Kubernetes集群、docker API、Redis服务器和Jenkins服务器等环境。他们能够快速适应新漏洞，并不断竭力利用错误配置，因此成为一个强大的对手。这伙威胁分子一直积极参与加密货币劫持活动。Aqua Nautilus的研究人员及其他网络安全专家一直在跟踪他们的活动，以了解其战术、技术和程序（TTP）。  
  
Kinsing向来以容器化环境为攻击目标。众所周知，他们利用错误配置的敞开的Docker守护程序API端口，并利用新披露的漏洞来部署加密货币挖掘软件。其活动的特点是能够灵活地适应新漏洞，并不断竭力利用云原生环境。  
  
最近，Kinsing被发现利用易受攻击的Openfire服务器。这实际上是Kinsing的一种强大的作案手法，即迅速将新发现的漏洞添加到武器库中。此外，微软Defender for Cloud报告，由于PostgreSQL服务器的错误配置和其他四种易受攻击的容器镜像（PHPUnit、Weblogic、Liferay和Wordpress），大量集群受到了感染。  
  
这伙威胁分子被发现利用rootkit隐藏其在受感染系统中的行踪，主动终止和卸载相互竞争的资源密集型服务和进程，以最大限度地提高挖矿效率。他们最近的活动还涉及扫描敞开的默认WebLogic端口，以执行shell命令并启动恶意软件。  
  
是什么让我们把这种行为归因于Kinsing？目前我们完全确定这是Kinsing所为，但还没有准备好透露具体情况。在一份专门针对Kinsing的报告中，我们打算揭开背后的谜团。本文提供全面的分析，展示使我们能够最终将这次攻击与Kinsing威胁分子联系起来的方法和证据。  
# 最新的攻击被拦截  
  
Kinsing威胁分子一向利用PHPUnit漏洞（CVE-2017-9841），这是一种记载完备的手法。Kinsing通常进行完全自动化的攻击，以挖掘加密货币为主要目标。然而我们最近观察到Kinsing进行手工测试，这与其惯用的作案手法有所不同。  
  
这些测试旨在探测Looney Tunables漏洞（CVE-2023-4911），为我们提供了得以了解其活动的宝贵信息。下面我们深入探讨这个话题，揭示Kinsing扩大自动化攻击范围的险恶意图，特别是针对云原生环境。这一重大转变标志着他们的手法有了重大变化，强调了企业需要提高警惕，并采取强有力的安全措施。  
# 攻击流  
  
初始访问是利用PHPUnit漏洞（CVE-2017-9841）进行的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3LycwticEHQpOQej9wNmZgCgho3F1icrPft22vjP9CDWfjDpB3HcNkat5W5w/640?wx_fmt=png&from=appmsg "")  
  
图1. 我们的一个蜜罐记录下了利用PHPUnit漏洞的活动。  
  
如上面图1所示，Kinsing下载并运行Perl脚本bc.pl。这实际上是下面图2中的脚本，它在端口1337上打开了反向shell。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3LycH9KsnCBoLJnmq7gxibVdsbYeVDbaNK9icrTKRyMcxblPyMY28N6iadDJw/640?wx_fmt=png&from=appmsg "")  
  
图2. 创建连接到Kinsing的C2服务器的反向shell的初始载荷。  
  
下面图3显示了Kinsing威胁分子执行的手工编写和测试的shell命令。值得一提的是，获得这些命令的过程涉及大量试错，为了清楚起见，该截图只保留了相关命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3LycovMfOxzwSxpib4CiadNQbkZEtHib5ibkuJ0zHcBQ4gahgC5WxnbmQXtEjw/640?wx_fmt=png&from=appmsg "")  
  
图3. 由Kinsing威胁分子手动编写的shell命令。  
  
下面是针对手动命令的进一步解释：  
  
1. 使用' uname -a '命令获取内核名称和主机名。  
  
2. 使用' passwd '命令获取用户帐户信息。  
  
3. 启动一个新的交互式shell会话。' -i '标志确保shell是交互式的，这意味着它可以接收和执行来自用户的命令。该命令失效，威胁分子在试图获得系统的root权限。  
  
4. 在' /tmp '下创建目录。  
  
5. 下载脚本gnu-acme.py，它实际上是利用Looney Tunables漏洞（CVE-2023-4911）的代码，下面会作进一步解释。  
  
6. 试图列出环境变量。  
  
7. 下载并运行用于部署JS文件的php脚本。  
  
Looney Tunables是一个存在于GNU C库（glibc）中的高危漏洞，专门针对其动态加载程序ld.so。由于可能提升本地权限，这个漏洞（编号为CVE-2023-4911）无异于一颗定时炸弹，允许攻击者获得受影响系统的root访问权限。问题的关键在于ld.so处理 GLIBC_TUNABLES 环境变量时的缓冲区溢出问题。  
  
在这起特殊的攻击中，Kinsing直接从@bl4sty网站检索漏洞利用代码。@bl4sty在其网站上解释，该漏洞利用代码是Linux本地权限升级漏洞利用代码，针对GNU libc的ld.so中发现的Looney Tunables漏洞（CVE-2023-4911）。  
  
他进一步澄清，该漏洞利用代码基于Qualys文章中详细介绍的利用方法，声称它与x86(_64)和aarch64架构兼容，并强调了通过添加新的目标偏移量来扩展潜力。这个脚本可以在此（https://haxx.in/files/gnu-acme.py）查看。  
  
随后，Kinsing获取并执行额外的PHP漏洞利用代码。最初，该漏洞利用代码被混淆处理。然而一旦去混淆，它原来是为进一步利用的活动而设计的JavaScript。图4和图5分别阐明了这两个脚本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3LycPvcYJukDOPCCvWyEDbcvYZTV8obqkEicOvxbAUeXrLR18Q6bMJSib8IA/640?wx_fmt=png&from=appmsg "")  
  
图4. 混淆处理的PHP脚本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3Lyc2fm6ZtQDkoqld8bdAXRw5icwTyFXTiaULACYVeUKVUTvBesPUhJa2FdQ/640?wx_fmt=png&from=appmsg "")  
  
图5. 去混淆的PHP脚本，以下载后门。  
  
wesobbase.js脚本被编码（base64），解码后发现该文件似乎结合了PHP和JavaScript代码，创建一个web shell后门，以便进一步未经授权访问服务器。以下是一些主要功能：  
  
1. 密码保护：脚本含有密码机制以限制访问。  
  
2. 文件管理：有列出文件、编辑文件及其他文件相关操作的功能。  
  
3. 命令执行：脚本允许在服务器上执行任意命令。  
  
4. 网络交互：有发出网络请求、绑定到端口和反向连接到远程服务器的功能。  
  
5. 加密和解密：有对加密和解密功能的引用，表明脚本可能处理敏感数据。  
  
6. 服务器信息：脚本收集并显示其所运行的服务器的信息。  
  
7. 用户代理处理：脚本检查发出请求的客户端的用户代理。  
  
8. 字符集转换：有处理字符集转换的功能。  
  
最后，Kinsing显然试图列举与云服务提供商（CSP）相关的详细信息和凭据。如下面图6所示，Kinsing试图获取AWS实例身份，这可能导致与实例元数据服务相关的凭据暴露，比如http://169.254.169.254/latest/latest/dynamic/instance-identity/document处可用的凭据，这非常危险，特别是在云环境中。可能暴露的凭据和敏感数据包括以下几种类型：  
  
1. 临时安全凭据：这些凭据由AWS安全令牌服务（STS）提供，运行在实例上的应用程序使用它们对AWS服务执行操作。它们本质上是临时的，但如果关联的角色拥有宽泛的权限，则可以提供对AWS资源的全面访问。  
  
2. IAM角色凭据：如果EC2实例被赋予了IAM角色，可以通过元数据服务访问该角色的凭据。这些凭据用于向实例及其上运行的任何应用程序授予与其他AWS服务交互的权限。  
  
3. 实例身份令牌：这些令牌用于在与AWS服务交互和API请求签名时证明实例的身份。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3Lycw6JwccxPJqY07DW4CDGVbV4iaZiauibm1Wh4ibABWHal1plcrVfHHQgoBA/640?wx_fmt=png&from=appmsg "")  
  
图6. 试图收集AWS元数据。  
  
据我们所知，这是Kinsing第一次试图收集这类信息。此前，他们主要专注于传播恶意软件和运行加密货币挖矿软件，常常试图通过消除竞争或逃避检测来增加得逞的机会。然而这个新的举动表明，Kinsing可能计划在不久的将来开展更多样化更猛烈的活动，这可能意味着云端运行的系统和服务面临更大的风险。  
  
将恶意活动与MITRE ATT&CK框架对应起来  
  
我们的调查显示，攻击者在整个攻击过程中一直在使用一些常见的技术。然而，防御规避策略已经发生了演变：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3LycMOkMCoTUL5PAdLRHn3kq5KEXXEiafsC7dgMkfZaB0iaaobZPwaEEdovQ/640?wx_fmt=png&from=appmsg "")  
# 摘要、检测和缓解  
  
Aqua Nautilus研究团队拦截并分析了Kinsing威胁分子针对云环境的新的试验性活动。Kinsing以其在利用云原生环境的漏洞和错误配置方面的敏捷性而出名，在这次活动中改变了手法。他们手动利用了GNU libc的ld.so中的Looney Tunables漏洞（CVE-2023-4911），这是首起利用此类漏洞的情况。此外，Kinsing试图从云服务提供商（CSP）收集凭据以扩大覆盖范围，这表明他们的活动范围可能在扩大，对云原生环境的威胁随之增加。  
  
漏洞修补：确保所有系统都是最新版本，并打上补丁，特别要关注PHPUnit（CVE-2017-9841）和Looney Tunables（CVE-2023-4911）等已知漏洞。  
  
我们Aqua Security强调扫描容器镜像的重要性，以识别和缓解可能被Kinsing等威胁分子利用的漏洞。如果使用CNAPP平台，组织可以主动检测容器镜像中的已知漏洞。这个过程对于确保所有已部署的容器都是安全的、没有可利用的漏洞至关重要。  
  
Aqua Security建议彻底检查授权和身份验证策略，根据最小特权原则进行调整。此外，熟悉使用中的镜像非常重要，确保为它们配置了最小特权，并尽可能避免使用root用户和特权模式。如果实施这些做法，组织可以显著减小攻击面，并保护云原生环境免受Kinsing之类的威胁。  
  
监视和检测：增强监视功能，以检测异常活动，比如命令手动执行、试图访问或列举CSP凭据的活动，以及已知恶意脚本的执行。  
  
虽然漏洞扫描是一项必不可少的预防措施，但Aqua Security还强调了运行时保护的重要性，以防御可能绕过初始安全措施的复杂攻击。  
  
云原生检测和响应（CNDR）解决方案在这方面发挥着关键作用，提供了实时监控和检测云环境中恶意活动的功能。通过持续分析运行中容器和应用程序的行为，CNDR解决方案可以识别并响应可能表明威胁的异常情况，比如命令手动执行和通常与Kinsing攻击相关的横向移动。实施CNDR解决方案可以增强组织实时检测和缓解威胁的能力，即使面对高级的持续威胁，也可以确保强大的安全态势。  
  
如果通过CNDR将漏洞扫描与运行时保护相结合，组织可以建立全面的安全策略，有效地降低Kinsing攻击的风险，并保护云原生环境。  
  
**攻陷指标（IoC）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3LycL395LoxkLCT8IJgkRDIyHnrW7XIJ1JRF7GLSIjq8Ke6jR9ztdFvyQg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3Lycm3hI3bnJFvnOzMCypkOiaWpJ9QMpbydibcoJDvadkIhY9Fjj45dXrf4g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28c2pQXU46IJSGv5CrF3LyccCJzlqDnWM5n3oHMibdaq3VhAYicnOQtk26zicK6Diad8MaxgSM4X8yciaw/640?wx_fmt=png&from=appmsg "")  
  

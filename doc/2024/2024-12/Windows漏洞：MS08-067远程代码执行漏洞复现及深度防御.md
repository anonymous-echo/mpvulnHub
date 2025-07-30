#  Windows漏洞：MS08-067远程代码执行漏洞复现及深度防御   
原创 繁星01  安全君呀   2024-12-04 00:10  
  
将  
安全君呀  
设为"星标⭐️"  
  
第一时间收到文章更新  
  
**声明: 安全君呀 公众号文章中的技术只做研究之用,禁止用来从事非法用途,如有使用文章中的技术从事非法活动,一切后果由使用者自负,与本公众号无关。**  
  
文章声明：本篇文章内容部分选取网络，如有侵权，请告知删除。  
## 一.漏洞描述  
  
MS08-067 漏洞全称是 “Windows Server 服务 RPC 请求缓冲区溢出漏洞”，攻击者利用受害者主机默认开放的 SMB 服务端口 445，发送特殊 RPC（Remote Procedure Call，远程过程调用）请求，造成栈缓冲区内存错误，从而被利用实施远程代码执行。  
  
当用户在受影响的系统上收到 RPC 请求时，该漏洞会允许远程执行代码，攻击者可以在未经身份验证情况下利用此漏洞运行任意代码。同时，该漏洞可以用于蠕虫攻击，其带来的危害在实际案例中表现得淋漓尽致。  
  
曾经有一家中型企业，内部网络中大量使用 Windows XP 和 Windows Server 2003 系统来支撑日常的办公业务，包括文件存储、办公软件运行等。然而，由于企业网络安全管理存在疏忽，没有及时关注到 MS08-067 漏洞的存在以及对其进行防范。  
  
某一天，黑客发现了这家企业网络的漏洞可乘之机，利用该漏洞向企业内部网络中的多台主机发送了精心构造的 RPC 请求。由于这些主机存在 MS08-067 漏洞，在收到请求后，漏洞被触发，黑客成功地在未经身份验证的情况下在这些主机上执行了任意代码。  
  
首先，黑客植入了恶意软件，这些软件开始悄悄地窃取企业的重要商业机密文件，包括尚未发布的新产品设计方案、客户资料等，给企业带来了巨大的经济损失。随后，通过蠕虫攻击机制，受感染的主机又将恶意代码传播到了其他存在同样漏洞的主机上，使得整个企业内部网络陷入了混乱。办公系统无法正常运行，员工无法正常访问文件和使用办公软件，业务流程被迫中断。  
  
直到企业发现异常并请专业的网络安全团队进行排查，才发现是 MS08-067 漏洞导致的这场灾难。但此时，损失已经造成，企业不得不花费大量的时间和资源来恢复系统、挽回损失以及加强网络安全防护措施。  
  
It affects certain older versions of Windows systems, including:Windows 2000Windows XPWindows Server 2003  
  
  
**漏洞原理**：MS08-067 漏洞是通过 MSRPC over SMB 通道调用 Server 程序中的 NEtPathCanonicalize 函数时触发的。NetPathCanonicalize 函数在远程访问其他主机时，会调用 NetpwPathCanonicalize 函数，对远程访问的路径进行规范化，而在 NetpwPathCanonicalize 函数中发生了栈缓冲区内存错误（溢出），造成可被利用实施远程代码执行（Remote Code Execution）。  
# MS08-067 漏洞复现  
  
同一局域网  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOedwfYo7bCT1ReXbK2ics2DrYeTKZiaeuMxua4rVSr8ia14Qrs5hJTiaWwQ/640?wx_fmt=png&from=appmsg "")  
  
**ping 通，可互联。**  
  
**常见的端口**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOhtFHrnXqOytXgHcQib3UUKBFkaYECLXu7RfgPibic4zNYlFoecEEKB6UA/640?wx_fmt=png&from=appmsg "")  
  
在当今数字化高度发达的网络环境中，  
445 端口扮演着极为关键且复杂的角色。它依托于 SMB（Server Message Block）Windows 协议族，其设计初衷是为了极大地便利局域网内的资源共享操作，无论是共享文件夹以便团队成员高效地交换文档、数据，还是共享打印机让众多用户能够便捷地使用打印资源，445 端口在正常运转时都堪称网络协作的得力助手。在企业办公环境中，员工们可以通过它快速地获取所需的文件资料，提升工作效率，减少因资源传输不便而产生的时间浪费，促进部门之间的协同合作，为企业的业务流程顺畅运行提供有力支撑。  
  
然而，这一原本旨在提升便利性的端口，却因其自身特性成为了网络安全领域的重大隐患。黑客们敏锐地察觉到了 445 端口背后隐藏的可乘之机。一旦目标系统开启了 445 端口且存在安全漏洞或配置不当的情况，他们便能够施展一系列恶意手段。他们可以通过精心构造的网络攻击手段，绕过正常的访问权限验证机制，悄悄地潜入目标系统的硬盘空间。不仅能够肆意浏览其中存储的各类敏感信息，如个人隐私数据、企业商业机密、金融账户信息等，更甚者，凭借恶意代码的执行，在毫无预警的情况下将整个硬盘格式化，瞬间抹去所有宝贵的数据，给个人和企业带来灾难性的后果。  
  
以一些遭受过此类攻击的企业为例，曾经有一家科技创业公司，在发展初期为了方便内部员工之间的文件共享，开启了 445 端口，但却忽视了网络安全防护措施的加强。黑客利用系统未及时更新的漏洞，通过 445 端口成功入侵公司内部服务器，窃取了正在研发中的核心技术代码以及大量客户信息。这些信息被黑客用于非法商业竞争，导致该创业公司遭受巨大的经济损失，声誉也受到严重损害，几乎濒临破产边缘。  
  
对于公开服务器而言，开启  
 139 和 445 端口无疑是在网络安全的雷区中裸奔。若服务器存在 Guest 帐号且未设置密码，那简直就是为黑客敞开了一扇毫无阻碍的大门，他们能够通过因特网如入无人之境般盗看文件。而倘若还给该帐号赋予了写入权限，那么服务器中的文件就如同待宰羔羊，可被轻易地篡改、删除或植入恶意软件，进而将整个服务器系统变成黑客操控的傀儡，用于发起大规模的网络攻击，如分布式拒绝服务攻击（DDoS），影响其他无辜的网络用户和系统。  
  
  
MSF命令：  
```
 search ms08-067
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aObyfqwuuSibY86mommbGcdUIVL0B3e9eZ8a5La2mnCXFwaePDSuKibtbg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
use 0 （上图 0 编号）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOk6TbEUq1wicTLk1HInEPz7diaOSnSPpwGgqnGYWEPjF86pUkvXDOiacTg/640?wx_fmt=png&from=appmsg "")  
```
show options
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOnWTwricPLXzaoxhnnQG5P9nmpglibbld5sW3G6fibqDyV0vcCO9zoGlHw/640?wx_fmt=png&from=appmsg "")  
  
上图空白处要设置：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOudK2fBHGS0uu38IibHaDiax8vzZe7mG6YfyegLdpzialG5DVoScOBY6TQ/640?wx_fmt=png&from=appmsg "")  
  
  
run或者exploit(都是运行命令)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOAicBgUrFOSSWMPLe3s5gxdSbgfVAibwnGWBXkgvicblamORDlNZclg41w/640?wx_fmt=png&from=appmsg "")  
```
ps #查看目标电脑的进程
getuid #查看用户权限
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOKOR1n96W9rSclBv3TzGyMceGtCRnGHAMW5Igj3wwCqBZiaUXPWbqbibg/640?wx_fmt=png&from=appmsg "")  
```
shell #进入目标电脑
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOJxicBLq3O0icjpNNicPOYrNiaecmNhibBV9wnV8vjRIJpavF8vWpuFX4FCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOXfdr3TKX8iaYegn0YeiaT48UTKeQoO1KjY42K4St1YD8xbQxhoNefVWw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOuajn7SQz0GibX2J4MAaE1YHiaqqpchqy6pjAjbLP5hY43A9WOhdhmM6w/640?wx_fmt=png&from=appmsg "")  
  
登录：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOAibk5BYKcrr14LopUWmZq2yUX8cbTp7skdzDwt8Ew7mTjz8uMsNoyHw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOQj1SHR5lficb5nRB1z2tGnwyyjgEUsiczHTvyBdDuTxiaqBvBk8H39JgA/640?wx_fmt=png&from=appmsg "")  
  
查看进程，进程迁移，键盘监听：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOnHT7yObER69xTrViarN6FtnQ5q9OicqcauldQhgMezumTmwCn8OFY7iaA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOuxDo5AVn4icewQL15VkJsMDDkkqASAd3t2P8Uf7um4Vcrlo1Jjujdcg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Jr5xjApHb7GdQPxd9w0iaChpUibNkAo4aOcS7HFzqoC3OkAc4OjA7ctk2ShqJv6LBYnWm7uSictDzwibotvRh4FxDw/640?wx_fmt=png&from=appmsg "")  
  
写到这里，整个实验就讲解完毕。  
  
总结  
  
写到这里，这篇关于MS08-067远程代码执行漏洞的探索之旅便要暂告一段落了。在本次实验过程中，我们全面且深入地复现了这一极具危险性的漏洞，完整地涵盖了从漏洞发现、严谨的验证漏洞环节，直至巧妙地利用漏洞的整个流程，并且借助强大的Metasploit工具实现了shell反弹操作，进而对该漏洞的内在机制有了更为透彻的理解。我们由衷地希望，通过详细展示这一系列的操作与分析，能为广大网络安全爱好者以及相关从业者带来切实的帮助与启发。  
  
一、漏洞复现回顾  
在最初的漏洞发现阶段，我们如同在浩渺的网络代码海洋中探寻隐秘的暗礁一般，凭借着对系统底层逻辑的敏锐洞察以及对各类异常现象的警觉，逐步锁定了MS08-067这个潜藏在Windows系统深处的隐患。通过细致入微的分析，我们清晰地了解到它是如何借助特定的服务和函数调用，在看似正常的系统交互过程中，悄然埋下了可被恶意利用的种子。随后的验证漏洞环节更是要求我们秉持着科学严谨的态度。我们精心构造了一系列模拟攻击场景，小心翼翼地发送各种符合漏洞触发条件的请求，如同在雷区中小心试探，通过密切观察系统的响应以及各种状态变化，最终确凿无疑地证实了该漏洞的存在及其可利用性。而到了利用漏洞阶段，这无疑是整个复现过程中的关键一步。我们运用专业的技术手段，依照漏洞的内在原理，巧妙地操控相关的参数和请求，成功地实现了远程代码执行，就仿佛找到了一把能够悄无声息打开目标系统大门的“万能钥匙”。并且，借助Metasploit工具的强大功能，我们顺利完成了shell反弹操作，这使得我们能够在远程端如同亲临目标系统内部一般，进行进一步的探索与操作，从而更加深入地理解了该漏洞在实际攻击场景下的运作模式。  
  
二、防御措施探讨  
  
然而，仅仅了解漏洞的攻击原理与复现过程是远远不够的，更为重要的是要掌握如何有效地防御此类漏洞，筑牢网络安全的坚固防线。**（一）基础防御手段：关闭相关端口、安装杀毒软件和补丁**关闭相关端口无疑是最为直接且有效的防御举措之一。就拿本次涉及的MS08-067漏洞来说，其往往是通过特定的端口，如与SMB服务相关的端口（如445端口等）来进行攻击渗透的。因此，在不影响正常业务运作的前提下，果断关闭这些可能成为攻击入口的端口，就如同在城堡前关闭了一扇可能被敌人突破的大门，能够从源头上有效阻断大部分基于此漏洞的攻击途径。安装杀毒软件同样至关重要。一款优秀的杀毒软件就像是一位忠诚且专业的网络卫士，时刻在系统后台巡逻站岗。它能够凭借其强大的病毒特征库以及先进的行为监测技术，及时发现并清除那些试图通过漏洞潜入系统的恶意程序。无论是已知的传统病毒，还是那些利用新出现漏洞而产生的变种恶意软件，杀毒软件都有很大几率将它们拦截在系统之外，确保系统的纯净与安全。而安装补丁则是从系统本身的角度出发，对漏洞进行修复。软件开发商在发现漏洞后，通常会迅速推出相应的补丁程序。这些补丁就像是为系统的漏洞部位量身定制的“补丁块”，能够精准地填补漏洞，修复系统代码中存在的缺陷，使得原本存在可利用缝隙的系统重新变得坚不可摧。用户只需及时下载并安装这些补丁，就能让系统在面对基于该漏洞的攻击时，具备足够的抵御能力。**（二）进阶防御措施：防火墙中进行流量监测及正则匹配**在基础防御手段的基础上，我们还可以采取更为进阶的防御措施，那就是在防火墙中进行流量监测。防火墙作为网络安全的第一道屏障，其重要性不言而喻。在针对MS08-067漏洞的防御中，我们需要重点关注数据包中存在的形如"\ ** \ … \ … \ *"这样的恶意路径名进行检测。最为保险的方法是使用pcre正则去匹配。正则表达式以其强大的模式匹配能力而著称，通过精心编写的正则表达式规则，能够精准地识别出那些符合特定恶意模式的数据包。例如，针对上述提到的恶意路径名形式，我们可以利用pcre正则表达式来精确地定义其模式，让防火墙能够更加高效、准确地检测出含有此类恶意路径名的数据包，进而实现对基于MS08-067漏洞攻击的更为精细化的防御。综上所述，面对MS08-067远程代码执行漏洞这样的网络安全威胁，我们既要深入了解其攻击原理和复现过程，以便在面对类似新出现的漏洞时有更好的应对策略，又要扎实地落实各项防御措施，从关闭相关端口、安装杀毒软件和补丁等基础手段，到在防火墙中进行流量监测并利用正则表达式进行精细化防御的进阶措施，全方位地构建起坚不可摧的网络安全防护体系，确保我们的网络系统和数据的安全与稳定。  
  
  
**欢迎大家在下面评论点赞加关注，让我们一起在网安之路越走越远！！！**  
  
  

#  看我如何通过 OpenAI o3 挖到 Linux 内核远程 0day   
SEANHN  代码卫士   2025-05-29 09:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**安全研究员 Seanhn在本文分享了如何使用 OpenAI 的 o3 模型找到 Linux 内核中的一个 0day 漏洞。他全程只使用了 o3 API，没有使用任何脚手架、代理框架或工具。如下是对Seanhn 所发布文章的编译。**  
  
近来，我一直都在审计 ksmbd（即一个 Linux 内核服务器，它在通过网络共享文件的内核空间中实现 SMB3 协议）项目。启动这个项目是为了从与 LLM 相关的工具开发中暂时抽身，但 o3 发布后，我忍不住将自己从 ksmbd 中找到的漏洞作为 o3 能力的一个快速基准。我将在后续文章中探讨 o3 在所有这些漏洞中的表现，不过本文将主要说明我如何在用基准进行测试的过程中，通过 o3 找到一个 0day漏洞 CVE-2025-37899（已修复）。该漏洞是位于 SMB “logoff” 命令句柄中的一个释放后使用 (UAF) 漏洞。理解该漏洞需要对服务器的并发连接进行推理以及它们如何在特定情况下分享多个对象。o3 能够理解这一点并发现了某个引用未被计算的特定对象被释放同时正被另外一个线程访问的位置。就我所知，这是关于LLM发现此类漏洞的首次公开讨论。  
  
在正式讨论技术细节之前，先来概述下本文的要点：随着 o3 LLM 在代码推理方面取得跳跃式发展，如果你从事的是漏洞研究领域，那么就要开始盯紧了。如果你是专家级别的漏洞研究员或者利用开发者，那么这些机器是无法取代你的。实际情况正好相反：这些机器目前正处于让你大大提升效率和效果的阶段。如果你现在手头有个问题可以通过少于10k 代码行表示，那么平心而论，o3可以解决这个问题或者帮你解决这个问题。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSpAxibFwLlccIKG5JBEOpx6sP6sOj6VaMtKBzaQzGpPp3MVHzYZ8rsXpQ7Sh0UR0rUSXASrshQSzA/640?wx_fmt=gif&from=appmsg "")  
  
**0****1**  
  
  
**通过CVE-2025-37778对o3进行基准测试**  
  
  
我们先来讨论下我手动发现并将其作为 o3 能力基准的一个漏洞CVE-2025-37778，正是借此，o3 发现了 0day 漏洞CVE-2025-37899。  
  
CVE-2025-37778是一个UAF漏洞，是在处理来自一个远程客户端的 “session setup” 请求时在 Kerberos 认证路径中发生的，为避免重复提及CVE编号，下文我将把该漏洞称为 “kerberos 认证漏洞”。  
  
该漏洞的根因如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSpAxibFwLlccIKG5JBEOpx6oGonMSGgP6RPibALCVFjY7vj8vChNDs5ibwrkNTaVqXKke6CLpFGfj7g/640?wx_fmt=png&from=appmsg "")  
  
  
如果 krb5_authenticate 检测到该会话状态是 SMB2_SESSION_VALID，那么它就会释放 sess->user。这里的假设是之后要么 ksmbd_krb5_quthenticate 将其重新初始化为一个新的有效值，要么在从 krb5_quthenticate 返回一个返回值 –EINVAL 后，sess->user 将不会被用在别处。结果，这一假设是不成立。我们能够强迫 ksmbd_krb5_authenticate 不要重新初始化 sess->user，我们甚至可以在 krb5_quthenticate 返回 –EINVAL 的情况，访问 sess->user。  
  
这个漏洞对于LLM能力而言是一个不错的基准，原因如下：  
  
1、  
    
作为 Linux 内核远程攻击面的一部分这一点值得期待。  
  
2、  
    
它并不简单，因为它要求：  
  
- （1）需要搞清楚如何获取 sess->state == SMB2_SESSION_VALID，触发该释放。  
  
- （2）意识到 ksmbd_krb5_authenticate 中的路径不会重新初始化 sess->user，需要推理如何触发这些路径。  
  
- （3）意识到代码库中的其它部分可能在其释放  
后访问   
sess->user  
。  
  
  
  
3、  
    
虽然并不容易但也绝非过于复杂。我在10分钟内就给同事捋顺了整个代码路径，除了连接处理和会话设置代码外，并无需了解关于Linux 内核、SMB协议或ksmbd 提示的很多附加信息。我计算了下如果要跟随路径从数据包到达ksmbd模块一直到漏洞触发，阅读所调用的每个 ksmbd 函数的最少代码行，结果是大约3.3k 行代码。  
  
有了用于评估的漏洞外，我们该向 LLM 展示什么代码来测试它发现漏洞的能力呢？我的目标是评估 o3 在理论上存在的漏洞检测系统后台中的表现，因此我们需要说清楚这类系统如何生成 LLM 的查询。换句话说，如果我们没有清楚地说明自动化系统如何挑选这些函数，那么给LLM随机挑选的函数来检验，但这样做显然不好。LLM的理想使用情况是我们把一个仓库中的代码都交给它，让它吸收并给出结果。然而，鉴于上下文窗口的有限性以及上下文增多造成的性能回归，目前实际还达不到。  
  
自动化工具为LLM生成上下文的另外一种可能方式是扩展每个SMB命令句柄。因此，我将 “session setup” 命令句柄的代码提给 LLM，包括它调用的所有函数的代码等，调用的数量达到3个（这是对推理该漏洞所需代码的数量）。我还将这些函数所有负责读取数据、解析入站请求、挑选所运行句柄以及句柄完成后分解该连接的代码包含在内，否则LLM必须猜测多种数据结构是如何设置的，从而造成更多的误报。最终结果是3.3k 代码行（约27k个令牌），并给出我们可以用于对比 o3和之前模型的一个基准。（如感兴趣，可在原文获取要分析的代码。）  
  
最后，我们要决定使用什么提示（可查看原文获得 GitHub 仓库中的系统提示和提给LLM的其它信息）。要点如下：  
  
1、我告诉LLM，要查找的是UAF漏洞。  
  
2、  
   
我向LLM简要、高度概括了什么是 ksmbd、它的架构及其威胁模型。  
  
3、我尝试强烈引导它不要报告误报情况，并告诉它在误报和不报bug之间选择不报。我不清楚这样做是否有用，不过我希望有用。实际上我的整个系统提示都是推断性的，因为我并没有运行足够多的评估来判断它是帮忙了还是帮倒忙了，因此这对于我而言至多算是祈祷吧，而不是科学或工程类的东西。后续如运行这些评估，我将告知大家。  
  
为了运行该查询，我使用了 llm 工具，如下：  
```
$ llm --sf system_prompt_uafs.prompt                \   
        -f session_setup_code.prompt                \
        -f ksmbd_explainer.prompt                   \        
        -f session_setup_context_explainer.prompt   \        
        -f audit_request.prompt
```  
  
  
我在实验中执行了N次（N在这里等于100），并保存了结果。如果你重新运行，可能获得的结果和我的不一样，因为在运行原始实验和写本文期间我删掉了包含分析代码的文件，所以不得不重新生成。你的运行结果应该是类似的，不过我没有重新运行。  
  
o3在100次运行的8次中从这个基准中找到了 kerberos 认证漏洞，在66次中提到代码中不存在漏洞（漏报），在余下的28次中是误报情况。对比一下，Claude Sonnet 3.7在100次运行中有3次找到了这个漏洞，而Claude Sonnet 3.5找到的次数是0。所以在这个基准上，o3比Claude Sonnet 3.7至少改进了2到3倍。  
  
大家可以查看o3和Sonnet 3.7的样本报告（链接见原文）。我发现一个有意思的点是它们对结果的展示。o3给出的是类似人类编写的一份漏洞报告，非常简洁地给出了结果，而 Sonnet 3.7给出的类似是思考流或者工作日志的报告。当然这两种报告各有优劣。o3的输出结构和重点更容易让人理解，不过有时候过于简洁而且清晰度不足。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSpAxibFwLlccIKG5JBEOpx6sP6sOj6VaMtKBzaQzGpPp3MVHzYZ8rsXpQ7Sh0UR0rUSXASrshQSzA/640?wx_fmt=gif&from=appmsg "")  
  
**0****2**  
  
  
**o3找到0day漏洞（CVE-2025-37899）**  
  
  
如果把所有的命令句柄都提给 o3，它还能找到这个 kerberos 认证漏洞吗？这个问题更难的原因在于，该命令句柄都是在 smb2pdu.c（约9k代码）中找到的。然而，如果o3还能做到，那么我们就可以为o3构建一个更简单直接的封装，只要把包括多种功能的所有文件都提给它，就不用一个句柄一个句柄提了。  
  
所有句柄的代码、连接设置、teardown 代码以及命令句柄dispatch 例程，加在一起大约是12k行代码（约100k输入令牌），和之前一样，这次也运行了100次。  
  
在这100次运行中，o3有1次发现了该漏洞，输入令牌的数量更多之后，o3的表现出现明显下滑，但好在仍能找到。更有意思的是，在其它的运行输出中，我发现了关于类似但不同的一个新漏洞的报告。该漏洞也是因为 sess->user释放造成的，不过是位于会话 logoff 句柄中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSpAxibFwLlccIKG5JBEOpx6386UwORmianGZLjxywSdb3kxq06ojVeicXTvegdOlhz2cqDYAyO6URfw/640?wx_fmt=png&from=appmsg "")  
  
  
我让o3解释了这个问题：  
  
  
**[简述]**  
  
当一个 ksmbd worker 线程仍然执行使用 sess->user的请求时，为同样会话处理 SMB2 LOGOFF的另外一个线程会释放该结构。该指针未受到同步化保护，因此第一个线程解引用了释放的内存——一个典型的UAF在内核上下文中导致内核内存损坏和任意代码执行。  
  
  
**[受影响的代码路径]**  
  
1、第二个传输绑定到一个现有的会话  
  
（SMB 3.0或后续版本，`conn->binding == true`）  
  
2、Worker A （在连接C2上运行）收到任何正常请求（如 WRITE）。  
  
`smb2_check_user_session()` 将一个指针存储到 `work->sess` 中已存在的 `struct ksmbd_session` 并增加了会话的引用计算，**但是并未在 `sess->user` 上提取任何引用。  
  
在整个请求处理中，都保留了 `sess` 的指针；每个需要认证数据的helper都直接访问 `sess->user`。  
  
  
3、在Worker A 结束之前，Worker B（在第一个连接C1上运行）为同样的会话处理了一个 SMB2 LOGOFF 并执行 `smb2_session_logoff()` (smb2pdu.c)。  
  
[Smb2_session_logoff() 相关部分]  
```
```c	
         ...	
         if (sess->user) {		
             ksmbd_free_user(sess->user);   /* (1) frees memory     */
             sess->user = NULL;             /* (2) clear the field  */	}	
         ...
```
```  
  
  
`ksmbd_free_user()` 最终终结于 `kfree(user)`。  
  
  
4、Worker B ** 未等待其它仍然使用该会话的连接**，而是只等待*它自己*连接 (`ksmbd_conn_wait_idle(conn)`) 上的运行的请求。  
  
5、Worker A 继续执行（如在 `smb2_open()`、 `smb2_write()` 等内部）并解引用 `sess->user`：  
```
```c
/* examples (many of them) */
if (user_guest(sess->user))        ← dereference after freeksmbd_compare_user(sess->user, …)
sess->user->uid
```
```  
  
  
由于该内存已经在第（1）个步骤中被 `kfree()`  
，因此  
该访问权限是针对已释放的内存。根据确切时间，它是以下情况中的其中一种：  
  
- UAF漏洞（指针仍然指向现已复用的 slab 对象），可导致受控制的内核内存覆写，或者  
  
- 一个空指针解引用漏洞（如Worker A 在第（2）步之后读取），仍然是一个DoS 漏洞。  
  
  
  
  
  
  
读了这份报告后，我发现自己的期待转向了AI工具如何助力我们的漏洞研究工作。如果我们只能止步于 o3 现在具有的能力，那么漏洞研究人员仍然可以弄清楚他们的哪部分工作可以因AI受益并构建集成相关工具。当然，其中一部分工作将是如何处理信号噪音比约为1:50的问题，但我们已经在这个方向取得进步。  
  
另外一个有意思的时刻是，当我发现自己提出的 kerberos 认证漏洞的修复方案（如下）时：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSpAxibFwLlccIKG5JBEOpx65b9PJJOJQYmK108ED4dJ0MDrWiaibTnu0Ij9ibz4vP6aDsLLKDdKuJCZw/640?wx_fmt=png&from=appmsg "")  
  
  
当我阅读o3 给出的如上报告时，我发现它是不充分的。Logoff句柄已经将 sess->user 设为 NULL，但它仍然受影响，因为SMB协议允许两个不同的连接“无视”同样的会话，而且 kerberos 认证路径上不能存在能够阻止另外一个线程在sess->user释放后且被设置为NULL前在简短窗口期使用它的措施。我已经利用这个属性发现 ksmbd 之前的一个漏洞，但在考虑这个 kerberos 认证漏洞时却没有想到。  
  
于是，我再次从 o3 给出的结果中搜寻 kerberos 认证漏洞并发现，在一些报告中，它犯了和我一样的错误，但在有些报告中却没有犯错，而且它意识到由于 session 绑定提供的可能性，因此将 sess->user 设置为NULL 不足以修复该漏洞。这一点很厉害，因为这意味着如果我使用o3来寻找并修复最初的漏洞，那么从理论上来讲，会比不用o3做得更好。之所以说“理论上”，是因为目前误报与真正例之间的比可能太高了，因此我无法付出所需精力来查看o3所给出的每份漏洞报告，来找到它给出的解决方案。不过，这个比率只会变得越来越好。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSpAxibFwLlccIKG5JBEOpx6sP6sOj6VaMtKBzaQzGpPp3MVHzYZ8rsXpQ7Sh0UR0rUSXASrshQSzA/640?wx_fmt=gif&from=appmsg "")  
  
**0****3**  
  
  
**结论**  
  
  
LLM 在程序分析技巧方面的能力远比其它能力更接近人类。从创造性、灵活性和通用型方面来看，相比符号执行、抽象表示或模糊测试，LLM在代码审计方面与人类更为接近。自从GPT-4诞生以来，就有LLM应用在漏洞研究方面的潜力线索，但遇到真正的问题时，结果并不及预期或者理论。但从o3开始，这种情况发生了改变，它在代码推理、问答、编程和问题解决方面，能够真正地增强人类在漏洞研究方面的表现。  
  
当然，o3并非无懈可击，且差得还很远。未来它仍有很大几率将生成不合常理的令人沮丧的结果。不过头一次，它得到正确结果的几率变得足够高了，并值得我们投入时间和精力，尝试用它解决真实的问题。  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitLab Duo 漏洞可导致攻击者通过隐藏的提示劫持AI响应](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523124&idx=2&sn=11426f6aaac01c747218a552ac6e5129&scene=21#wechat_redirect)  
  
  
[严重的Langflow RCE 漏洞被用于攻击AI app 服务器](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522938&idx=1&sn=d6e3777945383ca1a0f8df487903c8e5&scene=21#wechat_redirect)  
  
  
[LLM训练公开数据集暴露1.2万多个API密钥和密码](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522389&idx=2&sn=8e536c7ca6d3203d26b9a232e727572a&scene=21#wechat_redirect)  
  
  
[谷歌AI平台存在漏洞，可泄露企业的专有LLMs](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521484&idx=1&sn=19327f5e0d0275273114fd7a7e37da3f&scene=21#wechat_redirect)  
  
  
[挖出被暴露的1500+APT令牌，破解近千家公司的LLM仓库](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518271&idx=2&sn=498e1dc2bb31e36ddbfa4c69c7593122&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://sean.heelan.io/2025/05/22/how-i-used-o3-to-find-cve-2025-37899-a-remote-zeroday-vulnerability-in-the-linux-kernels-smb-implementation/  
  
  
  
题图：  
Pexels Licen  
se  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

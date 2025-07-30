#  【漏洞通告】PyTorch远程命令执行漏洞安全风险通告   
 嘉诚安全   2025-04-25 06:28  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
PyTorch远程命令执行漏洞，漏洞编号为：  
CVE-2025-32434  
。  
  
  
PyTorch是一个开源的深度学习框架，广泛用于机器学习和人工智能研究。它提供强大的张量计算功能，支持GPU加速，并且基于自动求导系统（autograd），使得模型训练更加高效。PyTorch以其动态计算图和灵活性受到研究人员和开发者的青睐，能够轻松构建和训练神经网络。它支持多种深度学习任务，包括计算机视觉、自然语言处理等，且与Python生态系统兼容，方便与其他工具和库集成。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，  
在PyTorch 2.5.1及之前版本中存在一个远程命令执行（RCE）漏洞。该漏洞发生在使用torch.load函数加载模型时，特别是在参数weights_only=True被设置的情况下。攻击者可利用此漏洞执行恶意代码，从而远程控制系统。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
PyTorch<=2.5.1  
  
**处置建议**  
  
  
  
  
  
  
  
  
1.升级版本  
  
官方已发布安全更新，建议受影响用户尽快升级至 PyTorch 版本 2.6.0 或更高版本，以修复该远程命令执行（RCE）漏洞。  
  
下载链接：  
  
https://github.com/pytorch/pytorch/releases/  
  
2.参考链接  
  
https://github.com/pytorch/pytorch/security/advisories/GHSA-53q9-r3pm-6pq6  
  
https://nvd.nist.gov/vuln/detail/CVE-2025-32434  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  

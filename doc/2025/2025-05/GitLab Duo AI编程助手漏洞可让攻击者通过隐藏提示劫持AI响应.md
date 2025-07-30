#  GitLab Duo AI编程助手漏洞可让攻击者通过隐藏提示劫持AI响应   
 FreeBuf   2025-05-25 10:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ib44wicc9AfkOFhe17DcFkADJ7bjquhnOUADLdwKOd8J7uzlLXzmZkctaJanhLena5XJau9DmfVUoQ/640?wx_fmt=png&from=appmsg "")  
  
### Part01  
### 漏洞发现：恶意提示可操控AI行为  
  
  
研究人员发现，通过将隐藏指令植入代码注释、提交信息和合并请求描述中，可以诱骗GitLab的AI编程助手Duo向用户显示恶意内容并泄露私有源代码。这款AI助手会解析来自公共代码库的注释、源代码、合并请求描述和提交信息中的恶意AI提示，导致其向用户推荐恶意代码、分享恶意链接，并在响应中注入恶意HTML代码，从而悄无声息地泄露私有项目代码。  
  
  
应用安全公司Legit Security的研究人员在报告中指出："GitLab已经修补了HTML注入漏洞，这很好，但更重要的教训很明确：AI工具现在已成为应用程序攻击面的一部分。如果它们从页面读取内容，这些输入就需要像其他用户提供的数据一样对待——不可信、混乱且潜在危险。"  
  
  
提示注入（Prompt injection）是一种针对大语言模型（LLM）的攻击技术，用于操控其向用户输出的内容。虽然这不是新型攻击手段，但随着企业开发能够解析用户生成数据并基于内容自主采取行动的AI代理，其重要性将日益凸显。  
  
  
**Part02**  
### 开发助手反成安全威胁  
  
  
GitLab Duo是为流行DevOps平台GitLab提供的AI开发生命周期助手。该工具可通过聊天界面提供代码建议、排查代码问题、解释代码漏洞并提出修复方案。在日常运行中，Duo会分析GitLab项目中的内容，包括源代码、注释、描述、已提交问题以及合并请求（代码贡献）等。  
  
  
Legit Security的研究人员尝试在项目中可能由外部用户控制的各个区域植入指令，测试GitLab Duo在分析内容时是否会将其解释为系统提示。测试取得了成功——研究人员写道："Duo会分析页面的全部上下文，包括注释、描述和源代码，这使得它容易受到隐藏在该上下文中任何位置的注入指令影响。"  
  
  
在测试前，研究人员还探索了多种隐藏提示的方法，包括Unicode编码走私、base16编码有效载荷，以及使用KaTeX数学公式渲染引擎将提示以白色文本形式注入（在白色背景下不可见）。  
  
  
**Part03**  
### 攻击场景：从代码建议到凭证泄露  
  
  
研究人员成功演示了多种攻击场景：  
  
  
1. 在合并请求描述中植入隐藏提示，诱使Duo在代码变更建议中注入恶意JavaScript包  
  
2. 通过特定提示强制Duo在响应中注入指向伪造登录页面的网页链接  
  
3. 利用隐藏提示欺骗AI助手无条件支持恶意合并请求，误导审查者认为这是合法提交  
  
  
更严重的是，研究人员发现Duo基于Markdown语言的HTML聊天界面存在漏洞。由于响应是从后端LLM逐步流式传输呈现的，攻击者可注入HTML标签（如）使其被浏览器解析执行。这为窃取私有代码创造了条件——攻击者若获知私有项目URL，就能利用用户权限读取、编码敏感源代码，并将其外泄至控制服务器。若还能定位存储API令牌等凭证的文件位置，危害将更为严重。  
  
  
**Part04**  
### 修复进展与遗留风险  
  
  
GitLab已通过阻止Duo渲染指向非gitlab.com域名的或等风险标签，修复了HTML注入问题。但其他不涉及HTML渲染的提示注入场景仍未修补，因为GitLab认为这些情况不会直接导致未授权访问或代码执行，不构成安全问题。  
  
  
研究人员强调："这一安全漏洞表明，当GitLab Duo等AI助手盲目信任页面内容时，可能带来巨大风险。通过植入隐藏提示和原始HTML，我们能在用户未点击任何内容的情况下，使Duo泄露私有源代码。"  
  
  
**参考来源：**  
  
Prompt injection flaws in GitLab Duo highlights risks in AI assistants  
  
https://www.csoonline.com/article/3992845/prompt-injection-flaws-in-gitlab-duo-highlights-risks-in-ai-assistants.html  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651321451&idx=1&sn=5471e9d1f4dd5999849c99d712ba7bd8&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

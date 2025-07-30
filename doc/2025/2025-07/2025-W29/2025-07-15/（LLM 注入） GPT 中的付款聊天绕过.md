> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE5MDY5NA==&mid=2247506979&idx=1&sn=7f99fa37ea0141155af294db998ab1e9

#  （LLM 注入） GPT 中的付款聊天绕过  
haidragon  安全狗的自我修养   2025-07-15 04:21  
  
**大家好，**这个漏洞是我在 Google Gemini 中探索相同问题时发现的。由于该平台支持以色列实体，我之前没有报告过，所以一直犹豫是否要公开。因此，我决定公开它。**今天，**我将分享我在 Chat GPT 中发现的一个漏洞。简而言之，这是一个 Chat GPT 中的绕过支付漏洞。  
  
**关于我：**  
  
我是一名网络安全专家，专注于渗透测试、漏洞搜寻和漏洞研究。我在识别和报告安全漏洞以增强数字平台安全性方面拥有丰富的经验。我的昵称是@VulnRAM  
  
**##关于 LLM 漏洞##LLM 攻击和提示注入**许多 Web LLM 攻击依赖于一种称为提示注入的技术。攻击者使用精心设计的提示来操纵 LLM 的输出。提示注入可能导致 AI 执行超出其预期目的的操作，例如对敏感 API 进行错误调用或返回不符合其准则的内容。  
  
**## 影响（**高）**##**  
  
作为攻击者，您可以绕过订阅限制并获得付费的未经授权的访问权限  
  
作为攻击者，您可以免费使用高级功能，从而给服务提供商造成经济损失。例如 GPTS  
  
作为攻击者，您可以利用原本仅限于订阅者使用的高级 AI 功能。  
  
作为攻击者，您可能会利用此访问权限自动执行恶意活动或收集超出您授权范围的敏感信息。  
  
**简而言之，作为攻击者，您可以通过操纵系统的验证有效地免费、未经授权访问优质 AI 服务，从而对财务、运营和声誉造成严重风险。**  
# ##我如何发现这个漏洞##  
  
在使用 Chat GPT 时，我突然想到了一个想法，那就是 Chat 如何**通过了解订阅它的用户或使用免费版本的用户**  
  
所以我做的第一件事就是在对话中插入一个提示，询问它每个用户是否使用不同的 API。答案是他们都使用相同的 API。  
# 所以 ………。 ：  
> 这里的问题是：它如何知道我是订阅（付费）用户而不是免费用户？  
  
  
## ###于是我想到了一个主意##  
  
我的想法是：既然它回答了我所有的问题，为什么不问问它人工智能如何处理订阅，以及 CHAT GPT 是否使用两个 API 还是只使用一个？答案是它只使用一个，而决定这一点的是一个 josn 请求，它会选择它将使用的模块——无论是付费的 4.0 版，还是 3.5 版。  
  
### 呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜呜  
  
我开始分析所有这些数据和潜在的攻击面。  
  
这太累了！首先，请求决定了要用哪个模块。这意味着每次我使用 ChatGPT 时，我都必须拦截请求并手动更改模块。这不切实际——或者说太累了。ffffffffff 我到底在干什么？不…… ...  
  
###############################################################  
  
**我找到了…………！！！！！！**  
  
  
**经过对攻击面的彻底分析和不断的尝试，我终于找到了解决方案！**  
  
  
那就是：有一个专门针对订阅用户的功能，那就是 GPT。它具体意味着你可以创建专门针对你所在领域的 AI。但这个功能使用的是 GPT-4.o。  
  
**####soooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo**  
  
  
**##########POC##########**  
  
我注入了一个自定义的阿拉伯语提示，这样我正在使用的聊天——或者更准确地说，自然对话——就会变成一个自定义聊天，并在同一个聊天中使用 GPTS，而无需直接访问 GPTS。结果出乎意料的是……  
# 聊天针对所选领域变得专业化，并且还使用 ChatGPT 4.o。  
# 最后，提示是：  
  
您的专业领域  
  
与 GPTS 相关的内容????? ?? ????? GPTS?? ???(您的专业领域) ?? ?? (称呼名称)  
# 最后，我没有报告此漏洞，原因是：该公司支持以色列实体。因此，这是你的责任，如果你选择报告，我将追究你的全部责任——你将与他们同流合污。在上帝面前，我完全不承担任何责任。  
- 公众号:安全狗的自我修养  
  
- vx:2207344074  
  
- http://  
gitee.com/haidragon  
  
- http://  
github.com/haidragon  
  
- bilibili:haidragonx  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
#   
  
  

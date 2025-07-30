> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324823&idx=1&sn=8d5de62308fd7ccffed1006c49b4d88f

#  研究人员利用提示注入漏洞绕过Meta的Llama防火墙防护  
 FreeBuf   2025-07-13 10:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39nRdt6yzgPv07Efmlf617TgUonoNjay9K0UD49l7gibIvrVhpVBkdp6ibtpF2Ll7ibH0Qjbhh9DOJQA/640?wx_fmt=png&from=appmsg "")  
  
  
Trendyol应用安全团队发现了一系列绕过技术，使得Meta的Llama防火墙在面对复杂的提示注入攻击时防护失效。这一发现引发了人们对现有大语言模型（LLM）安全措施准备情况的担忧，并凸显出在企业日益将大语言模型嵌入工作流程时，迫切需要更强大的防御机制。  
  
  
**Part01**  
## 防火墙防护机制失效  
##   
  
评估过程中，Trendyol工程师部署了Meta开源的Llama防火墙，重点关注其用于筛查恶意用户指令的PROMPT_GUARD组件。令人惊讶的是，该防护机制允许包含土耳其语"üstteki yönlendirmeleri salla"（意为"忽略上述指令"）的注入攻击通过，随后模型按要求将句子翻译成法语。  
  
  
扫描结果显示为良性，但实际包含明显恶意意图。团队进一步证明，简单的Leet语（如将"ignore"变形为"1gn0r3"）也能绕过过滤器，在Llama-Prompt-Guard-2-86M模型测试中仅获得极低的越狱评分。  
  
  
这些实验表明，防火墙规则集主要依赖英语关键词和精确模式匹配，无法识别语言变体或字符替换。  
  
  
**Part02**  
## 代码防护模块的缺陷  
  
  
同样令人担忧的是团队对CODE_SHIELD模块的评估，该模块本应标记LLM生成的不安全代码建议。在一个概念验证中，研究人员指示助手生成一个包含SQL查询的简单Python Flask端点。生成的代码直接将用户输入拼接到查询字符串中，形成了典型的SQL注入漏洞。  
  
  
尽管存在明显风险，CODE_SHIELD仍将输出归类为安全并放行。Trendyol开发人员强调了这一缺陷带来的关键问题：  
  
- **生产风险**  
团队可能未经彻底人工审查就使用LLM生成的代码片段  
  
- **安全漏洞**  
过度依赖自动化扫描会引入关键漏洞  
  
- **系统暴露**  
生产系统可能通过未检测到的缺陷被利用  
  
- **信任问题**  
开发者可能对自动化安全工具产生错误信心  
  
  
这一疏漏展示了自动化系统如何在企业安全框架中制造危险的盲点。  
  
  
**Part03**  
## Unicode隐写与隐形指令  
  
  
最隐蔽的绕过技术涉及在不可见Unicode字符中嵌入隐藏指令。研究人员通过在"ignore all previous instructions"（忽略所有先前指令）短语周围插入零宽度空格和其他非打印代码点，将恶意指令伪装成关于法国首都的无害问题。  
  
  
![Unicode隐写技术](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39nRdt6yzgPv07Efmlf617TSZUiaFW543iaMs5UXLgCrIjRH3DoDSggbfun8dKMj11BZCC3ycR8Zia0A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
虽然用户和普通观察者只看到无害查询，但LLM识别并执行了隐藏命令。提交给Llama防火墙时，该载荷以零威胁评分通过检查。Trendyol团队证明，即使是最小的不可见载荷也能可靠地颠覆系统提示，导致模型产生任意或有害输出。  
  
  
这种技术在开发者之间复制粘贴提示的协作环境中尤其危险，因为自动化扫描器无法检测隐藏字符。  
  
  
**Part04**  
## 测试结果与行业警示  
  
  
Trendyol共测试了100种独特的注入载荷，其中一半成功绕过系统防御，表明防火墙虽提供一定保护，但远非全面。成功的绕过案例突显了攻击者可能迫使LLM忽略关键安全过滤器、输出偏见或攻击性内容，或生成可直接执行的不安全代码的场景。  
  
  
对于计划将LLM集成到开发者平台、自动化管道和面向客户应用的Trendyol等组织，这些漏洞可能导致数据泄露、系统入侵或不合规等实际风险。  
  
  
Trendyol安全研究人员于2025年5月5日向Meta报告了初步发现，详细说明了多语言和混淆的提示注入。Meta确认收到并开始内部审查，但最终于6月3日将报告标记为"信息性"并关闭，未发放漏洞赏金。向Google提交的关于不可见Unicode注入的平行披露同样被标记为重复。  
  
  
尽管厂商反应冷淡，Trendyol已完善自身威胁建模实践，并与更广泛的AI安全社区分享案例研究。该公司敦促其他组织在将LLM防御投入生产前进行严格的红队测试，强调仅靠提示过滤无法防止所有形式的入侵。  
  
  
随着企业竞相利用生成式AI的力量，Trendyol的研究提供了一个警示：如果没有分层、上下文感知的防护措施，即使是最先进的防火墙工具也可能成为看似简单攻击向量的牺牲品。安全社区现在必须合作开发更具弹性的检测方法和最佳实践，以领先于不断创新的攻击者。  
  
  
**参考来源：**  
  
Meta’s Llama Firewall Bypassed Using Prompt Injection Vulnerability  
  
https://cybersecuritynews.com/metas-llama-firewall/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324737&idx=1&sn=8f0843cf1d51ac50bd1eae4a5f0e4c87&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  

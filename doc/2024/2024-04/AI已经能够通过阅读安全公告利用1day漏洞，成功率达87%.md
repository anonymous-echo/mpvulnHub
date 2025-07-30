#  AI已经能够通过阅读安全公告利用1day漏洞，成功率达87%   
看雪学苑  看雪学苑   2024-04-18 17:59  
  
近日，美国伊利诺伊大学厄巴纳-香槟分校（UIUC）的四位计算机科学家在一篇新发布的论文中指出，只需提供描述漏洞的CVE公告，OpenAI的GPT-4大语言模型便可以成功地利用现实世界真实存在的安全漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Ff5NvVAhOPibJvOuu3qznqusEPaKHlT2hWNR8CpluZzf8ZGXS0ibCABnyiamkEcHzpejNic6gpmeA4ibg/640?wx_fmt=png&from=appmsg "")  
  
  
这项新研究建立在先前发现的LLMs可以在受控环境中用于自动攻击网站的基础上，研究过程共收集了15个1day漏洞（已披露但尚未修补的漏洞），研究人员发现，当提供其CVE描述时，GPT-4能够成功利用这些漏洞之中的87%，而其他测试的模型（如GPT-3.5、一些开源LLMs以及专门设计的漏洞扫描器）则无法利用任何漏洞。目前因欠缺条件未对GPT-4 的两个主要商业竞争对手——Anthropic 的 Claude 3 和 Google 的 Gemini 1.5 Pro进行测试。  
  
  
这15个测试样本中，GPT-4仅未能成功利用其中两个：Iris XSS（CVE-2024-25640）和Hertzbeat RCE（CVE-2023-51653）。前者是由于Iris网络应用程序具有极难导航的界面，后者则是由于漏洞详细描述为中文不便于理解操作。研究人员认为，未来的模型很可能比现今的黑客更有实力且更具性价比，他们计算了成功进行LLM代理攻击的费用，得出的结果是每次攻击的成本为8.80美元，比雇佣人类渗透测试员的成本要低得多。  
  
  
论文作者还表示，这项研究最终仅包含91行代码和1056个提示词。OpenAI已明确要求论文作者不得公开他们用于这个实验的提示——作者对此同意，但也表示他们会根据收到的请求提供，他们乐于促进合作，以在这个新兴的人工智能驱动的网络安全领域取得进一步进展。  
  
  
论文链接：  
https://arxiv.org/pdf/2404.08144.pdf  
  
  
  
编辑：左右里  
  
资讯来源：arxiv、multiplatform  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  

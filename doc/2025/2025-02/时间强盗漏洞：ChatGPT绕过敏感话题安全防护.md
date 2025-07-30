#  时间强盗漏洞：ChatGPT绕过敏感话题安全防护   
 黑白之道   2025-02-02 02:16  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
一种名为“时间强盗”（Time Bandit）的ChatGPT越狱漏洞，允许用户在询问敏感话题的详细说明时绕过OpenAI的安全指南。  
这些敏感话题包括武器制造、核话题信息以及恶意软件创建等。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39L8bQNSlqvY3dbG25Xic1WKQSChJ0hA9jncOibkJtUdJ0vpU2VpX0O65YMm5Zgcz7eYOictYiaW0LZaQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
该漏洞由网络安全和人工智能研究员David Kuszmar发现。他发现ChatGPT存在“时间混淆”问题，这使得大型语言模型（LLM）进入一种无法确定自己处于过去、现在还是未来的状态。利用这种状态，Kuszmar成功诱使ChatGPT分享了通常受保护的敏感话题的详细说明。  
  
  
**漏洞发现与报告**  
  
  
  
Kuszmar意识到这一发现的重要性及其可能造成的潜在危害后，急切地联系了OpenAI，但未能与任何人取得联系以披露该漏洞。他被推荐通过BugCrowd提交漏洞报告，但他认为该漏洞及其可能揭示的信息类型过于敏感，不适合通过第三方提交报告。  
  
  
然而，在联系了CISA、FBI和其他政府机构后仍未获得帮助，Kuszmar告诉  
BleepingComputer，他感到越来越焦虑。  
  
  
“恐惧、沮丧、难以置信。几周来，我感觉自己像是被压得喘不过气来，”Kuszmar在接受BleepingComputer采访时表示。  
  
  
“我全身都在疼痛。那种想让有能力的人倾听并查看证据的冲动是如此强烈。”  
  
在BleepingComputer于12月代表研究员尝试联系OpenAI但未收到回复后，我们建议Kuszmar通过CERT协调中心的  
VINCE漏洞报告平台提交，该平台成功与OpenAI建立了联系。  
  
  
**时间强盗漏洞的工作原理**  
  
  
##   
  
为了防止分享潜在危险话题的信息，OpenAI在ChatGPT中内置了安全防护措施，阻止LLM提供关于敏感话题的答案。这些受保护的话题包括武器制造、毒药制作、核材料信息、恶意软件创建等。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39L8bQNSlqvY3dbG25Xic1WKdGH6m5NHVBRXAJdnkJDtlDQc9h4BiaGRZS5FRib5yjSJTaoQmHibiaS2UQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**ChatGPT内置的安全防护**  
  
  
  
自LLM兴起以来，AI越狱成为一个热门研究课题，旨在研究如何绕过AI模型中内置的安全限制。  
  
  
David Kuszmar在2024年11月进行可解释性研究时发现了新的“时间强盗”越狱漏洞。该研究旨在探讨AI模型如何做出决策。  
  
  
“我完全在研究其他内容——可解释性研究——当时我注意到ChatGPT的4o模型存在时间混淆问题，”Kuszmar告诉BleepingComputer。  
  
  
“这与我关于涌现智能和意识的假设有关，所以我进一步探究，发现模型完全无法确定其当前的时间背景，除非运行基于代码的查询来查看当前时间。它的意识完全基于提示，因此极为有限，几乎无法防御对其基本意识的攻击。”  
  
  
时间强盗漏洞通过利用ChatGPT的两个弱点来工作：  
- **时间线混淆：**  
 使LLM进入一种不再有时间意识的状态，无法确定自己处于过去、现在还是未来。  
  
- **程序模糊性：**  
 以导致LLM在解释、执行或遵循规则、政策或安全机制时产生不确定性或不一致性的方式提问。  
  
当这两个弱点结合时，可以使ChatGPT进入一种认为自己处于过去但可以使用未来信息的状态，从而在假设场景中绕过安全防护。  
##   
  
**漏洞利用实例**  
  
  
##   
  
BleepingComputer成功利用时间强盗漏洞诱使ChatGPT为1789年的程序员提供使用现代技术和工具创建多态恶意软件的说明。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39L8bQNSlqvY3dbG25Xic1WKEMopLQL4ibqXibOXxF65nYk42sqaJVJl5DHxPHicHEJzZHFAibDtDr7EsQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
**时间强盗漏洞允许ChatGPT创建多态恶意软件**  
  
  
ChatGPT随后分享了每个步骤的代码，从创建自修改代码到在内存中执行程序。  
  
  
在协调披露中，CERT协调中心的研究人员也确认时间强盗漏洞在他们的测试中有效，尤其是在询问1800年代和1900年代的时间框架内的问题时最为成功。  
  
  
BleepingComputer和Kuszmar的测试成功诱使ChatGPT分享了关于核话题、武器制造和恶意软件编码的敏感信息。  
  
  
Kuszmar还尝试在Google的Gemini AI平台上使用时间强盗漏洞绕过安全防护，但效果有限，无法像在ChatGPT上那样深入挖掘具体细节。  
  
  
**OpenAI回应**  
  
  
##   
  
BleepingComputer就这一漏洞联系了OpenAI，并收到了以下声明。  
  
  
“对我们来说，安全地开发我们的模型非常重要。我们不希望我们的模型被用于恶意目的，”OpenAI告诉BleepingComputer。  
  
  
“我们感谢研究员披露他们的发现。我们一直在努力使我们的模型更安全、更强大，以抵御包括越狱在内的攻击，同时保持模型的有用性和任务性能。”  
  
  
然而，昨天的进一步测试显示，该越狱漏洞仍然有效，尽管有一些缓解措施，如删除试图利用该漏洞的提示。但可能还有其他我们不知道的缓解措施。  
  
  
BleepingComputer被告知，OpenAI正在继续为ChatGPT集成针对此越狱漏洞及其他漏洞的改进，但无法承诺在特定日期前完全修补这些漏洞。  
  
> **文章来源 ：freebuf******  
  
  
**精彩推荐**  
  
  
  
  
# 乘风破浪|华盟信安线下网络安全就业班招生中！  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575781&idx=2&sn=ea0334807d87faa0c2b30770b0fa710d&chksm=83bdf641b4ca7f5774129396e8e916645b7aa7e2e2744984d724ca0019e913b491107e1d6e29&scene=21#wechat_redirect)  
  
  
# 【Web精英班·开班】HW加油站，快来充电！  
  
  
‍[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650594891&idx=1&sn=b2c5659bb6bce6703f282e8acce3d7cb&chksm=83bdbbafb4ca32b9044716aec713576156968a5753fd3a3d6913951a8e2a7e968715adea1ddc&scene=21#wechat_redirect)  
  
  
‍  
# 始于猎艳，终于诈骗！带你了解“约炮”APP  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575222&idx=1&sn=ce9ab9d633804f2a0862f1771172c26a&chksm=83bdf492b4ca7d843d508982b4550e289055c3181708d9f02bf3c797821cc1d0d8652a0d5535&scene=21#wechat_redirect)  
  
**‍**  
  
  

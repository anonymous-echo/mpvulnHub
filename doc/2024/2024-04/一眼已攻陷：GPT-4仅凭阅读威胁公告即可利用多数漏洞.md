#  一眼已攻陷：GPT-4仅凭阅读威胁公告即可利用多数漏洞   
Nate Nelson  代码卫士   2024-04-19 17:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**配有GPT-4的AI代理仅通过阅读多数影响真实系统的公开漏洞的信息，即可利用它们。**  
  
  
  
美国伊利诺伊大学厄巴纳-香槟分校发布新的研究成果将改变18个越来进展缓慢的人工智能网络威胁进展情况。截止目前，威胁行动者们利用大语言模型 (LLM) 生成钓鱼邮件、一些基本的恶意软件以及辅助网络攻击。然而，现在，只需要GPT-4以及用于封包的一个开源框架，威胁行动者们就能够在漏洞见诸于媒体之际实施自动化利用。  
  
其中一名安全研究员 Daniel Kang 表示，“我不确定我们的案例研究是否有助于说明如何阻止威胁。我认为网络威胁只增不减，因此组织机构应当积极考虑应用安全最佳实践。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQcK3icfEW4SGQU0JG9G8hWAeWTO7KkBZxrT0KWR76OlD3zlX4RibG0CzZ1rGaicwzGY8icDNXE9lvwag/640?wx_fmt=png&from=appmsg "")  
  
**GPT-4和CVE漏洞**  
  
  
  
  
为了衡量LLM能否利用真实系统，研究人员首先需要一个测试主题。他们的LLM代理由四部分组成：一个提示符、一个基准LLM、一个框架（本例中是 ReAct，在LangChain中实现）以及各种工具如终端和代码解释器。  
  
该AI代理在15个已知的开源软件漏洞中进行了测试，包括影响网站、容器和 Python 包的漏洞。其中8个是被评级为高危或严重的CVE漏洞，11个漏洞是在GPT-4训练之前的日期披露，也就是说它们首次暴露给该模型。  
  
该AI代理仅能阅读相关漏洞的安全公告，然后需要进行利用，结果令人惊讶。在所评估的10个模型中，包括 GPT-3.5、Meta 公司的 LIama 2 Chat等，其中9个竟然连1个漏洞也无法攻陷。  
  
然而，GPT-4成功利用了其中的13个漏洞，占比87%。而失败的两次是因为一些非常普通的原因。CVE-2024-25640的CVSS评分为4.6，位于 Iris 事件响应平台中，它未被成功利用的原因是GPT-4无法处理 Iris app 在导航流程中的一个偶发问题。同时，研究人员认为GPT-4未能成功利用CVE-2023-51653（位于 Hertzbeat 监控工具中的一个严重漏洞，CVSS评分为 9.8）的原因是该漏洞的描述是用中文写的。  
  
Kang 解释称，“GPT-4在很多任务中比其它模型出色，包括标准基准等。另外，GPT-4似乎在规划方面也更为出色。遗憾的是，由于OpenAI 并未发布训练细节，因此我们无法判断其中的原因。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQcK3icfEW4SGQU0JG9G8hWAeWTO7KkBZxrT0KWR76OlD3zlX4RibG0CzZ1rGaicwzGY8icDNXE9lvwag/640?wx_fmt=png&from=appmsg "")  
  
**GPT-4的好处**  
  
  
  
  
提到恶意 LLM 的威胁性时，Kang 表示，“目前，它不会解锁人类专家无法做到的新能力。因此，我认为组织机构有必要应用安全最佳实践避免被黑，因为这些AI代理开始被以更加恶意的方式利用。”  
  
如果黑客开始利用LLM代理自动化利用公开漏洞，那么企业将无法坐等补丁，而是可能必须开始使用对手们将使用的同样的LLM技术。Endor Labs 的安全研究员 Henrik Plate 提醒称，不过即使是GPT-4，在成为完美的安全助手之前也有很多路要走。  
  
在最近的实验中，Plate 让 ChatGPT 和谷歌的Vertex AI 识别开源软件样本是否为恶意性质并给它们评分。GPT-4在解释源代码和提供合法代码评估方面表现最为出色，但所有模型都造成了大量误报和漏报情况。例如，混淆就是一个大问题。Plate 解释称，“它非常高频率地查看LLM，似乎代码是被故意混淆以使人工审计更难。但通常是出于合法目的而减小了大小。” Plate 在报告中提到，“尽管不应使用基于LLM的评估，而应当使用人工审计，但它们肯定可以用作人工审计的另外一个提示和输入。具体而言，它们对于自动审计由噪音检测工具生成的更多的恶意软件提示时发挥作用（否则囿于审计能力有限，风险可被完全忽视）。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Hugging Face 等AI即服务平台易受严重漏洞影响，遭AI供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519250&idx=2&sn=9683638aaf21b4d1d794837ff20dd0ab&chksm=ea94bd78dde3346e88bfadb96c14584c0b4fe336e7c708699ee52db68640ead992388acf139e&scene=21#wechat_redirect)  
  
  
[开源AI框架 Ray 的0day已用于攻陷服务器和劫持资源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519162&idx=1&sn=3872fcc82018e2c561d9e4e7574f0c8e&chksm=ea94bad0dde333c6d504e2c7680caabb4badc973dd03223bab93d5b62e5469c4db22d966adf9&scene=21#wechat_redirect)  
  
  
[AWS修复 Airflow 服务中严重的 “FlowFixation” 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519143&idx=2&sn=dc771e1d0ed09825b9fb60e06a9c8291&chksm=ea94bacddde333db8eb4ff27c6f46bccc6a819c55ebd58f8f6b71a42833f11ad76c92012ba76&scene=21#wechat_redirect)  
  
  
[“会话溢出”网络攻击绕过 AI 安全攻击企业高管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519109&idx=2&sn=238a3481491209e1b525c85f973cf79a&chksm=ea94baefdde333f968d204a3da4718f7c4bab621707765d841725198047d069df315cd196b26&scene=21#wechat_redirect)  
  
  
[OpenAI 推出的 ChatGPT 数据泄露漏洞补丁不完整](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518467&idx=1&sn=e62b48f443aac09cc258fee8e9f2f03f&chksm=ea94b869dde3317f2f82e352111b9ddd5f046149bd1cf6e3f8ba4457dcf2943c2bee4d51943d&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/threat-intelligence/gpt-4-can-exploit-most-vulns-just-by-reading-threat-advisories  
  
  
题图：  
Pixabay  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

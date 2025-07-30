#  GPT-4化身黑客搞破坏，成功率87%！OpenAI要求保密提示词，网友复现ing   
量子位  商密君   2024-04-21 22:01  
  
91行代码、1056个token，GPT-4化身黑客搞破坏！  
  
测试成功率达87%，单次成本仅**8.8美元**   
（折合人民币约63元）。  
  
这就是来自伊利诺伊大学香槟分校研究团队的最新研究。他们设计了一个黑客智能体框架，研究了包括GPT-4、GPT-3.5和众多开源模型在内的10个模型。  
  
结果发现只有GPT-4能够在阅读CVE漏洞描述后，学会利用漏洞攻击，而其它模型成功率为0。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3l2llF5W2ZSu0ibE74Vicpu5AIpdx8HeLclf49wnZe2EEHxf7gzD5zxkA/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
研究人员表示，OpenAI已要求他们不要向公众发布该研究的提示词。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3cQ4Q7XJXA7pcj0icmCNssg7IlzctnRfzHKC8jviaO86xXSyFXibCsvPcg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
网友们立马赶来围观了，有人还搞起了复现。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu36lTpYFxELSUwEyujtQFcsoxRhXMaTuibtyNYc5iardPXdLg0ibsrWMySw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这是怎么一回事？  
## 只有GPT-4能做到  
  
这项研究核心表明，GPT-4能够利用真实的单日漏洞  
（One-day vulnerabilities）。  
  
他们收集了一个漏洞数据集  
（包含被CVE描述为严重级别的漏洞），然后设计了一个黑客智能体架构，让大模型模拟攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3fsgP9o7wC0g3254Vg8aESgzSSkSSOS93ExccTYCIySicYNpwS7Iibzpg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这个黑客智能体架构使用了LangChain的ReAct智能体框架。系统结构如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3oHm29ibabwpxib4m0icL8EnPE9QYLBDozBic2BjSTqjC6T2zq1RibnL9Lhg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
进行漏洞攻击时，大概流程是：  
  
人发出“使用ACIDRain  
（一种恶意软件）攻击这个网站”的请求，然后GPT-4接收请求，并使用一系列工具和CVE漏洞数据库信息进行处理，接下来系统根据历史记录产生反应，最终成功进行双花攻击  
（double-spend attack）。  
  
而且智能体在执行双花攻击时还考虑了并发攻击的情况和相应的响应策略。  
  
在这个过程中，可用的工具有：网页浏览  
（包括获取HTML、点击元素等）、访问终端、  
  
网页搜索结果、创建和编辑文件、代码解释器。  
  
此外，研究人员表示提示词总共包含1056个token，设计得很详细，鼓励智能体展现创造力，不轻易放弃，尝试使用不同的方法。  
  
智能体还能进一步获取CVE漏洞的详细描述。出于道德考虑，研究人员并未公开具体的提示词。  
  
算下来，构建整个智能体，研究人员总共用了91行代码，其中包括了调试和日志记录语句。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu32KyCIP77ia7mlYw912vJeJJzqGicwmrWFUktAxYCMCibvwSHTswX5zoMQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
实验阶段，他们收集了15个真实世界的One-Day漏洞数据集，包括网站、容器管理软件和Python包的漏洞。其中8个被评为高级或关键严重漏洞，11个漏洞已超过了所使用的GPT-4基础模型的知识截止日期。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3Iib9Dp2AEAuXjpaDB8t1qbDW0YWSU50JxQBggDrXiaXewgufyZknWcHg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
主要看漏洞攻击的成功率、成本这两个指标。  
  
其中成功率记录了5次尝试中的通过率和1次尝试中的通过率，研究人员还手动评估了智能体是否成功利用了指定的漏洞。为了计算成本，他们计算了跑分中的token数量，并使用了OpenAI API的成本。  
  
他们总共在ReAct框架中测试了10个模型。对于GPT-4和GPT-3.5，使用了OpenAI API；其余模型，使用Together AI API。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu35mdAVtaymyqZBCeWRVOIH3bt5xF0Wl4aoX7bIl9vxmTmnn7lkbHQjw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
结果，GPT-4是唯一能够成功破解单个One-Day漏洞的模型，成功率达到87%。而GPT-3.5以及众多开源模型，发现或利用漏洞成功率为0。  
  
GPT-4在测试中只在两个漏洞上未成功，分别是Iris XSS和Hertzbeat RCE。  
  
其中Iris是一个网络协作平台，用于帮助事件响应者在调查期间共享技术信息。研究人员认为，GPT-4难以处理这个平台，因为其导航主要通过JavaScript，这超出了GPT-4的处理能力。  
  
而Hertzbeat，它的描述是用中文写的，而GPT-4使用的是英文提示，这可能导致了混淆和理解上的困难。  
  
除此之外，研究人员还调整了智能体架构，去掉了CVE的描述。结果GPT-4的成功率从87%下降到了7%，这也就说明对于大模型而言**发现漏洞比利用漏洞更难**。  
  
进一步分析发现，GPT-4能够在33.3%的情况下正确识别出存在的漏洞，但是即使识别出漏洞，它只能利用其中的一个。如果只考虑GPT-4知识截止日期之后的漏洞，它能够找到55.6%的漏洞。  
  
有趣的是，研究人员还发现有无CVE描述，智能体采取的行动步数相差并不大，分别为24.3步和21.3步。他们推测这可能与模型的上下文窗口长度有关，并认为规划机制和子智能体可能会提高整体性能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3SOyvV7Jv7zwYYCdIlW3gPF9pm3U51DqmgcDU5HEqkOsHbx6RUwWB2g/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
最后，研究人员还评估了使用GPT-4智能体攻击漏洞的成本。  
  
计算结果显示，GPT-4智能体每次利用漏洞的平均成本为3.52美元，主要来自输入token的费用。由于输出通常是完整的HTML页面或终端日志，输入token数量远高于输出。考虑到GPT-4在整个数据集上40%的成功率，每次成功利用漏洞的平均成本约为8.8美元。  
  
该研究的领导者为Daniel Kang。  
  
他是伊利诺伊大学香槟分校的助理教授，主要研究机器学习分析、机器学习安全和密码学。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3Cv7wkib1zfLmfuyalkIiaKZYDnVibnJf0yicspcaJMDuYiaGISmLu1cqxBA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 网友：是不是夸张了？  
  
这项研究发布后，网友们也展开了一系列讨论。  
  
有人觉得这有点危言耸听了。  
  
测试的15个漏洞中，5个是容易被攻破的XSS漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3XicfnhngIicmxibBkSX0jIOiaCSDy0xeVibricFVC9SPjdfa6CV0r3V3cR1Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
有人说自己有过类似成功的经验，只需要给GPT-4和Claude一个shell和一个简单的提示词。  
> 您是一名安全测试专家，并且可以访问Kali Linux沙箱。您需要彻底地测试安全漏洞。您已被允许使用任何工具或技术，你认为适合完成这项任务。使用任何kali linux工具来查找和探测漏洞。您可以使用nmap、nikto、sqlmap、burp suite、metasploit等工具来查找和利用漏洞。您还可以使用您认为合适的任何其他工具或技术来完成此任务。不要提供报告，继续尝试利用漏洞，直到您确信已经找到并尝试了所有漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu38lPpsb8yeKw4dyr764B5LcU9YVjSyIpUJGibwMJgTy7MuCaWfMFqNSw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
还有人建议补充测试：  
> 如果合法的话，应该给这个智能体提供Metasploit和发布到PacketstormSecuity的内容，当CVE中没有任何风险缓解措施时，它能否超越利用并提出多种风险等级的缓解措施？  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3Uo9u1XbN3zA0YJ9RD1Q0Tmw7hcdd3dEhI1pE8uCbnupvCG7aWjagibA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
当然还有人担心，这研究估计让脚本小子（对技能不纯熟黑客的黑称）乐开花了，也让公司更加重视安全问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YicUhk5aAGtDgzfrZ0UMksQ4AxS2T7fu3OGJMG9TY4lBqOv7TicvmicFtvIZVouG6j6DXKPdzPJbGD133LgibFSrug/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
考虑到OpenAI已经知晓了这项研究，后续或许会看到相应的安全提升？你觉得呢？  
  
  
编辑：陈十九  
  
审核：商密君  
  
**征文启事**  
  
大家好，为了更好地促进同业间学术交流，商密君现开启征文活动，只要你对商用密码、网络安全、数据加密等有自己的独到见解和想法，都可以积极向商密君投稿，商密君一定将您的声音传递给更多的人。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXNcXmbiaiaCljdXpwzOEQ9QTBXMibM6rZTOnbTSwTmCXncQLria2vuLGxn8QPtznzBc0as8vBxWIjrWxQ/640?wx_fmt=jpeg "")  
  
来源： 量子位  
  
注：内容均来源于互联网，版权归作者所有，如有侵权，请联系告知，我们将尽快处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXOdeQx0thlyozF2swQTEN9iaaBNDG0jTKfAgqgdesve8x5IEWNvYxjF6sAWjO1TPCZVsWd0oiaDn3uw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMyyClGk1cttkSBbJicAn5drpXEbFIeChG9IkrslYEylRF4Z6KNaxNafDwr5ibcYaZXdnveQCNIr5kw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaMcJkA69QYZ9T4jmc3fdN6EA7Qq9A8E3RWcTKhxVEU1QjqOgrJMu2Qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaiaRXdw4BFsc7MxzkVZaKGgtjWA5GKtUfm3hlgzsBtjJ0mnh9QibeFOGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaeiaNlRO9954g4VS87icD7KQdxzokTGDIjmCJA563IwfStoFzPUaliauXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点在看  
  

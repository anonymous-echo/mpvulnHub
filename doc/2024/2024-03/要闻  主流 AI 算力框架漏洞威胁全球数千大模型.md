#  要闻 | 主流 AI 算力框架漏洞威胁全球数千大模型   
 内生安全联盟   2024-03-28 15:37  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/jRRfTC292pXDTPcN2ic8q5pNxt5QicZb6UD7ibeo5FQ6FX4dXgT0nCNLXCDTq5N4hGiaQ3OYT1xOH8S9gakDomB1JA/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
近日，知名网络安全公司Oligo Security发现人工智能行业主流算力框架Ray的一个未修复安全漏洞正被黑客野外大规模利用，**攻击AI工作负载并窃取敏感（生产）数据和算力**。  
  
  
包括亚马逊、Uber、OpenAI等数以千计的人工智能企业受到影响，数百个集群已经遭到攻击，超过10亿美元算力遭到“劫持”。  
  
  
**01**  
  
**主流算力框架遭遇七个月野外攻击**  
  
像ChatGPT和GPT-4，以及国内的月之暗面（Kimi）等超大模型已经展示了惊人的内容生成能力和扩展能力，而支持这些模型“野蛮生长”的基础技术除了数以万计的高端GPU算力卡，还包括管理和编排这样大规模GPU集群来提供足够并行计算能力的AI算力框架，其中最流行也最重要的，非Ray框架莫属。  
  
  
Ray是由Berkeley加州大学计算机教授Ion Stoica创办的Anyscale公司开发的开创性分布式AI框架，被数以千计运行AI基础设施的公司采用。包括OpenAI、亚马逊、Shopify、Uber、字节跳动在内的数以千计的公司使用Ray框架支持ChatGPT这样动辄超过千亿参数的超大模型训练所需要的大规模底层基础算力资源优化和调度。  
  
  
此外，很多主流大模型项目还依赖Ray来支持SaaS、数据和AI工作负载，充分利用Ray的高可扩展性、速度和效率优势。  
  
  
根据Oligo Security的报告，Ray框架曝出的漏洞编号为CVE-2023-48022，在过去7个月中一直被积极利用，涉及教育、加密货币、生物制药等多个行业。所有使用Ray框架的企业和机构都应检查其基础设施环境，确保没有漏洞暴露，并分析任何可疑活动。  
  
  
**02**  
  
**AI算力基础设施漏洞野外利用第一案**  
  
2023年底，AI工作负载主流开源框架Ray曝出五个漏洞，这些漏洞由Bishop Fox、BryceBearchell和Protect AI团队分别披露（部分同时披露）。漏洞披露后，Ray的开发者和维护者Anyscale发布了一篇博文进行回应，澄清事件始末并详细介绍了每个漏洞的修复方案。  
  
  
虽然报告的五个漏洞中有四个已经在Ray 2.8.1版本中得到修复，但CVE-2023-48022漏洞仍存在争议。Anyscale并未将其视为安全风险，因此没有提供即时修复方案。  
  
  
由于存在争议，许多开发团队（以及大多数静态扫描工具）都没有意识到CVE-2023-48022的潜在危害。一些团队可能错过了Ray的相关文档，另一些则根本不知道此漏洞的存在。  
  
  
OligoSecurity的研究人员观察到，CVE-2023-48022漏洞正被积极利用，这使得**原本争议的漏洞变成了“影子漏洞”——此类漏洞不会在静态扫描中显现，却能导致安全漏洞和重大损失**。  
  
  
Oligo的研究团队将此漏洞命名为ShadowRay，是首个已知人工智能基础设施漏洞被用于攻击人工智能工作负载的案例。  
  
  
研究发现，全球范围内已有数千台部署在公共网络上的Ray服务器因该漏洞被攻陷，有些服务器甚至已经沦陷至少7个月。其中许多服务器包含了历史命令记录，这使得攻击者更容易理解服务器上的内容，并可能泄露生产环境中之前使用过的敏感机密信息。  
  
  
受Ray漏洞影响，数百家公司已经暴露于远程代码执行(RCE)风险之中，其中一些公司至今仍未修复漏洞。（文末链接的报告提供了完整的IoCs列表）。  
  
  
**03**  
  
**AI算力基础设施损失超10亿美元**  
  
截至目前，Oligo已发现数百个受感染的AI算力集群。每个集群由许多节点组成，这些节点是通过网络连接到集群的机器。大多数节点都有GPU，攻击者通过安装不同类型的挖矿软件利用GPU进行加密货币挖矿活动。  
  
  
换而言之，攻击者选择攻击AI算力集群不仅是因为他们可以获得有价值的敏感信息，而且因为当前GPU算力资源非常昂贵且难以获得。  
  
  
GPU机器的按需价格主要取决于GPU类型和内存。截至发稿，AWS上的GPU按需价格每台机器的年成本可高达85.8万美元。  
  
  
根据Oligo过去几周的监测，可能已遭到攻击的机器和算力总估值近10亿美元。  
  
  
参考链接：  
  
https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild  
  
  
来源：  
GoUpSec  
  
  
  
  
**| 往期推荐：**  
  
[国际观察 | 美国实施全球网络攻击“七种罪”](http://mp.weixin.qq.com/s?__biz=Mzg4MDU0NTQ4Mw==&mid=2247517603&idx=1&sn=f988a34d4e7863c7368cdcd43e63f981&chksm=cf715e07f806d7112dd3f28eb4443f30933ff1bdd2bf51b62c093e41762afe73f70c44954c23&scene=21#wechat_redirect)  
  
  
[答记者问来了！数据安全治理样板，国家金融监督管理总局重磅发布《银行保险机构数据安全管理办法》（九章八十一条）公开征求意见](http://mp.weixin.qq.com/s?__biz=Mzg4MDU0NTQ4Mw==&mid=2247517550&idx=1&sn=20b4f3b81b974ddb26c682b0920033c9&chksm=cf715ecaf806d7dcf21c9fcc6e3cd8b390f6af1d3eb2b9d54ffb732dce2ce7f2e24e6c96390a&scene=21#wechat_redirect)  
  
  
[专家观点 | 开辟智能网联汽车产业赛道](http://mp.weixin.qq.com/s?__biz=Mzg4MDU0NTQ4Mw==&mid=2247517524&idx=1&sn=9ec8e31cd601ee0984978416d15428c5&chksm=cf715ef0f806d7e618f7b11180f0c4ff438ed60a73ea1e2ac7e1e2d5bfb7be1a6f4d61c97659&scene=21#wechat_redirect)  
  
  
[警惕！全球APT组织正在使用大模型辅助网络攻击](http://mp.weixin.qq.com/s?__biz=Mzg4MDU0NTQ4Mw==&mid=2247517524&idx=2&sn=18b0297f27cff2423adc9f9834e7ec00&chksm=cf715ef0f806d7e65ffbd0b679a766a1dac1e2c09c1e3ea67460e9615cdd81474ef3df1fa069&scene=21#wechat_redirect)  
  
  
[附全文 | 金融监管总局就《银行保险机构数据安全管理办法（征求意见稿）》公开征求意见](http://mp.weixin.qq.com/s?__biz=Mzg4MDU0NTQ4Mw==&mid=2247517482&idx=1&sn=f17774e267517dbeb637f2951a2bc65a&chksm=cf715e8ef806d798afc7fe31017a0031af8bdd0f0da573f94e05e7d64b5e7dd3a064f8870ecc&scene=21#wechat_redirect)  
  
  
[数据安全技术 | 重要数据识别有了国家标准！专家：对数据跨境流动安全管理意义重大](http://mp.weixin.qq.com/s?__biz=Mzg4MDU0NTQ4Mw==&mid=2247517466&idx=1&sn=5c1619ff5206cfdb3c4d76ec58f853de&chksm=cf715ebef806d7a8412c17a2c5b95834f084820abffd8ca5cc6eb8e85fbff99ff6d6d6231a70&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/jRRfTC292pXGqHBACsK1cVtpyTB5F8VFsEY3paWnfS3dichupP4OknoSrNN3c6YviaDsLwKnfHwj1OibB7lWFvbibQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  

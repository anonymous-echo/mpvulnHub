#  安全事件运营SOP：接收漏洞事件   
原创 aerfa21  我的安全视界观   2023-06-18 18:18  
  
在开篇《安全事件运营SOP【1】安全事件概述》中，介绍了安全事件的定义、分级、处置原则及处置流程。当发生某类安全事件时，该如何快速处置？以及如何保证不同人员处置的效果都达标？安全事件的种类虽然繁多，但是处理起来并非无据可循。为了解决上述两个问题，同时提升工作效率和降低安全风险。经过大量的运营处置实践，总结出以下常见的处置标准操作程序（SOP）。  
  
  
本文将从基础概念、运营处置、内部响应实现和事件处置策略四个维度，对接收漏洞事件运营SOP进行阐述。  
由于作者所处平台及个人视野有限，总结出的SOP虽然经过大量重复的操作、总结及提炼，但仍会存在错误或不足，请读者同行们不吝赐教，这也是分享该系列实践的初衷。  
  
         ![](https://mmbiz.qpic.cn/mmbiz_png/UQ8MSNOhDKY5A00ZlDCobHwGzuR79OWR9JvC5123QiaDT9uHrkowRchOfJibVyCJdHDSJicC620loEn8OUmdhasUA/640?wx_fmt=png "")  
  
  
            
  
          
  
01  
  
—  
  
**基础概念**  
  
    
  
在企业网络安全运营中，有一类事情可能不太被重视，但却常会遇到，如果处置不当可能会给公司带来比较大的麻烦 - - 接收漏洞事件。  
之所以称之为安全事件，是因为存在不可控因素，处置时需要考虑的范围已经超过漏洞原理本身，被人利用可能给社会或公司带来负面的影响。  
  
            
## 1.1 接收渠道分类    
  
漏洞接收事件的渠道可以分为内部和外部两类，可能会有疑问：内部渠道为什么会算进来，以及内部渠道是指SDLC中发现的漏洞吗？从安全事件的定义来看，内部发现的漏洞也有可能导致负面影响，不过概率会比外部的低。内部的漏洞事件是指：非安全部门  
直接  
发现的漏洞。比如安全部门发起的SRC奖金悬赏活动收到的漏洞、安全公司有非常多懂攻防的员工、开发也可能对安全比较感兴趣从而提交漏洞…这并非他们的本职工作，所以也可以算作内部的“外部人员”，漏洞在他们手里就有可能导致事件。  
  
            
## 1.2 常见接收渠道    
  
内部渠道相对可控，外部就比较被动了。不仅不能清楚何时会以何种方式被通知有漏洞，还可能会被各种要求，比如有反馈要求、时限要求、处置动作说明、责令整改等。在外部的漏洞接收渠道中，包括国家级的漏洞库或平台、行业监管单位下发漏洞、民间漏洞收集相关平台，前两者会得到明确的漏洞通知，最后一种却比较艰难，因为民间平台不会通知企业、可能得通过白帽关系等才能弄清楚漏洞。以下为漏洞接收事件的常见渠道：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UQ8MSNOhDKY5A00ZlDCobHwGzuR79OWReFiaIKS3PMibR4llibYFicfWeRn1F0d9BbckfsBPtQJWypzzspJvOs7yng/640?wx_fmt=png "")  
  
   
  
02  
  
—  
  
安全运营SOP  
  
  
面对“在野”的漏洞细节，无论是何种渠道的漏洞事件，都需要快速响应与处置，通常可以参照以下流程：  
## 2.1 分析研判    
  
在对应的环境进行漏洞信息验证，测试漏洞是否真实存在、以及判断被利用带来的影响。针对监管单位下发的漏洞，即使不存在也会被要求按照既定格式、时间进行正式回复。  
  
            
## 2.2 风险定级    
  
除了漏洞的利用难度、被利用带来的直接影响，还应该从外部舆论、产品在客户侧的覆盖面等方面，全面对漏洞事件进行评估，从而采取不同的应对措施。  
  
            
## 2.3 修复验证    
  
安全人员组织对应的产品线进行漏洞修复，在修复之后进行验证，验证漏洞是否被彻底修复、漏洞修复方法是否可能被bypass、漏洞修复是否带来新的安全问题。在确认无误的情况下，将验证结果告知产线，产线输出修复方案和经过验证的补丁。  
  
            
## 2.4 处置反馈    
  
漏洞修复后，对各来源渠道需要有明确、及时的答复，如在SRC上确认漏洞并定级给奖金、回复修复计划给监管单位/国家级漏洞库、记录并给与内部提交人一定奖励、对反馈漏洞的客户进行修复与致谢。  
  
            
## 2.5 复盘总结    
  
针对漏洞接收、处置、修复、验证、回复等整个环节进行总结，反向来优化现有标准与现有流程；对漏洞产生的原因进行分析，反向加强安全测试和内部安全管控。  
  
            
## 2.6 SOP流程图    
  
2.1 – 2.5  
描述的内容，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UQ8MSNOhDKY5A00ZlDCobHwGzuR79OWR6aDI0OPjhIKMiaRicIapOql4KSjfVo6UoEy4u4EzZffLK8AU0gcZNtoQ/640?wx_fmt=png "")  
  
注：图中的监管单位，默认包括国家级漏洞库、平台和相关行业的监管单位。对于民间的漏洞库或平台，由于没有固定的方式暂不纳入  
SOP  
。  
  
      
  
  
   
  
03  
  
—  
  
**内部响应实现**  
  
       
  
漏洞事件的处置其实是一件比较复杂的工作，仅凭安全部门是做不好的。比如漏洞事件需要与GA对接，事件在外部已经产生舆论，事件涉及到侵权，事件处置措施出现分歧无人拍板…  
  
## 3.1 事件响应组织    
  
不少公司已经建立了SRC/安全运营团队，对于安全技术运营方面没问题，但当遇到“漏洞”升级为“事件”时，则需要将团队扩大化。比如在成立公司级PSIRT（Product Security Incident Response Team，产品安全应急响应小组-更适合于非SaaS化的产品及服务），  
由研发、安全、技术服务、客户经理  
、法务、公关  
等各岗位专家组成，覆盖供应链、研发、工程交付及技术服务等各环节。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UQ8MSNOhDKY5A00ZlDCobHwGzuR79OWR36IKu1kfQnzXLHXzfoTQJO5Jic2n6sx3T4ic81kiaNFibv7h0pyIHyrLwA/640?wx_fmt=png "")  
  
同时设置领导小组和工作小组，领导小组负责产品安全事件的议事与决策，工作小组依据领导小组决策及职责分工进行工作落地。  
  
            
## 3.2 事件定级标准    
  
在2.2中，简要介绍了影响定级的要素，但对于每个因素的占比、事件的分级未提及。此处将针对这部分内容进一步说明：  
  
- 定级要素：  
从以往的经验来看，可以从产品重要程度、产品影响范围、社会舆论、漏洞利用条件、漏洞实际影响五方面，对漏洞事件进行定级，比例分别为10%、20%、30%、10和30%（长期运营的结果，没有标准参考）；  
  
  
- 事件分级：  
漏洞事件也分为四个等级，分别为红色特别重大事件（9.0-10.0分）、橙色重大事件（8.0-8.9分）、黄色较大事件（7.0-7.9分）和蓝色一般事件（3.0-6.9分），事件分数为定级要素的各项评分之和。  
  
  
  
  
在日常运营中，按照以上规  
则，对每个接收漏洞事件进行评分，就可以得到事件等级。附：某次接收漏洞事件的定级示例  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UQ8MSNOhDKY5A00ZlDCobHwGzuR79OWRqU3ibtiaaicuNic5l9oRXl6CoZKhHZUBdT92dN2z268eHHJNIudH7mbNDg/640?wx_fmt=png "")  
  
            
  
  
04  
  
—  
  
处置漏洞事件策略  
## 4.1 化被动为主动    
  
被动就是处理起来比较难受，与其被动的等待不如主动接收。当安全建设到一定程度（如主要安全基础设施已建设，进入运营阶段），可以从以下方面着手：  
  
- 按照平台的要求，主动注册账号：  
一般可以提供企业营业执照、企业邮箱、联系人等信息在漏洞库系统注册账号，后续收到漏洞信息能先在平台上看到，比起邮箱接收会提高时效性，减少被动感；  
  
  
  
- 加强自身安全性，积极减少漏洞：  
打铁还需自身硬，加强自身安全建设才是硬本事。自己发现的漏洞比别人多，别人发现的就少了；自己发现漏洞的速度比别人快，自己就不会那么被动；  
  
  
  
- 建立自有外部漏洞接收渠道和机制：  
自建SRC或使用托管的SRC服务，主动发起悬赏活动，也是一种常见的漏洞风险收敛措施。但前提得有预算，不一定适合于所有的公司，但一定是从外部收敛风险的好方法。  
  
            
## 4.2 按规及时反馈    
  
在处置外部接收的漏洞事件时，经常会碰到一些特殊的场景：  
- 内部已知的漏洞（内部安全测试发现、SRC已经发现），并对外已经发布补丁和公告信息，漏洞库下发通报；  
  
- 已退市多年的产品存在漏洞，也对外部发过下市通告，  
漏洞库下发通报…  
  
  
  
  
曾尝试过与漏洞库沟通，此类漏洞是否出具证明就直接在系统上关闭？但得到了否定的答案，须按照时限和格式进行邮件反馈。自此以后，内部建立SOP和SLA标准化处置每一次漏洞事件。  
  
            
## 4.3 对白帽子的呼吁    
  
除了上面撞洞的情况，还经常会有另一种情况：SRC前不久刚收到漏洞，怎么没过多长时间漏洞库就来通报了？仔细查看内容，所有的描述甚至连截图、涉及到的IP都一样。这很难不让人联想到一洞多投，价值最大化。  
  
  
虽然SRC声明：要求白帽子对提交的信息进行保密、禁止传播，但还是很难去约束。我们曾经也是一名白帽子，很理解白帽子挖洞付出的辛劳，故在漏洞审核时间响应速度、漏洞现金奖励、季度奖励、年度奖励方面投入很多。但换来的却还是多平台刷洞，这难免有点让人心寒。不过好在绝大多数白帽子能坚守住，高质量的漏洞也基本没出现过此类情况。在此，还是想趁机呼吁所有的白帽师傅：遵守SRC或平台的规则，做个正直诚信的人。  
  
  
  
  
**长按识别二维码，和我交流**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UQ8MSNOhDKblctsA0yeRibKPYm3JrocibHpmnImpp5E3gDUR6j8q87OlCMjKrnR3qlSQDsgA5xo5icUrQ7yRmGDnQ/640?wx_fmt=jpeg "")  
  
  
More...  
  
**--------- 安全运营 ---------**  
- [](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247485157&idx=1&sn=1ccc7733e09b8e4d9f72dedfa7ac0307&chksm=eb6c249ddc1bad8b8838a9c2fa3720c9e9f650fbb30cd5e989045b691e07d4148875e5377e94&scene=21#wechat_redirect)  
[安全事件运营SOP：webshell事件](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247485157&idx=1&sn=1ccc7733e09b8e4d9f72dedfa7ac0307&chksm=eb6c249ddc1bad8b8838a9c2fa3720c9e9f650fbb30cd5e989045b691e07d4148875e5377e94&scene=21#wechat_redirect)  
  
  
- [安全事件运营SOP：蜜罐告警](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247485135&idx=1&sn=e18a1ce832d2cbc493f3a7d1ce94fca1&chksm=eb6c24b7dc1bada1b2b0e35f5d0f112f723e9e982e049c30b7556813c057ed3492ef0ed54ec3&scene=21#wechat_redirect)  
  
  
- [安全事件运营SOP：网络攻击](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247485116&idx=1&sn=4891f628f141cadc056d61b1ad0a1a96&chksm=eb6c24c4dc1badd26dfe3617c6d7ca27f1c10e509915ef87074e7f9dcf74fef8b8e71c969d71&scene=21#wechat_redirect)  
  
  
- [安全事件运营SOP：钓鱼邮件](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247485082&idx=1&sn=666a267839c7759a116cce9ba5a6fd46&chksm=eb6c24e2dc1badf4d5d3c3f6876c0a1435ba66857706d982344400ce0b9a3b7f5995a3600354&scene=21#wechat_redirect)  
  
  
- [安全事件运营SOP：基于实践的安全事件简述](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247485045&idx=1&sn=7dc5bdb661462ce817e6498bf96850fb&chksm=eb6c240ddc1bad1bc8968ba192eafb4f6abb99a167298a3bdfff48dd69567fa93f7f0b836719&scene=21#wechat_redirect)  
  
  
- **企业级供应链投毒应急安全能力建设**  
  
- [应急能力提升：实战应急困境与突破](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484697&idx=1&sn=dff997e13495fdb3622e4bb8646b889b&chksm=eb6c2761dc1bae778997e1645757c0a6e9fed52db50ef64ca3af729e0a6327616b609ad78b6e&scene=21#wechat_redirect)  
  
  
- [应急能力提升：挖矿权限维持攻击模拟](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484823&idx=1&sn=69462ecc159cf0fb859cd6aba19dadee&chksm=eb6c27efdc1baef96531ce6ff7ab6aa633e36567c5884d68c428a25af8a2dc14a4d0f7eabff0&scene=21#wechat_redirect)  
  
  
- [应急能力提升：内网横向移动攻击模拟](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484887&idx=1&sn=25e229a4f57c0ff1fd929e9697cf73d0&chksm=eb6c27afdc1baeb98a17c1b8bc061fef11247aa805c0ee6981268b3d757cd5a851f796a2a2dd&scene=21#wechat_redirect)  
  
  
- [应急能力提升：实战应急响应经验](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484926&idx=1&sn=72029ad8277ac5f6546be9c222d8fef8&chksm=eb6c2786dc1bae90805cc5f3cf181c45ce13390a93f1cc76610c8a8d7d7d5c9c124f16eee74a&scene=21#wechat_redirect)  
  
  
- [应急能力提升：应急响应报告点评](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484940&idx=1&sn=41974bb0e67d03a48e3c66f758d51cca&chksm=eb6c2474dc1bad629679c71e1db8ab043f9bb8c92da0985fa11b0d9675fc276b35157df23d49&scene=21#wechat_redirect)  
  
  
- [应急能力提升：应急响应专题总结会](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484984&idx=1&sn=a940a3090a69255f9ce97f043a37627a&chksm=eb6c2440dc1bad5652e5a86a67b64700475a82729fc5446ac64b5c92dac3868354f870669de1&scene=21#wechat_redirect)  
  
  
- [应急响应：redis挖矿（防御篇）](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247483818&idx=1&sn=b6068877196e1c240003ade42b2d4b77&scene=21#wechat_redirect)  
  
  
- [应急响应：redis挖矿（攻击篇）](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247483843&idx=1&sn=80d08e5cd1949d9db4ed83d7cedf8fa1&scene=21#wechat_redirect)  
  
  
- **应急响应：redis挖矿（完结篇）**  
  
  
  
**--------- 软件安全 ---------**  
- [开篇](https://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484219&idx=1&sn=6ff469339838922b9010463eca27dce1&scene=21#wechat_redirect)  
  
  
- [安全培训](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484271&idx=1&sn=6ac52c337d700b0c37f1e9ad98bec24c&chksm=eb6c2117dc1ba8014d08f4cde5c8bba8368a6cb44305d32237ac826ee12e07583fb626286208&scene=21#wechat_redirect)  
  
  
- **安全需求**  
  
- [安全设计](https://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484328&idx=1&sn=bba34270246d8e01eb1f54e4a0605d00&scene=21#wechat_redirect)  
  
  
- **安全开发**  
  
- [安全测试](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484366&idx=1&sn=72cc4c6bcc5dde0b234cf5a2693d3970&chksm=eb6c21b6dc1ba8a0fa8640a1bc3a977cab84c4f50835b8b448ee9e3c0b1dc6d85ba256b46ce2&scene=21#wechat_redirect)  
  
  
- **安全审核**  
  
- **安全响应**  
  
- **完结篇（全系列paper下载）**  
  
- **浅谈安全产品的hvv安全之道**  
  
- **Shift Left在开发安全中的应用**  
  
**--------- 企业安全 ---------**  
- **企业安全建设需求**  
  
- **企业安全威胁简述**  
  
- **企业安全架构建设**  
  
- **企业安全项目-测试环境内网化**  
  
- **企业安全项目-Github信息泄露**  
  
- **企业安全项目-短信验证码安全**  
  
- **企业安全项目-前端绕过专项整改**  
  
- **业务安全之另类隐患**  
  
- [应用发布之安全隐患](https://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484196&idx=1&sn=aa495a9446351335496b3497b4344778&scene=21&token=2126588985&lang=zh_CN#wechat_redirect)  
  
  
- **甲方眼里的安全测试**  
  
- **基于堡垒机的自动化功能实践1**  
  
- [基于堡垒机的自动化功能实践2](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484282&idx=1&sn=928cd8afbba2a7fced744c410cc6f026&chksm=eb6c2102dc1ba814397da7d7e2222b3c175db36b16822abab6b9de6ccd0efbf7947bf9e30191&scene=21#wechat_redirect)  
  
  
- **基于堡垒机的自动化功能实践3**  
  
- **基于堡垒机的自动化功能实践4**  
  
- **Nmap操作系统探测技术浅析**  
  
- **漏洞情报调研**  
  
- **漏洞调研报告（非完整版）**  
  
- [从漏洞视角看敏捷安全](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484466&idx=1&sn=5935aeeffe873a30be650cc7d616a5ca&chksm=eb6c264adc1baf5c21291c4c630f26eb4197aa7743dfdec308fa057d503c4c5f59d2ec7edbb7&scene=21#wechat_redirect)  
  
  
- [从漏洞视角看敏捷安全](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484466&idx=1&sn=5935aeeffe873a30be650cc7d616a5ca&chksm=eb6c264adc1baf5c21291c4c630f26eb4197aa7743dfdec308fa057d503c4c5f59d2ec7edbb7&scene=21#wechat_redirect)  
  
  
**--------- 渗透测试 ---------**  
- **安全运维那些洞**  
  
- **安全业务那些洞**  
  
- **那个简单的威胁情报**  
  
- **Android APP数据存储安全**  
  
- **搜集SRC信息中的“技术活儿”**  
  
- **常规渗透瓶颈，发散思维突破**  
  
  
****  
**--------- 安全开发 ---------**  
- **python武器库**  
  
- **漏洞扫描器资产处理**  
  
- [python代码审计武器I](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484025&idx=1&sn=a2a6b9ca9f939c2459f438a649399589&scene=21#wechat_redirect)  
  
  
- [python代码审计武器II](https://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484106&idx=1&sn=fa39b33b28c97ce7f504af3263461d48&scene=21#wechat_redirect)  
  
  
- [Nodejs代码审计武器](https://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484075&idx=1&sn=98b45084cb5635b880c0626a8dce0930&scene=21#wechat_redirect)  
  
  
- **fortify漏洞的学习途径**  
  
  
  
**--------- 个人体验 ---------**  
- [如何学习这么多的安全文章（实践篇）](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484686&idx=1&sn=12bb6d99b3e127e33c523265fc4695d6&chksm=eb6c2776dc1bae60224437b199d0774ac64cf321774f44a4596370857af2ff7ce6b5935acfa4&scene=21#wechat_redirect)  
  
  
- [如何学习这么多的安全文章（理论篇）](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484635&idx=1&sn=aab8f0a3e93899323db37e19f98550d3&chksm=eb6c26a3dc1bafb5710d526486d64485329bdfd16499aa9f0d079a9105d0ddb6d18644be32fa&scene=21#wechat_redirect)  
  
  
- [漫谈在安全公司做内部安全的体验](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484556&idx=1&sn=8b09f6c75926cc10f3c68473adef2c56&chksm=eb6c26f4dc1bafe2620c0aa23aa62443fa00a789e4b14cff0317eded78d6e6e46ac82f94d9cd&scene=21#wechat_redirect)  
  
  
- [C3安全峰会参后感](https://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484126&idx=1&sn=3c9a2d1e36ef0024f47eb5cd6c848c72&scene=21#wechat_redirect)  
  
  
- [提高认知效率秘籍](http://mp.weixin.qq.com/s?__biz=MzI3Njk2OTIzOQ==&mid=2247484202&idx=1&sn=2503f771d5240c97980d41243126f9ec&chksm=eb6c2152dc1ba844d8e12748d32bc38cb5475356a39e72413fd1f691308233b7f21e4b71f30f&scene=21#wechat_redirect)  
  
  
            
  

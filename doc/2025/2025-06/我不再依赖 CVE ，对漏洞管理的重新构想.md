#  我不再依赖 CVE ，对漏洞管理的重新构想   
原创 刘宸宇  数世咨询   2025-06-05 10:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Y9btpvDIDqojUmoC2G9zGDiaSicSdMDDCjjzqHNYvegNe3GhLJamRaH46iblxuejNB3SiaRbvicA7nqnlMpbyMouTZw/640?wx_fmt=png&from=appmsg "")  
  
疲于奔命的漏洞管理  
  
漏洞管理的天然滞后性，加上策略和流程的延迟，让安全团队疲于奔命。在能力有限的现实下，要立即修复所有漏洞只会让团队不堪重负。我们的漏洞运营中心 （VOC） 数据集分析团队在 68,500 个客户资产中发现了 1,337,797 个安全漏洞。其中有CVE编号的 32,585 个漏洞中，有 10,014 个漏洞 CVSS 评分为 8 分或更高。所有漏洞中，涉及外部资产的CVE编号漏洞有 11,605 个，内部资产这一数据为 31,966 个。面对如此数量的 CVE，有些 CVE 未打补丁导致被攻击利用也就不足为奇了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Y9btpvDIDqojUmoC2G9zGDiaSicSdMDDCjE8rmCZI9l53GczTu5Edd0VpnFcFXAlfZr3QqXpVx5d4qXJ9vfB8zFw/640?wx_fmt=jpeg&from=appmsg "")  
  
为什么我们会陷入这种情况，可以做些什么，有没有更好的方法？  
  
我们将探讨漏洞管理的现状，如何通过威胁情报、可利用性、检查统计概率来确定漏洞的优先级，并简要讨论相关的风险。最后，我们将考虑什么样的解决方案可以最大限度地减少漏洞影响，同时为管理团队提供事件响应的灵活性。  
  
不再依赖 CVE  
  
西方国家和组织使用通用漏洞披露 （CVE） 和通用漏洞评分系统 （CVSS） 来跟踪和评级漏洞，由 MITRE 和 NIST 等美国政府资助的机构监督。截至 2024 年 9 月，已运转了 25 年的 CVE 计划已发布超过 264,000 个 CVE，截止到 2025 年 4 月 15 日，包括“拒绝”或“延期”在内的CVE 总数增加到约 290,000 个。  
  
补充阅读：[CVE 漏洞项目及时"续命",11个月后生死难料](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247538513&idx=1&sn=2f03dab7cbc7139e09be0d33a4ddefde&scene=21#wechat_redirect)  
  
  
NIST 的国家漏洞数据库 （NVD） 依靠 CVE 编号机构 （CNA） 来记录带有初始 CVSS 评分的 CVE，这有助于后续流程的扩展，但也引入了偏差。由于研究人员和供应商在漏洞影响、漏洞相关性和漏洞准确性方面的分歧，严重漏洞的披露过程非常复杂，进而影响着更为广泛的社区 。  
  
由于 2024 年 3 月以来官方的各种不作为，截止到 2025 年 4 月，NVD 已经积压了超过 24,000 个未补充信息的 CVE漏洞。尽管漏洞报告持续不断，但 CVE 信息补充工作暂时停止，这突出地表明了该系统的脆弱性。正是“临时暂停”导致了至今尚未清理的大量积压工作。  
  
2025 年 4 月 15 日，MITRE 宣布美国国土安全部将不再与其续签合同，这将直接影响 CVE 计划[15]。这给 CVE 的未来以及它将如何影响网络安全从业者带来了很多不确定性。幸运的是，鉴于社区和行业的强烈反应，CVE 计划的资金得到了延长。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Y9btpvDIDqojUmoC2G9zGDiaSicSdMDDCjIYDy9YAvHSmkk9M0sibPqCjatWUicx3NNpZ1ib2Jswu7Rxcavvjgkichvw/640?wx_fmt=jpeg&from=appmsg "")  
  
CVE 和 NVD 并不是漏洞情报的唯一来源。许多组织（包括我们）都开发了独立产品，这些产品跟踪的漏洞远多于 MITRE 的 CVE 和 NIST 的 NVD 计划。  
  
自 2009 年以来，中国一直在运营自己的漏洞数据库 CNNVD ，尽管政治障碍使合作的可能性不大，但这仍然可能是一个宝贵的技术资源 。此外，并非所有漏洞都会立即披露，这会导致盲区的产生--有些漏洞被利用了却没有被检测到 -- 即所谓的 0 day漏洞。  
  
2023 年，谷歌的威胁分析小组 （TAG） 和 Mandiant 确认了 97 个 0day 漏洞，主要影响移动设备、操作系统、浏览器和其他应用程序。与此同时，CVE 列表中只有大约 6% 的漏洞被利用过 ，2022 年的一项研究表明，一半的组织机构每月只修补 15.5% 或更少的漏洞 。  
  
虽然 CVE 对安全管理人员至关重要，但它是一个不完美的志愿者系统，既不受全球监管，也未得到普遍采用。  
  
因此，这篇文章旨在探讨我们如何在日常运营中减少对它的依赖。  
  
基于威胁情报的决策  
  
尽管存在缺点，但 CVE 系统仍然提供了一些可能影响安全性的宝贵漏洞情报。但是，由于需要解决的 CVE 如此之多，我们必须优先考虑最有可能被威胁行为者利用的 CVE。  
  
漏洞利用预测评分系统 （EPSS） 由事件响应和安全团队论坛 （FIRST） 特别兴趣小组（SIG） 开发，有助于预测漏洞在野被利用的可能性。借助 EPSS 情报，安全主管可以优先修补尽可能多的 CVE 以实现广泛的覆盖范围，或者专注于关键漏洞以最大限度地提高效率并防止漏洞利用。这两种方法都有优点和缺点。  
  
为了描述覆盖率和效率之间的平衡，我们需要两个数据集：一个代表潜在的补丁（VOC 数据集），另一个代表被积极利用的漏洞，其中包括 CISA KEV [10]、道德黑客调查结果，以及来自 CERT 漏洞情报监测服务 [12]的数据。  
  
EPSS 阈值可被用来根据 CVE 在野被利用的可能性来确定需要优先修复的一组漏洞。修复集和被利用漏洞集之间的交集，可用于计算所选策略的 Efficiency（效率）、Coverage（覆盖率）和 Effort（工作量）。  
  
EPSS 预测的是漏洞在某个区域被利用的可能性，而不是在任何特定系统上被利用的可能性。当然，这个概率可以被进一步“推算”。例如，抛一枚硬币有 50% 的概率正面朝上，但抛掷 10 枚硬币会把“至少一枚硬币正面朝上”的概率提高到 99.9%。这种“推算”是使用补码规则 计算的，该规则通过从 1 中减去失败的几率来找到所需结果的概率。  
  
正如 FIRST 所解释的那样，“EPSS 可以预测特定漏洞被利用的概率，并且可以通过计算至少一个事件发生的可能性从而将这一概率扩展至服务器、子网乃至整个企业面临的可能威胁。”  
  
借助 EPSS，我们可以使用补码规则计算得出一个漏洞列表中至少有一个漏洞被利用的可能性。  
  
以一组数据为例。我们分析了漏洞运营中心（VOC） 扫描数据中某客户公共管理部门相关的 397 个漏洞。如下图所示，列表中大多数漏洞的 EPSS 得分较低，直到第 276 个漏洞开始，其 EPSS 分值急剧上升。图表上还显示了使用补码规则“推算”出的漏洞利用概率，当考虑前 264 个漏洞的利用可能性时，推算概率实际上就已达到 100%。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Y9btpvDIDqojUmoC2G9zGDiaSicSdMDDCjR7doW5Ko36kYmE1Wm6jM4TFuCl4B2QM7icZ3hRMFChb63UWQgbDP5HQ/640?wx_fmt=jpeg&from=appmsg "")  
  
如图表上的 EPSS 推算曲线（左侧蓝色）所示，随着列入考虑的 CVE 增多，其中一个 CVE 被在野利用的推算概率会迅速增加。当列入考虑的不同 CVE 数量增加至265个时，其中一个漏洞被在野利用的可能性超过 99%。在考虑任何具有高 EPSS 的单个漏洞之前（黄色曲线），概率就会达到此级别。当推算 EPSS 值超过 99%（位置 260 前后）时，单个漏洞的最大 EPSS 仍低于 11% （0.11）。  
  
上述这个示例，展示的是暴露在互联网侧的漏洞情况，来源于真实的客户端数据，显示出随着潜在包含漏洞的系统数量的增加，确定漏洞的优先级会变得多么困难。  
  
EPSS 给出了漏洞在野被利用的概率，这对防御者很有帮助，不仅如此，我们可以看到，当涉及多个漏洞时，这种概率会以多快的速度增加。如果漏洞足够多，即使单个 EPSS 分数较低，也确实有可能被利用。  
  
这就好像天气预报预测“下雨的概率”一样，区域越大，某处下雨的可能性就越大。反之同理，将漏洞利用的可能性降至接近零的程度是不可能的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Y9btpvDIDqojUmoC2G9zGDiaSicSdMDDCjwXHATmndLDtvmCdf0abt6gVXLvAtibolD2ozzDIzy57HM7Np8lZMOQQ/640?wx_fmt=jpeg&from=appmsg "")  
  
攻击者赔率  
  
我们已经确定了三个关键事实，必须将其整合到我们对漏洞管理流程的检查中：  
  
●攻击者并不关注特定的漏洞；他们的目标是破坏系统。  
  
●  
利用漏洞并不是唯一的入侵途径。  
  
●  
攻击者的技能水平与耐心程度各不相同。  
  
这些因素使我们能够扩展对 EPSS 及其概率的分析，以考虑攻击者破坏某个特定系统的可能性，然后对其进行“推算”以确定破坏网络中某些系统的可能性，后者可能让攻击者获得进一步对其余系统的访问权限。  
  
我们可以假设每个黑客都有一定的“概率”来破坏系统，这个概率基于他们的技能、经验、工具和时间可能会有所增加。然后，我们可以继续应用概率推算来评估攻击者在更广泛的计算机环境中的成功率。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Y9btpvDIDqojUmoC2G9zGDiaSicSdMDDCjGFcoKlGlTO68deNImpFu5gzdDMO88HPxfLBlwLazDfb9bfMyBa4a4w/640?wx_fmt=jpeg&from=appmsg "")  
  
假设有一个耐心的、未被发现的黑客，从统计上讲，需要多少次尝试才能攻破系统获得访问权限？要回答这个问题，需要应用一个重新设计的二项分布，其形式为以下方程 ：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Y9btpvDIDqojUmoC2G9zGDiaSicSdMDDCjUdvIt1UtMboFibpjTnAWnNM2QiaxLzXZgUxELghXz7HcZQib3f6licBFSw/640?wx_fmt=jpeg&from=appmsg "")  
  
使用这个方程，我们可以估算出特定技能水平的攻击者需要多少次尝试。例如，如果攻击者 A1 每个系统的成功率为 5%（20 分之一），则他们需要以多达 180 个系统为目标，才能有 99.99% 的成功把握。  
  
另一个成功率为 10%（10 分之一）的攻击者 A2 需要大约 88 个目标才能确保至少一次成功，而一个更熟练的攻击者 A3 的成功率为 20%（5 分之一），同样的概率只需要大约 42 个目标。  
  
这些概率，是攻击者可能在第一次尝试时成功，或者需要多次尝试才能达到预期的成功率。为了评估实际影响，我们调查了团队中的高级渗透测试人员，他们估计自己针对任意互联网目标的成功率约为 30%。  
  
假设熟练的攻击者有 5% 到 40% 的机会攻破一台机器，现在我们可以估算出需要多少个目标才能保证一次成功的入侵。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Y9btpvDIDqojUmoC2G9zGDiaSicSdMDDCjOHtyaqrzg5ibT2UfUE8TdPIYHsY4b05MHOge2OogU2k5qWV39xoZicZA/640?wx_fmt=jpeg&from=appmsg "")  
  
结论是惊人的：只需 100 个潜在目标，即使是中等技能的攻击者也几乎肯定会至少成功一次。在典型的企业中，这种“成功”并不难实现，攻击者通常具备广泛的网络访问权限，可以覆盖数千台计算机。  
  
对漏洞管理的重新构想  
  
对于未来，我们需要构想一个不受单个系统影响的环境和架构。在短期内，我们认为现有的漏洞管理方法必须改变。  
  
当前的漏洞管理方法植根于它的名字：“漏洞”（由 CVE、CVSS、EPSS、错误配置、错误等定义）及“管理”。然而，我们无法控制 CVE 的数量、披露速度或重要程度，这导致我们只能对混乱的新漏洞疲于奔命。  
  
EPSS 帮助我们确定可能被利用的漏洞的优先级，这些漏洞代表着真正的威胁，这迫使我们始终处于被动响应的状态。虽然缓解措施解决的是漏洞，但我们的应对措施实际上应对的是威胁，因此，此过程应称为威胁缓解。  
  
如前所述，从统计学上讲，仅靠对漏洞情报做出反应是不可能有效应对大型企业面临的威胁。降低风险是我们能做的最好的事情。因为风险源于资产、漏洞、威胁三要素。降低风险的过程，也是我们发现更多可控领域并对其管理和缓解的过程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Y9btpvDIDqojUmoC2G9zGDiaSicSdMDDCj3TvibPuSOdS0IUBCQnkcRb218fYicFiccwviaIBLOO4w3SUErzTFOgZoYg/640?wx_fmt=jpeg&from=appmsg "")  
  
威胁缓解  
  
威胁缓解是一个动态的、持续的过程，涉及识别威胁、评估其相关性并采取措施缓解威胁。响应可能包括漏洞修复、重新配置、筛选、添加补偿控件，甚至将易受攻击的系统卸载。EPSS 是一种有价值的工具，可补充更多威胁和漏洞的情报来源。  
  
但是，概率的推算性质使得 EPSS 在大型内部环境中不太有用。由于 EPSS 侧重于可能被“在野”利用的漏洞，因此它最适用于直接暴露在互联网上的系统。因此，威胁缓解工作应主要针对那些暴露在外的系统。  
  
降低风险  
  
网络风险是资产、脆弱性和威胁的共同产物。虽然“威胁”在很大程度上超出了我们的控制范围，但在大型环境中修补特定漏洞并不会显著降低泄露风险。因此，降低风险应侧重于三个关键工作：  
  
1.减少攻击面：随着入侵的可能性随着资产规模的增加而增加，可以通过缩小攻击面来降低入侵。一个关键的优先事项是识别和删除未托管或不必要的面向互联网的系统。  
  
2.限制影响：就像朗伯定律（Lambert's law）中描述的光传播会衰减一样，攻击者在访问和穿越不同网络层级、权限边界、应用和数据区域时，其造成的影响也应受到限制。零信任架构为这一目标提供了一个实用的参考模型。  
  
3.改进基线：系统性地减少漏洞的总数和严重性，而不是在报告或发现特定漏洞时才关注这些漏洞，从而降低被攻破的风险。这种方法优先考虑效率和投资回报，忽略当前的严重威胁，有利于长期降低风险。  
  
通过将威胁缓解与风险降低分开，我们可以摆脱被迫对特定威胁做出反应的死循环，专注于更高效的战略方法，为其他优先事项腾出资源。  
  
高效的方法  
  
可以系统地采用这种方法来优化资源。重点从被动的“漏洞管理” 转移到主动的设计、实施和验证弹性架构与基准配置。一旦安全部门设置好这些基线，IT 就可以接管实施和维护。  
  
这里的关键是，内部系统打补丁的 “触发条件” 应当是一个预先设定好的、与系统所有者达成一致的计划，目的是升级到新的、经批准的基线。这种方法肯定比不断追逐最新的漏洞要小得多，效率也更高。  
  
当然，漏洞扫描对于创建准确的资产清单和识别不合规的系统仍然很重要。在现有的标准化流程中，漏洞扫描应当是支撑角色，而非发起角色。  
  
塑造未来  
  
大量随机发现、报告的漏洞，以 CVE、CVSS 和 EPSS 等方式给我们的人员、流程和技术带来着持续压力。二十多年来，尽管我们一直以相同的方式有效地进行漏洞管理，并取得了一定的成功。  
  
但，现在是时候了，重新构想如何设计、构建和维护我们的漏洞管理。  
  
新理念模板  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oA3dHkeddXhJ3jib0k7rGnEegZibZniccsaghqFkMzPa3rJgf7Upv76J2JhOLPsYoWOqZbZNFmXcYnt8nhBQCf2gA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VpOHYBMQuCddPmS5icYleAHBrHzTb1Ptuuyo36pTFVgmSyFUvXRMibFob0q5ibkP588HsclbQkAm4icQX3HoJ63log/640?wx_fmt=png "")  
  
2030 年以后的安全理念需要考虑以下关键因素：  
  
从源头开始  
  
  
人为因素  
  
◆利用人类的优点，预测人类的弱点。  
  
◆获得高级管理层和高管的支持。  
  
◆成为推动者，而不是阻碍者。  
  
  
基于威胁的决策  
  
◆从事件中学习，重点关注被攻击者利用的部分。  
  
◆  
基于现有能力，使用新的理念增强修复效果。  
  
  
威胁建模与模拟  
  
◆  
使用威胁模型了解潜在的攻击路径。  
  
◆  
通过道德黑客攻击，测试您的环境是否能够抵御真正的威胁。  
  
  
系统架构与设计  
  
◆  
应用威胁模型和模拟来验证新系统中的假设。  
  
◆  
系统地减少攻击面。  
  
◆  
通过审查现有系统来加强深度防御。  
  
◆  
将 SASE 和零信任视为理念，而不仅仅是技术。  
  
  
需求驱动的默认安全  
（译注：原文为Secure by Demand / Default ，指从需求端出发，将安全作为一种内在需求融入企业运营的各个方面，从默认设置上保证安全）  
  
◆  
将安全列入企业正式策略，将安全性嵌入到企业文化中。  
  
◆  
确保供应商拥有积极的安全改进计划。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qovj3UeGdqzuKO84egVLICib5WCduqaMDVh8HzSPvWuJJM6wz4Gh7yL8v4qoaslXS1uQzstzx4kGic8Kc3pbPBicQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vuDdwuxAtiaGvKZOHYFlxdafcefFsdiaibmvv9B3gyxBfxleCC9Mw1KNcwbYgWM14I88IlCM5SKH00oeoZThichgcQ/640?wx_fmt=png "")  
  
  
注：本文由 Orange Cyberdefense 的高级安全研究员 Wicus Ross 专业撰写。  
  
  
* 本文为小眼儿编译，原文地址：  
https://thehackernews.com/2025/05/beyond-vulnerability-management-cves.html  
  
注：图片均来源于网络，无法联系到版权持有者。如有侵权，请与后台联系，做删除处理。  
  
— 【 THE END 】—  
  
🎉 大家期盼很久的#  
**数字安全交流群**  
来了！快来加入我们的粉丝群吧！  
  
🎁**多种报告，产业趋势、技术趋势**  
  
这里汇聚了行业内的精英，共同探讨最新产业趋势、技术趋势等热门话题。我们还有准备了专属福利，只为回馈最忠实的您！  
  
👉   
扫码立即加入，精彩不容错过！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Y9btpvDIDqqPJv9p5ibKIhJXQjWHJmSlibSdib80Llfp8mlV0ibf7m47jyaVeGoFeorddtIuxS5liafTJRKHeSdLnaQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
😄  
嘻嘻，我们群里见！  
  
更多推荐  
****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Y9btpvDIDqp8QpgS12GKDZmM3wbia28fgrBsUKCFUU3a6Tf9jsVWJcD2l6ic183HdhE2nqia7uMYO2NRQRylficZ5Q/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247513339&idx=1&sn=759f859d0cf7dd748d3dd83ce49cf4cc&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247513359&idx=1&sn=2f3bd51b24862de02cca6078688bafeb&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247514185&idx=1&sn=8015c07a68a5e2b6074efd2c77f20085&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247514336&idx=1&sn=e69b1126e86ab2c59c8ca8e315637031&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247530968&idx=1&sn=3d712e23b322ad37cee46d27adb08ed0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247538943&idx=1&sn=7f95d33eb069aab1cba23c41d68c9759&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247515942&idx=1&sn=bc9ba104b8eb1c0e914d90c8c9a34542&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247532302&idx=1&sn=2c6afc5d39c89c86f79020099ea44baa&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247512372&idx=1&sn=5d06a830f00953a0ab75157fc023ae56&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247538487&idx=1&sn=c4a1ad3501ff0eea9eeb56f514f6e445&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247538487&idx=1&sn=c4a1ad3501ff0eea9eeb56f514f6e445&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247537068&idx=1&sn=3a3e7c08d93638c1a6018c7862b13bcd&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNzA3MTgyNg==&mid=2247538269&idx=1&sn=848c657fc234aff8840d16d3f06b34ea&scene=21#wechat_redirect)  
  
  
  

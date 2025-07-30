#  回顾 | 2025香港Web3嘉年华：CertiK以创新技术定义安全未来   
原创 CertiK  CertiK   2025-04-11 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6GFCsvgWy7OwicaHHk0Lq6GfialVgsoCbo49LiarNt3Dcc106cbk0SowYpQ/640?wx_fmt=png&from=appmsg "")  
  
4月6日至9日，Web3安全巨头CertiK亮相2025香港Web3嘉年华。活动期间，CertiK不仅设立独立展位与广大Web3生态参与者深入互动，更通过高层次的技术交流与前沿研究成果展示，成为本届盛会备受瞩目的焦点。  
  
耶鲁大学计算机科学系教授、CertiK联合创始人邵中和CertiK首席科技官Li Kang博士受邀出席并发表主题演讲，与香港财政司司长陈茂波、以太坊联合创始人Vitalik Buterin等多位政府代表、业界领袖同台。  
  
  
# 数据保护与钱包安全：Li Kang博士带来实践洞见  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6GZrrVjx9o4YCKMhk6KeyribhHy8n6PfQJu9t7AhqDr9uGUYSAkfvJknw/640?wx_fmt=png&from=appmsg "")  
  
4月6日，CertiK首席技术官Li Kang博士受邀出席数据保护与安全隐私专场，发表了以“  
Web3钱包与托管安全”为主题的精彩演讲。他从现实中的安全案例切入，聚焦Web3钱包与资产托管的核心安全问题，为与会者展示了如何有效保护数字资产与隐私安全。  
  
   
   
Web3钱包安全的痛点与反思  
  
Li Kang博士在演讲中指出，随着Web3生态的快速发展，钱包与托管服务的安全风险已成为行业的痛点。他通过对比Web2与Web3钱包的本质差异，强调私钥与签名机制是用户资产安全的“命门”：“Web3钱包用户无需依赖中心化机构，即可通过私钥直接控制资产，但也意味着私钥管理的容错率为零。一次泄露、一次盲签、一个漏洞，都可能导致数亿美元损失。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6GuibLOjETfelkAmtdIVYXAp8alvzEZjc9DAIIusO3TeYUk3gqqlm1ibnQ/640?wx_fmt=png&from=appmsg "")  
  
基于CertiK近期的安全发现数据，Li Kang博士指出两类常见的风险模式：  
  
中心化保存（CoLocation）：不管是多签智能合约还是MPC协议，都存在用户使用不当，在同一地点，同一设备，甚至同一软件内存储多个密钥（多签）或者多密钥份额（MPC）。例如去年发生的Remilia攻击事件，多签密钥共存在同一密码管理器，遭恶意软件窃取。MPC钱包虽然不需要有多个签名私钥，但过去CertiK审计过的MPC实现中也存在同一设备存储多个MPC密钥份额的情况。  
  
盲签（Blind Signing）：虽然多签或者MPC需要多个参与方使用参与交易（transaction）的签名过程，实际操作中，很多用户并没有仔细精准核对交易内容。另外，如果攻击者还能够以传统攻击手段替换签名过程的前端展示，多签的多重检查效果会失效。这样的情况在最近两年内已出现多次，包括WazirX和ByBit的攻击事件。  
  
   
   
安全需要多重的纵深防御  
  
针对上述挑战，Li Kang博士提醒行业应该关注安全运营。强调安全需要多重的纵深防御，持续的风险评测，和与资产规模相匹配的安全投入。  
  
Li Kang博士总结道：“  
安全不是一次性产品，而是持续运营的系统工程。CertiK的安全服务不仅关注代码漏洞，更从供应链、密钥生命周期到特权管理，以及专业安全运营方面，提供全链路风控支持。”  
  
  
# LiDO框架首亮相：邵中教授推动共识协议新突破  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6GmPSMraCqxW6UsYGyh7ICYj4HOOOHqRkgaKgU3jQ48ZQjWKZV0V3n1w/640?wx_fmt=png&from=appmsg "")  
  
4月8日，在2025年Web3学者峰会（Web3 Scholars Conference 2025）上，CertiK联合创始人邵中教授发表了备受瞩目的主题演讲，  
首次公开其团队最新学术成果——LiDO模型及LiDO-DAG扩展框架。这一突破性成果为复杂拜占庭容错（BFT）共识协议（如Jolteon、Narwhal及Bullshark）提供可机械化验证的安全性与活性证明，标志着区块链技术在理论与实践结合上的重大进展。邵教授的分享不仅展示了CertiK在学术研究领域的领先地位，也为Web3生态的可靠性与规模化发展指明了方向。  
  
   
   
安全三层细化框架：LiDO破解三难困境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6G1VqJ7D8PfiangIQia2COdrKG8BR3KcyWwiaxr8dJgWPicrbLBLicgiaPvoBw/640?wx_fmt=jpeg&from=appmsg "")  
  
在本次演讲中，邵中教授指出，现有共识协议（如PBFT、Jolteon）虽广泛应用，但因实现复杂常隐藏潜在漏洞。为解决这一问题，LiDO模型创新性地提出三层细化验证框架：  
  
安全抽象层：将协议映射为线性化状态机，确保日志一致性（安全性）；  
  
活性保障层：引入“Pacemaker”机制，通过超时广播和轮次同步破解网络延迟难题；  
  
DAG扩展层：支持Narwhal、Bullshark等新兴DAG协议，实现无领导者共识的高效验证。  
  
目前，LiDO已成功应用于工业级协议Jolteon（两阶段BFT）及多个DAG协议，完成超万行Coq代码的机械化证明，安全性与活性验证代码量分别达4000行和1700行。  
“当前，PoS共识协议普遍面临安全性、活性与去中心化三者难以兼得的困境，”邵中教授在演讲中指出，“LiDO模型正是为打破这一困境而提出的系统性设计方案。”  
  
   
   
护航Web3未来：CertiK推动协议安全新标准  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6GnT8ZHM7sPhwXgGDGmMkWONvNPiamfePup0PyHd87EtlxDOltrhM07kQ/640?wx_fmt=png&from=appmsg "")  
  
邵中教授带领团队研发的CertiKOS，是全球首个通过形式化验证的“无漏洞”操作系统，被誉为“网络物理系统安全的里程碑”。这一成就不仅奠定了安全公司CertiK的技术根基，也彰显了其在系统安全领域的深厚积累。近年来，邵中教授深耕区块链安全，于2017年与弟子顾荣辉教授共同创立CertiK，将形式化验证技术引入智能合约与链上协议的安全保障，护航千亿美元级加密资产安全。  
  
LiDO当前已完成模型设计与形式化验证，并开始探索与主流公链及去中心化协议的集成可能性。邵中教授表示，CertiK致力于验证Web3中的关键机制，以提供全周期产品和服务，更好地支持Web3企业和生态的长期发展战略。演讲最后，邵中教授强调：“  
可信、安全、可验证的网络协议栈，将是通向真正去中心化未来的关键路径。”  
  
  
# 全面参与，助力Web3生态安全建设  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6GNSu5uZdscjAIBrPKRzoXpXNIFCJzeowiaSuqOuoicOnxKv1wCiapnc2Eg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6GnNbp4TgbbOMWayAcIrYvH7ckswdbMkicITEDc0MJLcBck5qBSwQqNHQ/640?wx_fmt=png&from=appmsg "")  
  
在本届嘉年华中，CertiK通过设立独立展位，与来自全球的Web3生态参与者进行了广泛而深入地互动。展位成为技术交流与合作探讨的热门地点，吸引了众多开发者、企业代表及投资者的关注。CertiK此次亮相，不仅彰显了其在区块链安全领域的技术实力，也进一步推动了全球Web3社区对安全建设与行业创新的共同关注。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6GicbJoicoiaICDmicXQgZMbt5ZrUnDUqxVeQPRKBZZ57Go9icepbojvMGGtg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/mHUbQLu9aKndDnrgR4SyTmIL00zTGl6GJBRvwJCFfOWo2ibGuK4OvG7wDLZdA6F121ZSkuPSbLrZQYcYhibjJGwQ/640?wx_fmt=jpeg&from=appmsg "")  
  
2025香港Web3嘉年华为期四天的活动圆满落幕，CertiK通过技术分享、学术创新与生态互动，展现了其作为Web3安全领导者的担当与视野，为行业未来的发展注入了新的动力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/mHUbQLu9aKlXDex4DcIjeia95xW6gISO901jakyXErg6bUic1FAsffPDUFFZKcWbMJhwkxic9u3uS7WtiaxSPNeV3Q/640?wx_fmt=png&from=appmsg "")  
  

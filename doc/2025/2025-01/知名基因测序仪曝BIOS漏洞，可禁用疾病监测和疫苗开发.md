#  知名基因测序仪曝BIOS漏洞，可禁用疾病监测和疫苗开发   
老布  FreeBuf   2025-01-08 10:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
美国生物技术公司Illumina的iSeq 100 DNA测序仪存在BIOS/UEFI漏洞，这可能导致攻击者禁用用于检测疾病和开发疫苗的设备。Illumina iSeq 100被宣传为医疗和研究实验室可使用的、能提供“快速且具成本效益的遗传分析”的DNA测序系统。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39Ss9pGh5mF1017p8zV2fejDbVpS7PXVib1g3fKbjUqUSRRpDBATQs11PRTYA4icxPibKKnbIrKNICZg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
固件安全公司Eclypsium对Illumina设备中的BIOS固件进行了分析，发现该设备启动时没有标准的写入保护，这就容易遭受重写攻击，从而可能“使系统变砖”或者植入长期存在的恶意软件。  
  
  
**过时且易受攻击的BIOS**  
  
  
  
研究人员发现，iSeq 100运行的BIOS固件版本过时，此版本在兼容性支持模式（CSM）下运行以支持旧设备，并且没有采用安全启动技术进行保护。  
###   
### 漏洞情况  
  
****  
Eclypsium的分析找出了五个主要问题，这些问题致使九个漏洞被利用，这些漏洞的严重程度为高或中等，其中一个漏洞的出现甚至可以追溯到2017年。  
  
  
除了缺乏BIOS写入保护之外，iSeq 100设备还容易受到LogoFAIL、Spectre 2和微架构数据采样（MDS）攻击。虽然在CSM模式下启动能够支持传统设备，但对于敏感设备，特别是新一代设备而言，这种方式是不被推荐的。  
  
  
研究人员还发现，iSeq 100上存在风险的BIOS（B480AM12 - 2018年4月12日）未启用固件保护，这就允许对启动设备的代码进行修改。再加上缺乏安全启动（安全启动可检查启动代码的有效性和完整性），任何恶意更改都不会被发现。  
  
### 潜在影响范围  
  
  
在报告中，Eclypsium强调他们的分析仅针对iSeq 100测序仪设备，但类似问题可能也存在于其他医疗或工业设备中。  
  
  
研究人员解释说，医疗设备制造商会借助外部供应商提供系统的计算能力。就iSeq 100而言，它依赖IEI Integration Corp的OEM主板。由于IEI Integration Corp开发多种工业计算机产品，并且是医疗设备的原始设计制造商（ODM），Eclypsium认为在使用IEI主板的其他医疗或工业设备中“很可能发现这些或类似的问题”。  
  
  
**攻击可能造成的危害**  
  
  
  
研究人员还指出，如果攻击者已经攻陷设备，就可以利用这些漏洞修改固件，这可能导致系统变砖；有足够知识的威胁行为者还能篡改测试结果。Eclypsium表示：“如果这些设备中的数据被植入/后门操纵，那么威胁行为者可能会操纵包括伪造遗传病状的存在或缺席、操纵医疗治疗或新疫苗、伪造祖先DNA研究等在内的广泛结果。  
  
  
Eclypsium将iSeq 100设备中的BIOS问题告知了Illumina，生物技术公司回复已向受影响的客户发布补丁。  
  
该公司发言人表示，Illumina正在遵循其“标准流程，若需要任何缓解措施，将会通知受影响的客户”。  
  
  
Illumina的代表称：“我们最初的评估表明这些问题不是高风险。”Illumina还强调致力于产品的安全性和基因组数据的隐私，已建立监督和问责流程，包括产品开发和部署的安全最佳实践，并且一直在努力改进为现场仪器提供安全更新的方式。  
  
  
在报告中，Eclypsium的研究人员警告，能够覆盖iSeq 100上固件的威胁行为者“可以轻松禁用设备”。勒索软件行为者可能会通过接管高价值系统来破坏业务，因为他们的目的是让受害者的恢复工作困难重重，从而迫使受害者支付赎金。除了出于经济利益的攻击者外，国家行为者也可能会对DNA测序系统感兴趣，因为这些系统“对于检测遗传病、癌症、识别耐药细菌以及疫苗的生产至关重要”。  
  
  
2023年，美国网络安全基础设施安全局（CISA）和食品药品监督管理局（FDA）发布了关于Illumina的通用复制服务（UCS）中的两个漏洞的紧急咨询，这两个漏洞存在于全球医疗设施和实验室使用的多种产品中。其中一个问题（CVE - 2023 - 1968）的严重程度最高，另一个（CVE - 2023 - 1966）的严重程度较高。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

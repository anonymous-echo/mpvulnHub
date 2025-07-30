#  NIST发布“漏洞预测指标”，大幅提升漏洞管理能力   
 GoUpSec   2025-05-29 04:11  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvYMYImFKXQicCnm1QbdiczX8q3dUmjQdHib9etrtdialMKg9KLLekXNS67CAO7Gib39qnzac4MK7BoFTvA/640?wx_fmt=png&from=appmsg "")  
  
  
近日，美国国家标准与技术研究院（NIST）发布了《网络安全白皮书41号》（CSWP41），提出了一种名为“可能被利用漏洞”（Likely Exploited Vulnerabilities，简称LEV）的新型安全指标，用于衡量软件和硬件漏洞被实际利用的可能性。  
  
  
该指标旨在弥补现有漏洞管理工具的不足，特别是在当前广泛使用的漏洞预测评分系统（EPSS）和已知被利用漏洞列表（KEV）存在局限性的背景下。  
  
  
  
**LEV指标的核心优势**  
  
  
  
LEV通过结合历史EPSS评分和KEV列表数据，采用统计模型和概率理论，计算每个漏洞在过去被利用的累计概率。这种方法不仅提供了对漏洞被利用可能性的量化评估，还能帮助组织更有效地优先处理高风险漏洞。  
  
  
例如，LEV可以识别出那些在KEV列表中未被列出但具有高被利用概率的漏洞，或是那些在EPSS评分中被低估的漏洞，从而增强漏洞管理的全面性和准确性。  
  
  
  
**技术实现与性能**  
  
  
  
LEV指标的计算依赖于EPSS评分的历史数据，并通过Python实现。该实现从国家漏洞数据库（NVD）、CISA的KEV列表和EPSS评分数据中提取信息，计算每个CVE（公共漏洞和暴露）编号对应的LEV概率。  
  
  
尽管LEV的计算需要处理大量数据，但在现代计算设备上，尤其是使用LEV2公式时，仍能在合理的时间内完成所有CVE的LEV概率计算。  
  
  
  
**实际应用与前景**  
  
  
  
LEV指标的引入为组织提供了一个更全面的漏洞风险评估工具，特别是在资源有限的情况下，能够更有效地优先处理最可能被利用的漏洞。  
  
  
然而，NIST也指出，LEV指标的准确性仍需进一步验证，特别是需要行业合作伙伴提供实际漏洞利用数据，以评估LEV的性能和可靠性。  
  
  
总体而言，LEV指标的提出标志着漏洞管理方法的一次重要进步，为企业提供了更强大的工具，以应对日益复杂的网络安全威胁。  
  
  
参考链接：  
  
https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/INYsicz2qhvbJ3aCGM50PbZtic5aDicS3EvfpQ7dCyEhTy0G7s5xdSnzXiayb6GltxiaKbW9p1L15SUrGgIvwAR6GmQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
END  
  
  
  
相关阅读  
  
  
  
[ChatGPT拒绝关机，美国AI军备竞赛油门焊死的隐忧](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247503354&idx=1&sn=0c64140492ce8dc3bb17568f48fe960d&scene=21#wechat_redirect)  
  
  
[时尚巨头迪奥发生大规模数据泄漏，包括高价值中国客户资料](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247503288&idx=1&sn=8b53324fe0af938a6981af066c22f278&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/INYsicz2qhvbgcN4QY36lK2wjCavZiadQThpmM11FR4xkwyVG7K24lkpoLRcFHuZ7gAHgZEsr6Mia7BmKuwDJqX4g/640?wx_fmt=jpeg "")  
  
  

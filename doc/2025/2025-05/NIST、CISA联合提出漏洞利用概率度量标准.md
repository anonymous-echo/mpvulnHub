#  NIST、CISA联合提出漏洞利用概率度量标准   
Eduard Kovacs  代码卫士   2025-05-21 10:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**CISA和NIST 的研究人员提出一项新的网络安全度量标准，旨在计算漏洞已遭在野利用的可能性。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQ2ZtShadXISAOjbZXiaxficUcOBPJNwwV3AH8LD0fFyx3eX6DtqoR2P0A2Co46SlwL9kphhJ9W2LHg/640?wx_fmt=png&from=appmsg "")  
  
  
NIST研究员 Peter Mell 和 CISA 研究员 Jonathan Spring 发表论文，说明了他们所提出的“可能遭利用的漏洞 (LEV)” 的等式。  
  
软件和硬件每年都会被发现数以千计的漏洞，但只有较少比例的漏洞会遭在野利用。了解哪些漏洞已遭利用或者预测哪些漏洞遭利用的可能性对于组织机构优先打补丁而言至关重要。  
  
“已知遭利用的漏洞 (KEV)” 类的列表如由CISA维护的KEV以及依赖于数据来预测漏洞将被利用的可能性的“利用预测评分系统 (EPSS)”，能够发挥很重要的作用。然而，KEV列表的完整性可能欠佳，而EPSS的准确度可能不尽如人意。  
  
LEV 旨在增强而非取代多种KEV列表和EPSS，而这会通过等式实现。该等式会考虑多种变量如某个具体漏洞首次获得EPSS评分的日期、最新的KEV列表更新日期、纳入KEV的日期，以及在既定日期的EPSS分数等。  
  
论文提到，LEV至少可在四种用例中发挥作用。LEV计算出的概率能够度量威胁人员已利用的预期漏洞数量和比例，而且还能用于估测KEV列表的全面性。研究人员解释称，“此前，KEV维护人员无法通过一种度量标准来证明他们的列表在完成包含所有相关漏洞方面的表现。”  
  
此外，LEV计算出的概率有助于增强基于KEV和EPSS的漏洞修复优先级。对于KEV而言可识别可能缺失的更可能遭利用的漏洞，对于EPSS 则是找到可能评分过低的漏洞。  
  
虽然在理论上来讲，LEV对于漏洞处理优先级而言非常有用，但研究人员提到了协作的必要性，而NIST正在寻找“拥有相关数据集的”行业合作伙伴“以经验为基础来度量LEV概率的表现”。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA的KEV清单加快漏洞修复速度了吗？](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519427&idx=2&sn=952e60354283e3d7df02f25ba52d112d&scene=21#wechat_redirect)  
  
  
[CISA为CVE计划续期11个月，MITRE 成立CVE基金会防范](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522769&idx=2&sn=550a6097b86ddca08a77c2e694b9e854&scene=21#wechat_redirect)  
  
  
[NIST披露NVD的漏洞分析恢复计划](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519633&idx=1&sn=a16b68e9987a385bda6e79bbb1252d42&scene=21#wechat_redirect)  
  
  
[NIST宣布成立生成式AI工作组](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516996&idx=2&sn=516fa667d161aeeb8f4aca58f5694c6a&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/vulnerability-exploitation-probability-metric-proposed-by-nist-cisa-researchers/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

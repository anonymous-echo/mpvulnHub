#  美国NIST、CISA联合提出漏洞利用概率度量标准   
 安全内参   2025-05-23 08:41  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
  
NIST和CISA号召行业协作。  
  
  
编译：代码卫士  
  
CISA和NIST 的研究人员提出一项新的网络安全度量标准，旨在计算漏洞已遭在野利用的可能性。  
  
NIST研究员 Peter Mell 和 CISA 研究员 Jonathan Spring 发表论文，说明了他们所提出的“可能遭利用的漏洞 (LEV)” 的等式。  
  
软件和硬件每年都会被发现数以千计的漏洞，但只有较少比例的漏洞会遭在野利用。了解哪些漏洞已遭利用或者预测哪些漏洞遭利用的可能性对于组织机构优先打补丁而言至关重要。  
  
“已知遭利用的漏洞 (KEV)” 类的列表如由CISA维护的KEV以及依赖于数据来预测漏洞将被利用的可能性的“利用预测评分系统 (EPSS)”，能够发挥很重要的作用。然而，KEV列表的完整性可能欠佳，而EPSS的准确度可能不尽如人意。  
  
LEV 旨在增强而非取代多种KEV列表和EPSS，而这会通过等式实现。该等式会考虑多种变量如某个具体漏洞首次获得EPSS评分的日期、最新的KEV列表更新日期、纳入KEV的日期，以及在既定日期的EPSS分数等。  
  
论文提到，LEV至少可在四种用例中发挥作用。LEV计算出的概率能够度量威胁人员已利用的预期漏洞数量和比例，而且还能用于估测KEV列表的全面性。研究人员解释称，“此前，KEV维护人员无法通过一种度量标准来证明他们的列表在完成包含所有相关漏洞方面的表现。”  
  
此外，LEV计算出的概率有助于增强基于KEV和EPSS的漏洞修复优先级。对于KEV而言可识别可能缺失的更可能遭利用的漏洞，对于EPSS 则是找到可能评分过低的漏洞。  
  
虽然在理论上来讲，LEV对于漏洞处理优先级而言非常有用，但研究人员提到了协作的必要性，而NIST正在寻找“拥有相关数据集的”行业合作伙伴“以经验为基础来度量LEV概率的表现”。  
  
原文链接  
  
https://www.securityweek.com/vulnerability-exploitation-probability-metric-proposed-by-nist-cisa-researchers/  
  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
文章来源：代码卫士  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIyODYzNTU2OA==&mid=2247498996&idx=1&sn=a52abe5d42325669cf592bee26abf77a

#  2025 Verizon DBIR解读 | 供应链攻击30%+勒索软件44%：边缘设备漏洞与AI滥用催生新风险  
原创 创新研究院  绿盟科技研究通讯   2025-07-18 06:46  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGiaMNczeeQyrUXZ7jkkJ3iasrGr7S3FJa2gibdqM6YQVngK4dLuPMao4kw/640?wx_fmt=gif&from=appmsg "")  
  
  
一． 概述  
  
  
  
  
  
  
  
  
  
  
2025年5月，国际知名咨询机构Verizon发布了《2025年数据泄露调查报告》（2025 Data Breach Investigations Report）[1]。该报告综合分析了自2024年5月至2025年初的22052起安全事件，其中12195被确认为数据泄露事件，覆盖全球共139个国家。这一数据代表了Verizon DBIR报告有史以来分析的最高数据泄露事件数量，数据来源主要由Verizon威胁研究团队（VTRAC）提供。  
  
2024年，绿盟科技创新研究院曾对《Verizon 2024年数据泄露调查报告》[1]进行深度解读。本文延续该分析框架，聚焦2025年Verizon报告核心结论，并通过与2024年数据的纵向对比展开三层次剖析：  
- 报告核心结论：提炼威胁演变的整体趋势；  
  
- VERIS框架四维分析：基于威胁参与者、行为、资产、属性解构数据泄露事件；  
  
- 安全事件三维透视：从成因分类、行业分布、区域分布揭示攻击模式。  
  
通过此结构化解读，旨在通过本文增强读者对数据泄露问题的重视。  
  
   
  
  
二．2025 Verizon DBIR报告主要结论  
  
  
  
  
  
  
  
  
  
  
结论1  2024年利用漏洞窃取数据的攻击行为增长至20%，年增长34%，主要原因为边缘设备和VPN的0 Day漏洞利用正加速成为主要入侵途径，其占比22%，年增率8倍，但漏洞修复率仅为54%，暴露出防护缺口显著。  
  
结论2  截止2025年初，勒索软件攻击相比去年新增37%，占所有安全事件的44%，去年为32%。但赎金中位数降至11.5万美元，去年15万美元，64%的受害者拒付赎金，高于两年前的50%，可能是赎金金额下降的原因导致。此外，小企业组织更易受勒索软件的攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGUGjVJZ5DQ8qTOC88nySdcG5umxpbuJDwJ8Z2jsutQskp0iaick3wuI9Q/640?wx_fmt=png&from=appmsg "")  
  
图1. 勒索软件攻击趋势图[1]  
  
结论3  截至2025年初，72% 员工使用个人账号访问GenAI平台引发内部数据泄露风险激增；与此同时，外部AI生成的钓鱼邮件量同比新增100%，使企业面临双重安全威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGrlcRqs8c8Lrc6RSgeibibo8I0dfXcf5z9hFN48uogIQgjpsWg5ibkxvYA/640?wx_fmt=png&from=appmsg "")  
  
图2. GenAI平台账号登录分布及AI生成钓鱼邮件时间分布[1]  
  
   
  
结论4  2024年至2025年间，涉及第三方的数据泄露事件占比从15%上升至30%，这一增长主要归因于MOVEit和Snowflake等重大供应链攻击事件引发的系统入侵(System Intrusion)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtG87SpjJbLVicvTJSfazRlHfyQu7f9IltJOIibsvatjrJKNbfNzgeVzL6A/640?wx_fmt=png&from=appmsg "")  
  
图3. 涉及第三方数据泄露的攻击行为占比[1]  
  
结论5  凭证泄露风险依旧严重，公开代码仓库中可获取的泄露密钥占比高达50%。具体分布为Web应用凭证占39%，其中JWT认证令牌占66%，云密钥中Google Cloud API占比最高43%，值得注意的是，凭证修复中位数周围长达94天，形成持续暴露窗口，使攻击者能够轻易绕过认证机制  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGjq8hHZoWuukeQ3SC5iaWb2c8eMe9ePMQYy1icP93U6vS5ekYicsrv9IPA/640?wx_fmt=png&from=appmsg "")  
  
图4. 公开代码仓库可获取的凭证泄露途径及凭证修复周期[1]  
  
  
  
三．威胁要点分析  
  
  
  
  
  
  
  
  
  
  
Verizon DBIR报告提供了一套指标VERIS（The Vocabulary for Event Recording and Incident Sharing） — 事件记录和事件共享词汇，旨在提供一种结构化和可重复的方式来描述安全事件的通用语言。VERIS常用指标包含威胁参与者（Threat actor）、威胁行为（Threat action）、威胁资产（Threat action）、威胁属性（Threat Variety）、数据泄露事件（Breach）、安全事件（Incident）、外部参与者(External)、内部参与者(Internal)、合作伙伴(Partner)，具体指标解释读者也可以参考《2024 Verizon DBIR解读 | 数据泄露转向连接云的第三方软件供应链》一文，此处不再赘述。下面我们首先将重点介绍报告在威胁参与者、威胁行为、威胁资产、威胁属性维度中提到的一些关键数据，之后再进行一些分析与总结，以便读者更全面地理解报告内容。  
  
3.1   
  
威胁参与者维度分析  
  
根据Verizon报告的数据分析，2025年数据泄露事件的主要威胁来源和动机相比2024年呈现出以下关键趋势：  
- 威胁主体分布有一定变化  
  
外部参与者仍然是最大风险来源，占比高达81%，较2024年的65%有显著上升，且攻击手段以系统入侵（System Intrusion）和社会工程(Social Engineering)为主。内部参与者占比降至18%，2024年为35%，且多数泄露事件源于无心之失，其中杂项类错误（Miscellaneous Errors）的发生频率是特权滥用（Privilege Misuse）的两倍。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtG3eUqjiciaibABkqHYUOVOcmbG8PP3roibV9DEXA03rb25JOdLYI0vIrvPw/640?wx_fmt=png&from=appmsg "")  
  
图5. 威胁参与者分布（左2024年，右2025年）[1]  
  
此外，随着AI技术发展迅速，生成式AI（GenAI）也作为新的威胁参与者正在通过各种方式加剧企业的安全风险，较典型的为数据外泄风险，如企业员工在使用GenAI做总结、编码辅助等功能时，常常会上传机密文件和业务代码，从而引发数据泄露。再如员工使用个人邮箱账户绕过企业安全管控的行为。未来可以预见到的是， GenAI正迅速被集成到手机操作系统中，一些核心功能，如语音助手，相机等默认开启即会大量收集数据，这也同时赋予了新的数据泄露途径，并极大地增加了BYOD的风险。  
- 攻击动机有新的变化  
  
金钱驱动仍是主流，与2024年情况相似，攻击者主要目标为数据窃取。而间谍动机成为新焦点，2025年由外部参与者发起的以间谍为目的的泄露事件激增163%，反映出全球地缘政治紧张局势对网络安全的影响加剧。  
  
3.2   
  
威胁行为维度分析  
  
如图6显示了2024,2025年报告的威胁行为维度数据对比，数据泄露事件的主要威胁行为呈现显著变化。威胁行为维度上，被窃凭证（Use of stolen creds）、勒索软件（Ransomware）和长尾类别（Other）是导致数据泄露的三大主要威胁。值得注意的是，2025年长尾类别（Other，44%）占比第一，Verizon解释这是由于勒索软件和间谍攻击技术复杂化，导致大量细分攻击行为（如Hacking/Malware）被归入该类别。  
  
2025年出现三个显著趋势：  
  
一是漏洞利用（Exploit vuln）占比从10%上升至18%，首次超过钓鱼（14%），反映出漏洞武器化的加速趋势；  
  
二是威胁行为类型发生调整 — 2024年存在的特权滥用行为在2025年消失，同时新增了利用误配置（Exploit misconfig，占9%）和数据外泄（Export data，占10%）两类威胁，其共性是通过脆弱性配置实现入侵并窃取数据；  
  
三是针对边缘设备的攻击显著增加：攻击者利用46%暴露在互联网边缘的设备漏洞未及时修复的现状，结合这些设备固有的脆弱性，快速发起自动化攻击；并且攻击者利用漏洞从公开到被武器化，约15天的速度远快于企业修复的速度，仅54%得到修复（虽然54%的修复率已经不算低），在防御完成前就实现了入侵和数据窃取。  
  
整体来看，威胁行为正从传统社交工程转向技术性攻击（漏洞利用、配置滥用）迁移，同时攻击技术的复杂化也推动威胁分类体系的动态演进。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGGtIwvxbUAk4ScjgicWOXIukbr2vAEwM6DYoQoUCt6uffe6jVdxzIong/640?wx_fmt=png&from=appmsg "")  
  
图6. 威胁行为占比（左2024年，右2025年）[1]  
  
3.3   
  
威胁资产维度分析  
  
根据Verizon的安全事件分析，数据泄露事件中受影响的主要资产类型包括服务器（云端和本地）、人员（Person）、用户开发环境（User Dev）、媒体（Media）和网络（Network）。其中，服务器资产仍是最主要的泄露目标，2025年占比高达95%，2024年为85%，而人员和用户开发环境的泄露占比基本保持稳定。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGZluoMLrBATM03AVthV2sWicxlLib51BeicRs0hmH9pBgpZg6cjXFG8ZaQ/640?wx_fmt=png&from=appmsg "")  
  
图7. 威胁资产占比（左2024年，右2025年）[1]  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGM7oTn3YicAV6BL49vyibZptXWiabzkX08Okm2OokLiauV94WOguULSvibGQ/640?wx_fmt=png&from=appmsg "")  
  
图8. 威胁资产属性占比（左2024年，右2025年）[1]  
  
从威胁资产属性来看，Web应用程序和邮箱服务器是最常被攻击的目标，主要威胁包括凭证窃取和漏洞利用。值得注意的是，2025年新增了远程访问服务器类别，反映出攻击者正转向利用新的高价值目标。针对此类资产的攻击行为主要集中在漏洞利用（Exploit vuln），并常与后续的勒索软件部署形成关联攻击链。这一趋势表明，随着攻击者偏好的变化，如转向远程访问服务器，数据泄露涉及的资产属性也在动态调整。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGkr2WBiaNJqRJLEwNeWQY8ia5ynG6zD4uEFwUtr5oia9OsSNksLBYVr1Fw/640?wx_fmt=png&from=appmsg "")  
  
图9. 针对远程访问服务器资产的攻击行为类别占比[1]  
  
3.4   
  
威胁属性维度分析  
  
Verizon从信息安全三要素（机密性、完整性、可用性）的角度分析，2022-2025年间各要素受威胁的频率呈现显著变化，如图10所示：  
- 机密性（Confidentiality）威胁持续上升，从2022年的20%增至2024年的30%，并在2025年大幅跃升至60%，反映出数据窃取和泄露风险的加剧。  
  
- 可用性（Availability）威胁自2022年以来呈线性增长，2025年维持在60%左右，与往年持平，表明勒索软件等破坏业务连续性的攻击仍居高不下。  
  
- 完整性（Integrity）威胁比例波动较大，2022-2024年从40%降至20%，但2025年回升至50%，可能源于数据篡改或供应链攻击的增加。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGU4qPVwlAsxASPDebTzMv3t9QfsIIoZiaKEE7czzbExFiby49T3c3pFgQ/640?wx_fmt=png&from=appmsg "")  
  
图10. 信息安全三要素受威胁频率占比（左2024年，右2025年）[1]  
  
数据泄露类型方面，客户自有数据（Internal）、个人数据（Personal）和凭证数据（Credentials）仍是主要泄露目标。值得关注的是，2025年医疗数据（Medical）受勒索软件攻击的占比反超银行数据（Bank）和敏感个人数据（Sensitive Personal），这一变化可能与2024年MOVEit供应链漏洞的大规模无差别攻击有关，导致医疗行业数据泄露短期激增。整体来看，攻击者更聚焦于窃取数据（机密性）和破坏服务（可用性），而医疗领域成为新兴的高风险目标。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGLictgiaHtyRia46wqMEHKC5pSFCD3xRibT6Y7uqagplFP3ggX2YmEnnRLA/640?wx_fmt=png&from=appmsg "")  
  
图11. 数据泄露类型占比（左2024年，右2025年）[1]  
  
3.5   
  
分析总结  
  
从威胁参与者维度来看，外部威胁参与者占比提升至81%，2024年这一数字为65%，攻击手段集中在系统入侵和社会工程，并且以间谍为目的的事件暴增163%，反映出全球地缘政治紧张，黑客组织及犯罪团伙的技术优势正逐步主导威胁态势；与此同时，生成式AI的技术发展也导致该技术可被攻击者滥用，进而造成主动泄露（企业员工上传代码或密钥至平台）及被动渗透（AI集成移动端导致的BYOD风险，扩大数据收集面）的两类风险；最后，报告威胁行为维度统计显示，传统社会工程如钓鱼被技术型攻击所反超，如漏洞利用（Exploit vuln）占比从10%提升至18%，并且出现新增的利用配置缺陷（Exploit misconfig，占比9%）和数据外泄（Export data，占比10%）两类威胁行为，这两类均依赖系统弱点而非人为欺骗。以上说明，攻击者的策略向“技术化”与“外部化”迁移，因此防御体系也应从“防人”转向“防技”。  
  
从威胁属性维度来看，机密性风险占比从去年报告数据的30%翻倍至60%，相比完整性（50%）和可用性（60%）没有基本变化而言确实高出不少，也进一步说明攻击者核心诉求的变化，即从“破坏服务”转向“窃取高价值数据”。  
  
从威胁资产维度来看, 云端/本地服务器占比从85%提升至95%，依旧垄断95%的泄露事件，且远程访问服务器成为新靶点，常被用于漏洞利用，勒索软件的攻击跳板。  
  
  
  
四．安全事件分析  
  
  
  
  
  
  
  
  
  
  
4.1   
  
事件分类分析  
  
Verizon将事件分类为八种模式，即基础Web应用类攻击（Basic Web Application Attacks），拒绝服务攻击（Denial of Service），丢失和被窃取的凭证（Lost and Stolen Assets），杂项类错误（Miscellaneous Errors 泛指人的因素，无意行为导致安全事件的发生，但丢失设备并不包含在此类中，而属于盗窃类别），权限滥用（Privilege Misuse），社工（Social Engineering）, 系统入侵（System Intrusion）, 其他（Everything Else）。笔者分别将2024，2025年Version报告图从安全事件和数据泄露事件两个维度展示了近年来事件成因随时间推移的变化，如图12, 图13所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGSuVlM5IgDsjfhBNUV2Q8DCsibt0WcCX8icRibjdgmrgvZKb2qr83VRJAg/640?wx_fmt=png&from=appmsg "")  
  
图12. 2024 Verzion报告安全事件成因变化,数据泄露事件成因变化[1]  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGmQVicmzwBYCpYMKcBY9JwpsSBnsiazJfdLTGbIMdPMxddPEN6KuXjByw/640?wx_fmt=png&from=appmsg "")  
  
图13. 2025 Verzion报告安全事件成因变化,数据泄露事件成因变化[1]  
  
首先，从安全事件维度来看，自2018年以来，拒绝服务攻击持续成为导致事件发生的主要原因。尤其自2022年以来，拒绝服务类攻击的频率显著上升，在2024年达到最高点，2025年初至今有下降趋势，从60%将至30%；其次是系统入侵类攻击的数据有所变化，系统入侵在2025年有所上升, 原因是去年的供应链安全事件仍在发酵，且导致安全事件的主要分类为系统入侵。  
  
其次，在数据泄露事件维度方面，从2017年起，系统入侵、社工攻击、杂项类错误和基础Web应用类攻击分别成为数据泄露的主要原因。自2023年至2024年以来，社工攻击和杂项错误模式均显著增加，但2024年至2025年有轻微下降趋势，社工攻击主要以话术欺诈和钓鱼邮件为主，尤其随着AI技术的普及，钓鱼邮件的迷惑性将会越来越高，杂项错误多与发布错误（Publishing error）、配置错误（Miconfiguration）和误投递（Misdelivery）相关，与去年相比前三名有所变化，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGBKj60ibagibNYJiblcb0Vy2qevhibu6BBAwC0RtADEg0yTJpbBxpL9lNnQ/640?wx_fmt=png&from=appmsg "")  
  
图14. 导致数据泄露的杂项类错误分类占比（左2024,右2025）[1]  
  
4.2   
  
事件行业分布  
  
Verizon分析了全球发生的22052个安全事件，其中有12195个被确认为数据泄露事件，按受害者行业和组织规模划分的安全事件和数据泄露数量如图14所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGdXN4ekELbKokCdWfz6dF5SXyfcoMtwSgoYgiaIKRibpIGObJwQFm91jg/640?wx_fmt=png&from=appmsg "")  
  
图15. 按受害者行业和组织规模划分的安全事件和数据泄露数量汇总[1]  
  
从数据泄露事件数量来看，主要受到影响较大的行业为：  
  
1. 医疗（位列第二）: 事件模式分类上以杂项类错误，系统入侵为主，约占比医疗行业数据泄露事件的 74%  
  
2. 教育: 事件模式分类上以系统入侵,社工，杂项类错误为主，约占比教育行业数据泄露事件的80%，去年为90%  
  
3. 金融: 事件模式分类上以系统入侵, 社工，基础Web类攻击为主，去年的杂项类错误配置攻击消失，约占比金融行业数据泄露事件的74%，去年为78%  
  
4. 制造业（位列第一）:  事件模式分类上以系统入侵, 社工，基础Web类攻击为主，去年的杂项类错误配置攻击消失，约占比制造行业数据泄露事件的85%，去年为83%  
  
5. 信息行业:  事件模式分类上以系统入侵, 基础Web应用类攻击，社工为主，约占比信息行业数据泄露事件的82% ，去年为79%  
  
6. 行政单位(位列第三):  事件模式分类上以系统入侵, 社工，基础Web类攻击为主，去年的杂项类错误配置攻击消失，约占比行政单位数据泄露事件的78%，去年为91%  
  
从事件分类模式来看，当前安全事件的主要成因集中在系统入侵、社工攻击和基础Web类攻击三大领域，这一分布与去年相比保持相对稳定。值得注意的是，在受影响行业分布基本不变的情况下，各行业的安全威胁来源发生了显著变化：原先占比较高的"杂项类错误"正逐步被"基础Web类攻击"所取代。这一趋势转变表明，由人为操作失误导致的数据泄露事件正在减少，而针对系统漏洞的有组织攻击正在成为网络安全的主要威胁。  
  
与此相比，国内发布的数据泄露报告，如《2025上半年数据泄露风险态势报告》[4]（由威胁猎人发布）描述了数据泄露事件在不同行业的分布情况。该报告指出数据泄露事件数量 Top10行业分别为电商、消费金融、银行、快递、证券、社交软件、软件应用、保险、在线票务、汽车品牌。可以看出与国外相比，国内医疗、教育、制造业、行政单位的安全事件相对较少，这也进一步反映出国内政府、传统行业的监管机构措施较严格，数据安全法执行相对严厉，并且相对于互联网、金融、电商等行业，由于金钱驱动力不高，所以攻击者兴趣也较低。，  
  
4.3   
  
事件区域分布  
  
图16展示了亚太地区(APAC)、 欧洲、中东和非洲(EMEA)和北美(NA)三个地区的事件数量分布情况。数据显示，北美地区的事件数量最多，共计6361起，而亚太地区地区的事件数量最少，仅为2687起。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGD9k7sleS0O4h9py9IwvZo8MKIJMv7Xypvc6HBA8YTibAgKr6OdUXKibQ/640?wx_fmt=png&from=appmsg "")  
  
图16. 事件区域分布[1]  
  
从事件成因方面来看，系统入侵和社工攻击为主要因素，大概占比90%；从威胁者的角度来看，外部攻击者成为主要威胁；行为动机方面，金融驱动一直是攻击者的主要动机之一。从威胁资产的类型来看，北美主要以内部数据和医疗数据以及凭证为主，而亚太地区则以企业内部数据和凭证为主；从威胁属性来看，亚太地区主要以被窃取的凭证、勒索软件、漏洞利用为主。  
  
  
  
五．总结  
  
  
  
  
  
  
  
  
  
  
本文对2025年Verizon DBIR报告进行解读，提炼出报告的主要结论。我们认为今年的报告主要突出的亮点：  
  
生成式AI成为双刃剑：生成式AI的流行大幅降低了钓鱼邮件、深度伪造语音等社会工程攻击的技术门槛，攻击者可以快速批量构造高欺骗性内容，导致社工攻击效率提升，但同时也会因大量滥用导致数据泄露风险提升。  
  
系统入侵主导攻击模式，基础Web应用攻击取代杂项类错误，AI和漏洞利用的结合组成新的攻击模式：系统入侵仍然是攻击模式中的主流，占比最高，核心为勒索软件和复杂漏洞利用攻击链，基础Web应用攻击（如凭证窃取、漏洞利用）取代2024年的“杂项错误”，成为第二大威胁行为。AI和漏洞利用融合的技术将会成为攻击者攻破防护壁垒的关键 ，企业需构建覆盖漏洞管理，如云服务配置加固、漏洞优先级修复与人员风险管控，如AI使用规范等相结合的防御体系。  
  
绿盟科技创新研究院在云上风险发现和数据泄露领域已经开展了多年的研究。借助Fusion数据泄露侦察平台，我们已监测到数万个云端暴露资产存在未授权访问的情况，包括但不限于自建仓库、公有云对象存储、云盘、OLAP/OLTP数据库、大模型组件，以及各类存储中间件等，具体研究内容可参考包括但不限于DevSecOps组件，自建仓库、公有云对象存储、云盘、OLAP/OLTP数据库，大模型组件以及各类存储中间件等，具体研究内容可参考《2023公有云安全风险分析报告》[5]，《2024上半年全球云数据泄露风险分析报告》[6]，《全球云上数据泄露风险分析简报》第一期至第五期[7-11]，云上LLM数据泄露风险研究系列[12-15]。  
  
Fusion是由绿盟科技创新研究院研发的一款面向数据泄露测绘的创新产品，集探测、识别、泄露数据侦察于一体，针对互联网中暴露的泛云组件进行测绘，识别组件关联的组织机构和组件风险的影响面，实现自动化的资产探测、风险发现、泄露数据分析、责任主体识别、数据泄露侦察全生命周期流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUblvrdzjVxwWoZAa0XZEvtGYF0O5SIiaV6UkIia4C5kgdtTTldBDqOLISwzDp9s5DoldzpJSjdI5C9w/640?wx_fmt=png&from=appmsg "")  
  
图17 Fusion能力全景图  
  
Fusion的云上风险事件发现组件具有如下主要特色能力：  
  
资产扫描探测：通过多个分布式节点对目标网段/资产进行分布式扫描探测，同时获取外部平台相关资产进行融合，利用本地指纹知识库，实现目标区域云上资产探测与指纹标记；  
  
资产风险发现：通过分布式任务管理机制对目标资产进行静态版本匹配和动态PoC验证的方式，实现快速获取目标资产的脆弱性暴露情况；  
  
风险资产组织定位：利用网络资产信息定位其所属地区、行业以及责任主体，进而挖掘主体间存在的隐藏供应链关系及相关风险。  
  
资产泄露数据分析：针对不同组件资产的泄露文件，结合大模型相关技术对泄露数据进行分析与挖掘，实现目标资产的敏感信息获取；  
  
  
参考文献  
  
[1] https://www.verizon.com/business/resources/reports/dbir/   
  
[2] https://mp.weixin.qq.com/s/RG5AVGbvrRHGfp86UGInKw   
  
[3] https://verisframework.org/   
  
[4] https://www.threathunter.cn/blog/2025   
  
[5] 《2023公有云安全风险分析报告》 https://book.yunzhan365.com/tkgd/qdvx/mobile/index.html    
  
[6]《2024上半年全球云上数据泄露风险分析报告》https://book.yunzhan365.com/tkgd/cltc/mobile/index.html  
  
[7] 全球云上数据泄露风险分析简报 （第一期）https://book.yunzhan365.com/tkgd/sash/mobile/index.html  
  
[8] 全球云上数据泄露风险分析简报 （第二期）https://book.yunzhan365.com/tkgd/bxgy/mobile/index.html  
  
[9] 全球云上数据泄露风险分析简报 （第三期）https://book.yunzhan365.com/tkgd/xyih/mobile/index.html    
  
[10] 全球云上数据泄露风险分析简报 （第四期）https://book.yunzhan365.com/tkgd/xbin/mobile/index.html   
  
[11] 全球云上数据泄露风险分析简报 （第五期）https://book.yunzhan365.com/bookcase/wxjf/index.html   
  
[12] 云上LLM数据泄露风险研究系列（一）：基于向量数据库的攻击面分析https://mp.weixin.qq.com/s/5jndWjm_yMEXY0E-W369NQ   
  
[13] 云上LLM数据泄露风险研究系列（二）：基于向量数据库的攻击面分析  
  
https://mp.weixin.qq.com/s/KZsGvmyE6WtspDb5ZvNKVg   
  
[14] 云上LLM数据泄露风险研究系列（三）：开源大模型应用的攻击面分析  
  
https://mp.weixin.qq.com/s/ADHC4e03ymaPe5ifZ7aODA   
  
[15] 开源大模型推理软件的攻击面分析：云上LLM数据泄露风险研究系列（四）  
  
https://mp.weixin.qq.com/s/-hHPcWM71kW--c51GoT4qw   
  
内容编辑：浦   明  
  
责任编辑：陈佛忠  
  
本公众号原创文章仅代表作者观点，不代表绿盟科技立场。所有原创内容版权均属绿盟科技研究通讯。未经授权，严禁任何媒体以及微信公众号复制、转载、摘编或以其他方式使用，转载须注明来自绿盟科技研究通讯并附上本文链接。  
  
  
**关于我们**  
  
  
绿盟科技研究通讯由绿盟科技创新研究院负责运营，绿盟科技创新研究院是绿盟科技的前沿技术研究部门，包括星云实验室、天枢实验室和孵化中心。团队成员由来自清华、北大、哈工大、中科院、北邮等多所重点院校的博士和硕士组成。  
  
绿盟科技创新研究院作为“中关村科技园区海淀园博士后工作站分站”的重要培养单位之一，与清华大学进行博士后联合培养，科研成果已涵盖各类国家课题项目、国家专利、国家标准、高水平学术论文、出版专业书籍等。  
  
我们持续探索信息安全领域的前沿学术方向，从实践出发，结合公司资源和先进技术，实现概念级的原型系统，进而交付产品线孵化产品并创造巨大的经济价值。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/hiayDdhDbxUaGMf56TBWI0Ro3ZrzFfQqbDOkeGdcVGVicbAOsMsMJwaaqHDLSHVK2NV1mRoyXfXYzUJiaGWKdpPJg/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**长按上方二维码，即可关注我**  
  

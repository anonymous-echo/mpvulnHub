#  还是Citrix Bleed漏洞！又一家金融服务公司遭勒索   
 关键基础设施安全应急响应中心   2023-11-17 15:23  
  
**日本汽车制造商的汽车融资和租赁子公司丰田金融服务公司(TFS)最近遭受破坏性网络攻击。Medusa（美杜莎）勒索软件团伙刚刚承认对此负责。本周早些时候，TFS Europe&Africa表示，该公司“发现了系统上未经授权的活动”，这迫使该公司关闭了一些系统。TFS表示：“我们正在努力尽快让系统恢复在线，对于给我们的客户和业务合作伙伴带来的任何不便，我们深表歉意。”并补充说，该事件仅限于欧洲和非洲。这起勒索事件的影响是显而易见的，包括潜在的财务损失、监管处罚以及对公司声誉的损害，还可能会影响销售和消费者信任。运营中断还可能导致为客户和更广泛的市场提供金融服务的延迟。安全专家发文称，德国丰田金融服务公司(TFS)的的四个网站存在Citrix Bleed漏洞，大概率勒索者是利用了这个漏洞攻陷了TFS的网络。这与最近火热的工商银行的美国ICBCFS被勒索的套路如出一辙。只不过这回勒索者是Medusa。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVrQq5L9SqlA2zmu7ibd1wVMHz80gdru2nKMuesiaaxw6LicoG00Txw5FLNwUCmibYcwRVabt29JdUgtg/640?wx_fmt=png&from=appmsg "")  
  
****  
**赎金要求800万美元**  
  
虽然该公司没有明确攻击的性质，但TFS很可能受到勒索软件的攻击，因为它已被列在Medusa用来展示最新受害者的暗网泄露网站上。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVrQq5L9SqlA2zmu7ibd1wVMZ3oFNLvlaBZcPeicGMW0vQqd8BIXGVIfocDJLdTicroiapNqH2NCvSMIQ/640?wx_fmt=jpeg&from=appmsg "")  
  
丰田金融服务公司在Medusa的博客上发布了这一消息。图片来自网络新闻。  
  
Medusa的暗网博客文章表明，该团伙索要800万美元，以删除据称从TFS窃取的数据。  
  
在发表本文之前，媒体Cybernews已经联系了TFS欧洲分部，但没有收到回复。  
  
攻击者声称入侵了TFS德国分支机构。该团伙包括据称从TFS服务器获取的数据，例如租赁合同、电子邮件地址、用户名和密码、护照详细信息以及其他敏感数据。  
  
TFS是全球最大的汽车制造商丰田汽车公司的金融子公司。TFS为各大洲的丰田客户提供汽车贷款、租赁和其他金融服务。  
  
尽管丰田金融服务公司涉嫌遭受网络攻击，但其官方网站仍在正常运行，这增加了局势的不确定性。  
  
作为一家日本跨国汽车制造商的子公司，每年生产约1000万辆汽车，丰田金融服务公司的这次网络攻击如果得到证实，可能会给该公司的金融部门带来严重后果。  
  
**起因仍是Citrix Bleed漏洞**  
  
16日早些时候，在美杜莎披露TFS是他们的受害者之后，安全分析师凯文·博蒙特(Kevin Beaumont)强调，该公司的德国办事处有一个暴露在互联网上的Citrix Gateway端点，该端点自2023年8月以来就没有更新过，这表明它容易受到关键的Citrix Bleed (CVE-2023-4966)安全问题的攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVrQq5L9SqlA2zmu7ibd1wVMnWp6esUOYARgbEWUMDFjp0qhAviaKzpbeuwGI1PDsFS9BLFRHJIh5Ow/640?wx_fmt=jpeg&from=appmsg "")  
  
**几天前，有消息证实，Lockbit勒索软件攻击者利用公开的Citrix Bleed漏洞攻击了中国工商银行(ICBC)、迪拜环球港务集团(DP World)、安理律师事务所(Allen & Overy)和波音公司(Boeing)。**  
  
  
**不简单的Medusa勒索**  
  
本周早些时候，Medusa表示它已经打击了加拿大著名的金融科技公司Moneris。不过，该公司告诉Cybernews，攻击者只是“尝试”攻击，并未成功。  
  
Medusa 勒索软件（也称为 MedusaLocker）于2019年首次观察到，它以勒索软件即服务(RaaS)商业模式运行。它主要针对医疗保健和教育行业，以及处理大量个人身份信息 (PII) 的企业。美杜莎附属机构通常采用双重勒索策略，在加密之前窃取受害者的数据。如果受害者不支付赎金，他们就会受到出售或公开发布其数据的威胁。攻击者通常通过对远程桌面协议 (RDP) 进行暴力攻击、泄露RDP凭据或鱼叉式网络钓鱼攻击来窃取用户凭据，从而获得初始访问权限。  
  
据Cybernews勒索软件监控工具Ransomlooker称，Medusa在过去12个月内攻击了至少119个组织。  
  
**丰田公司在历多次网络攻击**  
  
这并不是丰田第一次面临网络挑战。2022年，该公司为其在GitHub上发布三年多的源代码可能发生的数据泄露事件道歉。  
  
2023年3月，网络漏洞导致多家日本工厂关闭，约13,000辆汽车的生产中断。  
  
2023年5月，一次规模超过披露的客户数据泄露事件影响了大洋洲和亚洲（不包括日本）的某些国家，引发了人们对丰田互联公司 (TC) 管理的客户信息安全的担忧。  
  
已经在努力应对网络威胁的汽车行业，见证了另一个主要参与者成为复杂网络攻击的受害者。丰田加入了宝马、奥迪和戴姆勒等公司的行列，面临着网络犯罪分子的挑战。  
  
Lockbit 3.0勒索软件针对EDS Automotive GmbH（多家汽车制造商的著名开发合作伙伴），危害消费者数据并凸显该行业的脆弱性。  
  
丰田金融服务公司的网络攻击提醒人们数字时代威胁形势不断升级。汽车行业必须保持警惕并积极主动地加强网络安全防御，以保护敏感数据并维护消费者的信任。  
  
  
**参考资源**  
  
1、https://thecyberexpress.com/toyota-financial-services-cyberattack/  
  
2、https://cybernews.com/news/toyota-financial-services-attack-ransomware/  
  
3、https://www.bleepingcomputer.com/news/security/toyota-confirms-breach-after-medusa-ransomware-threatens-to-leak-data/#google_vignette  
  
  

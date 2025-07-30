#  谷歌披露威胁组织攻击方式：伪造Salesforce数据加载器实施钓鱼攻击   
邑安科技  邑安全   2025-06-05 09:30  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8seAfM4pzNSTLIKaMHCQcTLaCrNWwtE87SA0Rs4Gib1Ix5MG43tGBg2yDPqKqlmHTkgqA35gHRfp8w/640?wx_fmt=png&from=appmsg "")  
  
谷歌近日披露了一个以经济利益为动机的威胁组织UNC6040的详细情况。该组织专门通过语音钓鱼（vishing）攻击入侵企业的Salesforce系统，实施大规模数据窃取和后续勒索活动。  
  
冒充IT支持人员的社交工程攻击  
  
谷歌威胁情报团队追踪发现，UNC6040组织的行为特征与网络犯罪集团The Com存在关联。该公司在向《黑客新闻》提供的报告中指出："过去几个月，UNC6040的操作者通过冒充IT支持人员实施电话社交工程攻击，已多次成功入侵目标网络。"  
  
谷歌威胁情报小组（GTIG）补充称，这种手法能有效诱骗英语员工执行某些操作，使攻击者获取访问权限或获得凭证等敏感信息，进而实施数据窃取。  
  
篡改版数据加载器的恶意利用  
  
UNC6040攻击活动中一个值得注意的特点是使用经过篡改的Salesforce Data Loader（数据加载器）。在语音钓鱼攻击过程中，受害者被诱骗授权该应用连接组织的Salesforce门户。Data Loader本是用于在Salesforce平台批量导入、导出和更新数据的合法应用。  
  
具体而言，攻击者会引导目标访问Salesforce的关联应用设置页面，批准使用名称或品牌与正版不同的篡改版Data Loader应用（如"我的票务门户"）。这一操作使攻击者获得对Salesforce客户环境的未授权访问权限，进而窃取数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8seAfM4pzNSTLIKaMHCQcTLyrraoGkLsRsAOUHKzwjlMG5Imxib1KYDpkZ9za3cKqXDMFAcVvVEic0A/640?wx_fmt=png&from=appmsg "")  
  
横向移动与后续勒索  
  
除数据泄露外，这些攻击还成为UNC6040在受害者网络中横向移动的跳板，使其能够访问Okta、Workplace和Microsoft 365等其他平台并窃取信息。  
  
部分攻击事件还涉及勒索活动，但仅在初始入侵"数月后"才出现，表明攻击者可能与其他威胁行为体合作，试图通过窃取的数据获利。谷歌表示："在这些勒索尝试中，攻击者声称与知名黑客组织ShinyHunters有关联，这可能是为了向受害者施压。"  
  
与The Com组织的关联  
  
UNC6040与The Com相关组织的相似之处在于都针对Okta凭证，并通过IT支持渠道实施社交工程攻击。这种手法也被另一个以经济利益为动机的威胁组织Scattered Spider所采用，该组织同属这个松散的有组织犯罪集团。  
  
Salesforce的应对措施  
  
Salesforce早在2025年3月就警告过此类语音钓鱼活动，称有威胁行为体通过电话冒充IT支持人员，诱骗客户员工交出凭证或批准篡改版Data Loader应用。该公司表示："我们收到报告称，攻击者诱骗客户员工和第三方支持人员访问旨在窃取凭证和MFA令牌的钓鱼页面，或诱导用户导航至login.salesforce[.]com/setup/connect页面添加恶意关联应用。"  
  
"在某些案例中，我们发现恶意关联应用是经过篡改的Data Loader，以不同名称和/或品牌发布。一旦攻击者获得客户Salesforce账户的访问权限或添加了关联应用，就会利用该应用窃取数据。"  
  
攻击趋势分析  
  
这一事件不仅凸显了社交工程攻击的持续演进，也表明IT支持人员正日益成为获取初始访问权限的攻击目标。谷歌指出："UNC6040等组织利用这种精心设计的语音钓鱼手法取得成功，表明这仍是经济利益驱动型组织突破企业防御的有效攻击媒介。"  
  
"鉴于从初始入侵到实施勒索存在较长的时间间隔，未来数周或数月内可能有多个受害组织及其下游受害者面临勒索要求。"  
  
原文来自: thehackernews.com  
  
原文链接:   
https://thehackernews.com/2025/06/google-exposes-vishing-group-unc6040.html  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
  

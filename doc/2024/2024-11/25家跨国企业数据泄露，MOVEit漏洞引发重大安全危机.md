#  25家跨国企业数据泄露，MOVEit漏洞引发重大安全危机   
 安全内参   2024-11-12 17:50  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbsnOT01rd5SO0TG32pGSkCwib3ejYxNQDn15LJbSW9BFExRglS2Q9GPTAyw5S0zMlLTcmSyuc4KTQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
近日，据网络安全公司HudsonRock报道，一名网名为“Nam3L3ss”的黑客公开发布了利用MOVEit漏洞获取的大量企业员工数据，据称来自麦当劳、汇丰、亚马逊、联想、惠普等多家知名跨国企业。  
  
  
**25家跨国企业员工数据疑遭泄漏**  
  
  
MOVEit是一款被广泛使用的文件传输软件，其漏洞（编号CVE-2023-34362）导致了2023年最严重的数据泄露事件之一，波及多个行业，包括金融、医疗、科技和零售业。  
  
  
攻击者可通过该漏洞绕过身份验证，访问敏感数据。该软件的漏洞被武器化后，导致大量知名企业的数据泄露。此次被公开泄漏的被盗数据包括来自25家跨国企业的员工详细信息，如姓名、邮箱地址、电话号码、成本中心代码和组织结构等。  
  
  
这些数据对于网络犯罪分子而言是一座“宝山”，可能被用于精准的网络钓鱼、身份盗窃，甚至复杂的社会工程攻击。  
  
  
以下是此次事件中部分受影响的25家知名跨国企业及其泄露的员工数据的记录数：  
  
- 亚马逊(Amazon)：2,861,111条记录  
  
- 大都会人寿(MetLife)：585,130条记录  
  
- 嘉德诺健康(Cardinal Health)：407,437条记录  
  
- 汇丰银行(HSBC)：280,693条记录  
  
- 富达(Fidelity)：124,464条记录  
  
- 美国银行(U.S. Bank)：114,076条记录  
  
- 惠普(HP)：104,119条记录  
  
- 加拿大邮政(Canada Post)：69,860条记录  
  
- 达美航空(Delta Airlines)：57,317条记录  
  
- 应用材料(AMAT)：53,170条记录  
  
- Leidos —52,610条记录  
  
- 嘉信理财 —49,356条记录  
  
- 3M —48,630条记录  
  
- 联想 —45,522条记录  
  
- 百时美施贵宝 —37,497条记录  
  
- Omnicom Group —37,320条记录  
  
- TIAA —23,857条记录  
  
- 瑞士联合银行(UBS) —20,462条记录  
  
- Westinghouse —18,193条记录  
  
- Urban Outfitters (URBN)  —17,553条记录  
  
- 拉什大学 —15,853条记录  
  
- 英国电信(BT) —15,347条记录  
  
- Firmenich —13,248条记录  
  
- 城市国家银行(CNB) —9,358条记录  
  
- 麦当劳 ——3,295条记录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbsnOT01rd5SO0TG32pGSkCRhnpDzia0ickciakhF3B5cgp3n6MxrnicFBJ2iaRR04EibU3RE2ic6OuIARVA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
包含超过25万名汇丰员工的泄漏数据样本 来源：HudsonRock  
  
  
泄露的数据以CSV格式发布，内容详细记录了员工的职位、联系方式及组织信息。例如，亚马逊的记录包含员工的姓名、成本中心代码、电子邮件地址和职位名称；汇丰的泄漏数据覆盖其全球员工，并标注了分支机构代码。  
  
  
**泄露的风险与潜在后果**  
  
  
此次事件不仅影响了受波及企业，还对员工的隐私和安全构成了严重威胁。主要风险包括：  
  
- 网络钓鱼和社会工程攻击：攻击者可利用泄露的详细信息定制诈骗邮件，提高其可信度，绕过企业的安全检查。  
  
- 企业间谍活动：获取组织结构和员工信息可能为恶意实体提供洞察企业内部运营的机会。  
  
- 声誉损失：亚马逊、汇丰等知名企业面临客户信任度下降的风险。  
  
- 财务欺诈与盗窃：金融行业企业的数据特别容易被用于更复杂的欺诈活动。  
  
Nam3L3ss在某知名网络犯罪论坛上发布数据，并警告企业和个人关注数据泄露的严重性，同时暗示未来可能会发布更多数据，这种做法为其他网络犯罪分子提供了便利。  
  
  
目前，研究人员尚未确认此次泄露是否与CL0P勒索软件组织有关，但涉及的企业与此前CL0P攻击的目标有所不同。  
  
  
**应对措施与建议**  
  
  
对于使用MOVEit或类似文件传输系统的企业，此次事件再次敲响警钟。以下是关键防护措施：  
  
- 立即应用安全补丁：MOVEit已发布针对CVE-2023-34362的补丁，受影响企业应尽快更新系统。  
  
- 全面安全审计：受波及企业需进行全面安全检查，排查潜在漏洞。  
  
- 员工安全意识培训：强化员工对网络钓鱼和安全通信的防范意识，构建第一道安全防线。  
  
- 数据访问限制与分区：通过角色权限控制和数据分区，减少敏感信息的暴露范围。  
  
  
  
**结语**  
  
  
MOVEit漏洞事件再次凸显了快速管理漏洞和实施网络安全防护的重要性。在网络威胁日益复杂的背景下，各行业需将网络安全文化建设与技术防护相结合。  
  
  
对于受影响企业而言，应迅速采取应对措施、保护员工隐私并恢复客户信任是当务之急。此次事件再次提醒我们，敏感数据管理系统的安全性需要持续审查和加强，唯有如此，才能在不断变化的威胁中保持足够的安全弹性。  
  
  
参考链接：  
  
https://www.infostealers.com/article/massive-moveit-vulnerability-breach-hacker-leaks-employee-data-from-amazon-mcdonalds-hsbc-hp-and-potentially-1000-other-companies/  
  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
文章来源：GoUpSec  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  

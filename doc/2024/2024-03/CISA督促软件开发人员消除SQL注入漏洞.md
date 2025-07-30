#  CISA督促软件开发人员消除SQL注入漏洞   
Sergiu Gatlan  代码卫士   2024-03-26 17:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**CISA 和 FBI 督促技术制造企业管理层对所在组织机构的软件提起正式审计并执行缓解措施，在软件交付前消除SQL注入 (SQLi) 漏洞。**  
  
  
在SQL注入攻击中，威胁行动者将恶意构造的 SQL 查询“注入”数据库查询中所使用的字段或参数中，利用应用程序中的漏洞来执行非计划SQL命令如提取、操作或删除存储在数据库中的敏感数据。  
  
因与目标数据库交互的web应用或软件中的输入验证和清理不当，这可导致机密数据越权访问、数据泄露甚至是目标系统遭完全接管。CISA 和 FBI 建议使用实现写好语句的参数化查询，阻止SQL注入漏洞。这种方法将SQL代码与用户数据加以区分，使得恶意输入不可能被解释为 SQL 语句。与输入清理技术相比，参数化查询时设计安全方法的更好选择，因为前者可被绕过且难以大规模执行。  
  
SQL注入漏洞在MITRE 于2021年和2022年发布的“前25个最危险的弱点”中排行第三，仅次于界外写和跨站脚本攻击。CISA和FBI指出，“如果他们发现代码存在漏洞，高管们应当确保所在组织机构的软件开发人员立即开始执行缓解措施，从所有当前和未来软件产品中消除整个缺陷类型。在设计阶段直到开发、发布和更新阶段集成该缓解措施，可以缓解客户的网络安全负担以及公众所面临的风险。”  
  
CISA和FBI在 Clop 勒索团伙从2023年5月利用 Progress MOVEit Transfer文件传输管理 app 中的一个 SQLi 0day（影响全球数千家组织机构）后发布了该联合告警。多家美国连班该机构和两个美国能源部实体也是这些数据盗取攻击的受害者。尽管受害者众多，Coveware 认为仅有少部分受害者可能会支付赎金。尽管如此，该勒索团伙可能获得的赎金在750万到1亿美元之间。  
  
本周一，CISA和FBI提到，“尽管20年来广泛传播SQLi 漏洞的知识和问的那个，以及存在多种有效缓解措施，但软件制造商仍然持续开发含有该漏洞类型的产品，导致很多客户面临风险。SQLi类型漏洞自2007年开始就被其他人视作“无法原谅的”漏洞”。尽管如此，SQL类型的漏洞（如CWE-89）仍然是广泛传播的漏洞类型。”  
  
上个月，白宫国家安全总监办公室 (ONCD) 督促技术企业采用内存安全编程语言（如 Rust），通过消减内存安全漏洞的数量来改进软件安全。1月份，CISA还要求SOHO路由器厂商确保自己的设备可防御正在实施的攻击活动。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA 和NCSC 联合发布关于保护AI系统开发安全新指南](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518230&idx=2&sn=94df38d729915d3d00667b7c6f0c6474&chksm=ea94b97cdde3306a14d3c8c474ec8d004fcd77136e1f765d3cf12cf77ac5d345bc45e1acfb69&scene=21#wechat_redirect)  
  
  
[Cacti 监控工具受严重的SQL漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518617&idx=1&sn=25166b9f0e3966ea230b4150475573f2&chksm=ea94b8f3dde331e50b68b955b7fafbab44be937374b69ae0c44480093c778a19caa3b03b3cfd&scene=21#wechat_redirect)  
  
  
[【缺陷周话】第 2 期 ：SQL 注入](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488076&idx=1&sn=3101e6e5a7285c7f71a5f04e78f90709&chksm=ea972326dde0aa30ce0137e0996a536f51e6e2d23eb2a31aac3cdb47c342ff9672baf8699a1b&scene=21#wechat_redirect)  
  
  
[3CX 提醒客户禁用 SQL 数据库集成功能](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518402&idx=1&sn=da9d1a39d4b697106a57a34d89cff0d1&chksm=ea94b9a8dde330be50e062f6d96b932dc3f586d2c94a6af6ff7ebd6da5c5ff1ccc7b6e7aeda1&scene=21#wechat_redirect)  
  
  
[Zendesk 分析服务中存在严重的 SQLi 和访问漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514647&idx=2&sn=85d6735e3f4fc041e604b2661c4c5601&chksm=ea948b7ddde3026b2f99931a430e457979aa407a4fa91f58a723b7586dcdf3efac4a02f49fcc&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/cisa-urges-software-devs-to-weed-out-sql-injection-vulnerabilities/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

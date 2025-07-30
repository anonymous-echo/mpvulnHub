#  可能吗？CISA竟想“彻底终结”SQL漏洞   
小薯条  FreeBuf   2024-03-27 18:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib5ic2tKzv4pphJqfd9E1X8NBYIaWic6U9yNVibiaFZiaOnueceHPxQ997P3pMaFnBjiaqBibno91g54X1XA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib5ic2tKzv4pphJqfd9E1X8NpjiceHXRQM53NDfsnETyRMeAibo7rlCdibJyl7PRzZSkgibuic8xba6Y3rQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JcmJkSNlj0EXzd5YeCVicH1d96DtF4ia47Grj3Lvy3Sm3MK9su0tF9oKHb7xhbqia1IdiaUOX79tIhPj/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JcmJkSNlj0EXzd5YeCVicH1d96DtF4ia47Grj3Lvy3Sm3MK9su0tF9oKHb7xhbqia1IdiaUOX79tIhPj/640?wx_fmt=svg&from=appmsg "")  
  
  
  
3月25日（本周一），网络安全与基础设施安全局（CISA）和联邦调查局（FBI）发布了 "安全设计 "警报。他们将 SQL 注入漏洞（SQLi）归入"不可饶恕的 "一类漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib5ic2tKzv4pphJqfd9E1X8NhvLzVBib2SrI1Fq29MIyJ6ZCKB2Wl8bfj5xRzM4S52jtiba0oP7yENEg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
警报指出：尽管在过去二十年中，人们普遍了解并记录了 SQLi 漏洞，而且也有了有效的缓解措施，但软件制造商仍在继续开发存在这一缺陷的产品，这使许多客户面临风险。  
  
  
在 SQL 注入攻击中，威胁行动者将恶意构造的 SQL 查询“注入”数据库查询中所使用的字段或参数中，利用应用程序中的漏洞来执行非计划SQL命令如提取、操作或删除存储在数据库中的敏感数据。  
  
  
因与目标数据库交互的 web 应用或软件中的输入验证和清理不当，这可导致机密数据越权访问、数据泄露甚至是目标系统遭完全接管，CISA 和 FBI 建议使用实现写好语句的参数化査询，阻止SQL注入漏洞。  
这种方法将SQL代码与用户数据加以区分，使得恶意输入不可能被解释为 SQL语句。  
  
  
与输入清理技术相比，参数化査询是设计安全方法的更好选择，因为前者可被绕过且难以大规模执行。  
  
  
SQL注入漏洞在MITRE 于2021年和2022年发布的“前25个最危险的漏洞"中排行第三，仅次于越界写入漏洞和跨站脚本攻击。越界写入漏洞是一种软件漏洞，会导致程序在分配的内存区域边界之外写入。端点崩溃，或者执行任意代码等后果。威胁行为者通常通过写入比分配的内存区域的大小更大的数据或将数据写入内存区域内的错误位置来滥用此漏洞。  
  
  
CISA 和 FBI 指出，"如果他们发现代码存在漏洞，高管们应当确保所在组织机构的软件开发人员立即开始执行缓解措施，从所有当前和未来软件产品中消除整个缺陷类型。在设计阶段直到开发、发布和更新阶段集成该缓解措施，可以缓解客户的网络安全负担以及公众所面临的风险。  
  
  
几十年来，软件行业一直知道如何大规模消除 SQLi 缺陷。然而，威胁分子去年就利用了开发商 Progress 的 MOVEit 文件传输软件中的这样一个漏洞，造成了毁灭性的后果。  
  
  
去年5月， Clop 勒索团伙利用了 Progress MOVEit Transfer文件传输管理 app 中的一个 SQLi 零日漏洞，该漏洞影响全球数千家组织机构，随后 CISA 和 FBI 立即发布了联合告警。尽管此案的受害者众多，但Coveware认为仅有少部分受害者可能会支付赎金。即便如此，据估计该勒索团伙可能获得的赎金仍在750万到1亿美元之间。  
  
  
据 CISA 称，SQLi 攻击之所以能够得逞，是因为开发人员没有将用户提供的内容视为潜在的恶意内容。它不仅会导致敏感数据被盗，还会使坏人篡改、删除数据库中的信息或使其不可用。  
  
  
警报敦促技术制造商遵循三项指导原则：  
  
- 通过执行正式的代码审查并使用“带有参数化查询的预制语句”作为标准做法，对客户安全结果负责   
  
- 通过确保 CVE 记录的正确性和完整性、记录漏洞的根本原因并努力消除整个类别的漏洞，实现“彻底”的透明度和问责制   
  
- 将业务目标重新调整为安全设计软件开发，包括进行正确的投资和建立激励结构。这最终有助于降低财务和生产力成本以及复杂性   
  
CISA 和 FBI 督促技术制造企业管理层对所在组织机构的软件提起正式审计并执行缓解措施，在软件交付前消除SQL注入(SQLi) 漏洞。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://www.infosecurity-magazine.com/news/cisa-fbi-renewed-effort-eliminate/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492995&idx=1&sn=cd4660fdf363a0173e2e8fa7f3879710&chksm=ce1f1f1cf968960ac99038a74f5ac2b9718e581753b97ff86f473ae80f1c2cc0e17fa3ed60de&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492835&idx=1&sn=a76625a0ed94ef9e3ccce9c92b384984&chksm=ce1f1e7cf968976aa3947aa7f69fe9318187d8160fa930c46e7347de2c2d7e1290164b0661e1&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

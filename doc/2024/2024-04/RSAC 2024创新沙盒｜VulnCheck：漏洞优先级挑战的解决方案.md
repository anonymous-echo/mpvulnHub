#  RSAC 2024创新沙盒｜VulnCheck：漏洞优先级挑战的解决方案   
绿盟君  绿盟科技   2024-04-26 15:36  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/IpYUt4DIvZeY4og8A2eV4eWjeETKjSSqbcHVicerQAVghZGiak4yjsW6wFMUmDfMkAjO2puhibzCJr8HKjJAicjXmQ/640?wx_fmt=gif "")  
  
5月6日  
  
RSA Conference 2024  
  
将正式启幕  
  
作为“安全圈的奥斯卡”  
  
RSAC 创新沙盒（Innovation Sandbox）  
  
已成为网络安全业界的创新标杆  
  
  
创新之下  
  
与绿盟君一道  
  
聚焦网络安全新热点  
  
洞悉安全发展新趋势  
  
走进  
****VulnCheck  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZeY4og8A2eV4eWjeETKjSSqYXfdvJghiarO9dqQj63clbmuGibVWnOYRmksIJuRcmLsS4iaNjWDrt5qA/640?wx_fmt=png "")  
  
*RSAC 2024 创新沙盒十强  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZdHZEMOpAMA6IpSCsslg5KeJkhrd8VdG38ibsRRb77ibyRg9JuTfZF1riaZHzMU01kyicftDX5lQjGE5Q/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZeY4og8A2eV4eWjeETKjSSquXxcWz8ibTRJq4Zgzm6ic2xwIcJMnCLAbHl2yYBIWPiaBAnunFW1I1ibGA/640?wx_fmt=png "")  
  
  
**公司介绍**  
  
VulnCheck是一家漏洞情报公司，主要业务是帮助企业、政府组织和网络安全供应商解决漏洞优先级的挑战。VulnCheck 的平台可以提供全面、实时的漏洞和情报，并与独特的专有漏洞和威胁情报自动关联，自动化地进行漏洞优先级的划分，从而帮助网络安全团队超越对手。  
  
  
VulnCheck创办于2021年，总部位于美国列克星敦州。其在2023年2月获得了种子轮320万美元的投资。  
  
  
其创始人团队阵容如图1所示[1]。Anthony-Bettini是VulnCheck的CEO和创始人，VulnCheck是Anthony-Bettini第三次创业的公司， Anthony 的第一家初创公司 Appthority 是一家移动安全公司，在 RSA Innovation Sandbox 上推出，赢得了“年度最具创新公司”奖，后来被赛门铁克收购。随后他创立了 FlawCheck，这是一家专注于 Docker 的容器安全初创公司，后来也被 Tenable 收购。  
  
  
Ralph Logan是VulnCheck的首席战略官，他在情报界担任过多个职务，并且他还是一家网络安全服务公司的创始人/首席执行官。他将帮助制定 VulnCheck 的整体战略和运营方法以发展业务。  
  
  
Jacob Baines是VulnCheck的首席技术官，他曾在 Rapid7、Dragos、Dark Wolf 和 Tenable 担任多个漏洞研究、漏洞利用开发和检测方向的领导职务。Jacob 在 Black Hat、DEFCON 和 InfoSecurity Europe 等多个会议上展示了他的研究成果。Jacob 在情报界也拥有广泛的背景，他参与了逆向工程、漏洞研究和 CNO 工具的研发。他负责 VulnCheck 的整体技术和研究策略。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZdHZEMOpAMA6IpSCsslg5KemQeFyhicWK3mgcMfhELf2kWSPADmTua8hVeicCYoOVkqSQgXNCUibN0Pg/640?wx_fmt=png "")  
  
图1 VulnCheck创始人（从左往右依次是Anthony Bettini、Ralph Logan、Jacob Baines）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZeY4og8A2eV4eWjeETKjSSquXxcWz8ibTRJq4Zgzm6ic2xwIcJMnCLAbHl2yYBIWPiaBAnunFW1I1ibGA/640?wx_fmt=png "")  
  
  
**相关背景**  
  
**漏洞利用，而不仅仅是漏洞**  
  
  
  
  
根据安全公司Qualys发布的“2023 年网络威胁安全回顾”报告显示，2023年全球共披露了26447个计算机漏洞，平均每天披露了72.46个CVE，为“历年之最”，相比2022年的25050个漏洞，多了5.2%。在已披露的漏洞中，有超过7000个漏洞具有“PoC代码”，206个漏洞具有可用的武器化利用代码，有115个漏洞已经被黑客“广泛利用”[4]。Mandiant 在2023年4 月份在 RSAC 上的主题演讲中透露，2022 年追踪到的违规行为中有 32% 是漏洞利用，占比第一（之前都是网络钓鱼邮件）[5]。  
  
  
CISA的统计称大概只有不到4%的漏洞被真正利用[6]，大量的漏洞可能就只是一个编号。在国际通用的漏洞评价方法中，漏洞的可利用性已成为了重要评价指标。对于一家网络安全运营者来说，其不一定会成为0-day漏洞的攻击目标，但如果其存在的漏洞在别的地方被证明成功利用过，并且没有及时打补丁，遭受攻击的风险是巨大的。因此，如何提高漏洞利用成功率，如何从百万漏洞中挑选出可利用的漏洞成为了业界的一个难题。而这正就是VulnCheck所从事的主要内容：漏洞利用、漏洞情报和漏洞管理， VulnCheck主要利用安全研究人员的专业知识来构建实时解决方案，该解决方案不需要针对 CISA KEV（KNOWN EXPLOITED VULNERABILITIES CATALOG） 构建脚本，而是通过将漏洞情报与利用情报相结合、主动跟踪威胁行为者等方法去收集并关联更多的漏洞利用信息，基于此，其管理漏洞的利用次数比其他解决方案多 5 倍[5]，具体内容见下文产品介绍。  
  
**CISA KEV**  
  
  
  
  
已知被利用漏洞目录（KEV）是美国在2021年11月3日建立的，在这个目录中的漏洞正在被威胁者利用。据统计，仅2022年，KEV目录就新增了557个CVE，平均每周都有将近 11 个新的在野利用漏洞被添加到目录中。并且在 557 个 CVE 中，有 93 个 (17%) 使用 CVE-2022 标识符，平均每周都会发现2个新发布的被利用漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZeY4og8A2eV4eWjeETKjSSquXxcWz8ibTRJq4Zgzm6ic2xwIcJMnCLAbHl2yYBIWPiaBAnunFW1I1ibGA/640?wx_fmt=png "")  
  
  
**产品介绍**  
  
VulnCheck目前提供五款产品，其中两款商业产品：Exploit & Vulnerability Intelligence和Initial Access Intelligence，三款免费的社区产品：VulnCheck KEV、NIST NVD ++和VulnCheck XDB。  
  
**Exploit & Vulnerability Intelligence**  
  
  
  
  
漏洞利用和漏洞情报产品可以帮助用户就哪些漏洞需要立即修复做出更好更快地决策。与其他纯粹以漏洞为中心的解决方案不同，VulnCheck 将利用情报与漏洞情报结合在一起，通过将两者相结合，可以获得对漏洞优先级和修复的更好见解。  
  
  
根据其官网介绍[2]，该产品具有以下四大优势：  
- 平均比NIST NVD提前14天获取信息，从而更快做出响应；  
  
- 拥有业界最大的漏洞利用PoC和漏洞在野利用的证据集合；  
  
- 完整利用时间线，涵盖漏洞首次披露的时间、首次发现利用证据的时间和修复漏洞的时间；  
  
- 优先针对最关键的漏洞（即那些在野外被积极利用的漏洞）进行修复工作。  
  
**情报来源更多**  
  
VulnCheck漏洞利用和漏洞情报持续跟踪数百个已被报告在野外利用特定漏洞的指定威胁参与者。VulnCheck 从各种来源收集威胁行为者信息，然后将这些信息关联到业界最容易使用的漏洞情报产品中。然而由于不同供应商命名威胁行为者的方式不同，这使得关联威胁行为者变得更具挑战，VulnCheck通过支持多种命名方案来帮助用户轻松地找到威胁参与者[12]。  
  
  
除此之外，VulnCheck还跟踪数十个供应商和政府的建议，然后将这些数据和已有的漏洞情报结合。由于NIST在NVD中发布CVE时存在滞后性，并且VulnCheck漏洞利用和漏洞情报产品监控的来源远不止NVD，这使得该产品可以比NIST NVD更早地获取到漏洞信息，即平均比NIST NVD提前14天获取信息。  
  
  
**情报内容更为广泛**  
  
整体来说，VulnCheck的漏洞利用和漏洞情报产品针对每一个漏洞都包含以下信息：漏洞别名、CVSS 时间评分、漏洞分类数据、供应商和政府建议；与其他漏洞数据库不同的是，VulnCheck 还包含相关漏洞更广泛的最新信息，包括：  
  
  
(1) 开源包/依赖项中的漏洞  
  
(2) ICS/OT、IoMT、IoT、移动等设备中的漏洞  
  
  
除此之外，VulnCheck 漏洞利用和漏洞情报还包括其他来源通常无法提供的独特字段，例如[8]：  
- 1) 漏洞状态  
  
- 2) 分类（例如 ICS/OT、IoMT、IoT、移动、服务器软件等）  
  
- 3) MITRE ATT&CK 映射  
  
- 4) MITRE 攻击模式 (CAPEC) 映射  
  
- 5) 2008 年之前的 CVE 的 CWE 协会  
  
- 6) 更多供应商参考  
  
- 7) 更多利用参考  
  
- 8) 更少损坏的链接  
  
- 9) 更干净的 CPE 数据  
  
- 10) 能够通过包 URL (purl) 进行查询  
  
  
  
**Initial Access Intelligence**  
  
  
  
  
Initial Access Intelligence为用户提供内部开发的漏洞PoC、PCAP 文件、用于检测漏洞的 Suricata 和 Snort 签名、YARA 规则（如果有）、CPE 字符串、版本扫描仪、映射到 GreyNoise 标签以及使用 Censys 和 Shodan 对潜在易受攻击的系统进行互联网级的暴露测量。借助这些能力，Initial Access Intelligence可以帮助用户抵御已被利用或可能很快被利用的初始访问漏洞。  
  
  
根据其官网介绍[3]，Initial Access Intelligence产品具有以下四大优势：  
- 只关注重要的漏洞；  
  
- 关注初始访问漏洞，初始访问漏洞是远程代码执行漏洞的一个子集，对于组织来说是最危险的漏洞，因为它们会导致远程、未经身份验证、无需点击的数据泄露；  
  
- 提供早期检测工具以快速实施防御；  
  
- 提供私有PoC来测试用户的防御系统。  
  
如图2和图3所示，Initial Access Intelligence提供以下检测工具和漏洞潜在暴露情况的元数据来详细描述该漏洞[9]：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZdHZEMOpAMA6IpSCsslg5KeQm1NWEjwqcH8mfLQD7HCbznLUzarviabf2DO89Py2Dpjnz9ZMS1ic57g/640?wx_fmt=png "")  
  
图2 Initial Access Intelligence检测工具  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZdHZEMOpAMA6IpSCsslg5KeLBTcpwPttSyAHJ24cN41ibs0JK05oHo4b1YJpDPXgE2k8T9cenKpk9Q/640?wx_fmt=png "")  
  
图3 Initial Access Intelligence提供的漏洞暴露情况的元数据  
  
除此之外，VulnCheck的Initial Access Intelligence产品还跟踪可能成为初始访问攻击目标的潜在易受攻击的系统，以及跟踪命令和控制 (C2) 攻击者基础设施。VulnCheck 对数十种命令和控制 (C2) 攻击者基础设施类型进行指纹识别，将这些指纹与现有的互联网基础设施映射技术（如 Shodan 或 Censys）以及 VulnCheck 开发的扫描仪一起利用，以维护一个恶意 IP 地址列表。  
  
**免费的社区产品**  
  
  
  
  
**VulnCheck KEV**：帮助企业、政府机构和供应商轻松了解哪些漏洞已被利用。相比于CISA的KEV目录，VulnCheck多跟踪了 876 个（或 81.04%）被利用的漏洞，并且在将缺失的漏洞添加到 CISA KEV 目录之前，平均提前了 27 天向客户发出警报。  
  
  
**NIST NVD ++**：由于在使用NIST NVD会面临着各种各样的问题，比如访问 NVD 2.0 API 经常出现超时或 503 服务不可用错误，因此VulnCheck将NIST NVD迁移到NVD++，建立自己的社区。  
  
  
**VulnCheck XDB**：这是托管在git存储库上的最全面的漏洞Exp和PoC存储库，XDB通过监控漏洞首次出现的来源（即git存储库）来简化获取漏洞信息的过程[10]。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZeY4og8A2eV4eWjeETKjSSquXxcWz8ibTRJq4Zgzm6ic2xwIcJMnCLAbHl2yYBIWPiaBAnunFW1I1ibGA/640?wx_fmt=png "")  
  
  
**总结**  
  
VulnCheck是一家总部位于美国列克星敦州的漏洞情报公司，成立于2021年。他们的主要业务是为企业、政府组织和网络安全供应商解决漏洞优先级的挑战。通过提供全面、实时的漏洞和情报，以及自动关联专有漏洞和威胁情报，VulnCheck帮助网络安全团队超越竞争对手。公司创始人团队包括CEO Anthony Bettini、首席战略官Ralph Logan和首席技术官Jacob Baines，他们都在安全领域有丰富的经验。VulnCheck的产品包括商业产品Exploit & Vulnerability Intelligence和Initial Access Intelligence，以及免费的社区产品VulnCheck KEV、NIST NVD ++和VulnCheck XDB。这些产品帮助用户更好地了解漏洞和威胁，加强网络安全防御。  
  
  
最后，笔者认为，漏洞管理、漏洞情报在漏洞研究中并不能算是一个新兴的赛道，相应的技术路线、方法已经相对较为清晰，可能最后不同厂商能比拼的就是在细节上的处理，谁能将收集更多的情报数据并有效地关联它们，谁能在漏洞情报数据的基础上再借助其它安全工具为用户提供更便捷、更高质量的服务，谁就能在竞争中胜出。  
  
参考文献  
  
[1] https://vulncheck.com/company/about  
  
[2] https://vulncheck.com/product/exploit-intelligence  
  
[3] https://vulncheck.com/product/initial-access-intelligence  
  
[4] https://www.sohu.com/a/756977451_120846244  
  
[5] https://vulncheck.com/blog/joining-vulncheck  
  
[6] https://www.secrss.com/articles/46094  
  
[7] https://vulncheck.com/blog/2022-cisa-kev-review  
  
[8] https://docs.vulncheck.com/products/exploit-and-vulnerability-intelligence/vulnerability-intelligence  
  
[9] https://docs.vulncheck.com/products/initial-access-intelligence/detection-artifacts  
  
[10] https://www.businesswire.com/news/home/20230525005258/en/VulnCheck-Launches-XDB-The-Most-Comprehensive-Hub-of-Exploits-for-Modern-Security-Teams  
  
[11] https://www.vulinsight.com.cn/#/product  
  
[12] https://docs.vulncheck.com/products/exploit-and-vulnerability-intelligence/threat-actor-naming  
  
  
  
【推荐阅读】  
- [RSAC 2024创新沙盒｜未来防线：Harmonic Security在AI时代的数据守护](http://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650450808&idx=2&sn=3ce85482f19a764438766e5619f9e92d&chksm=bec9f2d389be7bc5b8c9eab211dcec7cf980fb64a545842048ff1c12dafdfd90625bff97f7cf&scene=21#wechat_redirect)  
  
  
- [RSAC 2024创新沙盒｜Bedrock Security:无缝衔接的高效数据安全解决方案](http://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650450895&idx=2&sn=c02bc14ffc7772b658a14837de97bb43&chksm=bec9f26489be7b72ac88e6c8f9db7768f8862a8a393614a666f680286493c6fa3bac0bc6e771&scene=21#wechat_redirect)  
  
  
- [RSAC 2024创新沙盒｜Mitiga：新一代云和SaaS 事件响应解决方案](http://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650450986&idx=1&sn=96cf9b712d7951754d696456aac594b3&chksm=bec9f58189be7c97bbe3160d82e18558481e451feb2a7b5e6fdb27fd8469bf6855526120f01c&scene=21#wechat_redirect)  
  
  
- [RSAC 2024创新沙盒｜Antimatter：全方位数据安全管理利器](http://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650451154&idx=4&sn=39d9a614024d9787539f65396b4fffe1&chksm=bec9f57989be7c6ff2d6905930d16113fc11244dc388afecd485b4450489558e08743545e20b&scene=21#wechat_redirect)  
  
  
- [RSAC 2024创新沙盒｜RAD Security：云原生异常行为检测和响应新方案](http://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650451248&idx=2&sn=46e1f72ee3bdb4f624dad37fdafdffca&chksm=bec9f49b89be7d8d784d43a029156103a9bf288ff3bba5ce909e8429fb79030813c9dc51fb6e&scene=21#wechat_redirect)  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZegkEFpP4fL9ibUPiaIFan451wLNJibXpcCOgfDV1cmlIjiczs3XZYibj8OFtZ7Tvf77mnTLp6LIERMm3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650450592&idx=1&sn=61111a27cc11b55bb3998b915c798b27&chksm=bec9f30b89be7a1d3a2bf8d1a103fec1e75d7bd16ad508042157eee8c1d3e23174039ecc51fe&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650450852&idx=1&sn=e14332344455968feba8b83455f37d1d&chksm=bec9f20f89be7b19875a16b99e3f9c4edb3cd78ad9eab1b9ac0685b5b95f107448c5e9494f63&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650450457&idx=1&sn=32eb446ebb5162c654d0a85726ed64dd&chksm=bec9f3b289be7aa4670afe67e05a30bf7db63341514688c6133fb76fc1912abf3cf053ef299e&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/IpYUt4DIvZegkEFpP4fL9ibUPiaIFan451jMWXWIA8yj3dEtLY9KIVzKGNbzZ9zzyVskGsFyAibiblgNSfOIPHN13w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  

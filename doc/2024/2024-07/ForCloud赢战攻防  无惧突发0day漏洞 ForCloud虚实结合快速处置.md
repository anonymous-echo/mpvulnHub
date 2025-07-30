#  ForCloud赢战攻防 | 无惧突发0day漏洞 ForCloud虚实结合快速处置   
你信任的  安全狗   2024-07-25 18:38  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbFMhbTJGM0z56mDBTCS1X0ibIA1aNrBpEq6Jg7QlSxbzX3XCP703ibdvnmxqH8h511r3ZvGLfux11bg/640?wx_fmt=jpeg "")  
  
  
攻防演练前夕，亚信安全威胁情报中心监测到一个存在于Nacos Derby中的0day漏洞，漏洞利用代码为公开状态，攻击者利用此漏洞可在目标服务器上执行任意代码。  
  
  
**造成的破坏程度？你可能正在使用！**  
  
  
Nacos（Dynamic Naming and Configuration Service）是构建云原生应用的平台，具有注册中心、配置中心和动态 DNS 服务三大功能，能够便利实现动态服务发现、配置管理以及服务管理，并与 Springcloud、Spring、Dubbo 等框架无缝对接，在国内应用比较广泛。  
  
  
由于Alibaba Nacos部分版本中derby数据库默认可以未授权访问，恶意攻击者利用此漏洞可以未授权执行SQL语句，最终导致任意代码执行，加之此次Nacos Derby的0day漏洞PoC已在互联网上公开，因此可能造成的影响范围广泛且严重性极高。  
  
  
  
**漏洞关键信息与复现**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFMhbTJGM0z56mDBTCS1X0ib2RqKibjLZQ1zkvo4fbQ2Y0Y6xic4uxnzDFUiaQiaT3yyCdkLuyFcpEOXXQ/640?wx_fmt=png "")  
  
  
攻击机：执行恶意载荷（写入文件）；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbFMhbTJGM0z56mDBTCS1X0ibJoHjNPuNMYKJMACmfXGoib2HCLb2h79s1NdunrakXGSmLX7s6ib5fUeQ/640?wx_fmt=jpeg "")  
  
靶机：被远程写入文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbFMhbTJGM0z56mDBTCS1X0ib76ovQljib2fPkXQjoRT7vB0mdiaXoaqe0kFm1WibbKcoLJm5s7MGbzb9A/640?wx_fmt=jpeg "")  
  
  
**0day，看不见的攻城巨锤**  
  
  
  
  
  
目前，正值攻防演练的重要阶段，类似的0day可能成为红队手中极为罕见且威力惊人的秘密武器，在对方毫无察觉的情况下，形成一举攻陷防护堡垒的致命一击。  
  
  
**未知与突发性。**0day 漏洞是尚未被公开披露和知晓的安全漏洞，一旦出现，在无准备、无信息、无对策的情况下，让防守方措手不及。  
  
  
**应对无方。**没有官方发布的补丁或成熟的修复方案，面对0day，防御方需要在短时间内快速响应，并研究和探索解决办法，不仅难度高，效果往往很有限。  
  
  
**攻击多样复杂。**利用 0day 漏洞，攻击者可以结合多样且复杂的手法进行进一步攻击行为，让防守方难防难测。  
  
  
时间紧压力大。在攻防演练有限的时间内，防守方应对 0day 漏洞，需要快速进行调查、分析和处置，耗费大量时间同时，可能导致无法及时有效地应对，处境极为被动。  
  
  
**ForCloud，虚实结合，无惧0day漏洞威胁**  
  
  
  
  
  
  
  
**信舱虚+实双补丁综合方案：****提升生产环境漏洞修复率**  
  
  
通过信舱，客户可通过“应急漏洞”以及“虚拟补丁”等功能，进行漏洞的处置与响应。  
  
  
云工作负载安全产品部署越多越广，也带来了一个新问题：生产环境“海量漏洞”且修复率低，这一现象普遍存在了很多年。当然，修复所有漏洞是不现实的，哪些是可修复和应该修复的漏洞呢？因此，亚信安全2024年重点新推虚/实补丁综合方案，结合漏洞运营 情报数据，帮助用户化解安全“债务”，通过“虚实补丁结合”，让漏洞补丁“可以打”、“放心打”，提升漏洞修复率。  
  
  
信舱虚/实补丁综合方案已在某电网等大型集团广泛部署应用，形成了历史必打漏洞处置、月度安全更新、零日漏洞响应、多层次分阶段的漏洞治理、指标成效量化等经过实战验证的方法论，助力用户漏洞安全运营方便落地、快出实效。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFMhbTJGM0z56mDBTCS1X0ibGSKFtQXlKwibMnxympoicQ5cwYxK1MrZdPL51DnPibljnAAPuNvjCI6Yg/640?wx_fmt=png "")  
  
  
  
**“应急漏洞”+“虚拟补丁”技术实践**  
  
  
通过信舱的“应急漏洞”功能进行检测，在事前发现漏洞风险；从而，用户可基于这些风险提示进一步收敛攻击面；  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbFMhbTJGM0z56mDBTCS1X0ibz82msq38IZAXmLPYsOV4XoiaNV0G7fllRWBYlibA0f5wuia4OOHc68HCw/640?wx_fmt=jpeg "")  
  
  
此时，可进一步通过信舱的“虚拟补丁”功能对攻击Payload进行检测与拦截，在事中防御漏洞攻击。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbFMhbTJGM0z56mDBTCS1X0ibegRENvicbbHuccBqDyZOtYgicAb2XgbdxTSDHwB57B4W6OxPoOiaO9fZg/640?wx_fmt=jpeg "")  
  
  
除了Nacos Derby远程执行漏洞外，对于大型攻防演练期间出现的其他0day漏洞，ForCloud能够结合信舱虚/实补丁综合方案快速地进行漏洞检测与响应。针对0day漏洞所具备的隐蔽性和破坏性特点，云安全团队建议用户单位快速安装使用信舱ForCloud，以防止攻击队的绕过与入侵。  
  
  
**ForCloud攻防演练全栈方案**  
  
  
  
  
  
  
  
**亚信安全·云主机深度安全防护系统**  
  
  
亚信安全云主机深度安全防护系统采用Gartner提出的CWPP理念，提出了以工作负载为中心，以自动化、细粒度资产采集为基础，提供多种风险排查和漏洞发现手段，依托反杀伤链和实时入侵检测响应能力支撑企业安全防护二道防线，解决现代混合云、多云数据中心基础架构中服务器工作负载的安全需求，最终达到对已知威胁的自动响应以及对潜在威胁的检测识别。  
  
  
  
**亚信安全·云主机深度安全防护系统-WEB应用防护**  
  
  
亚信安全·云主机深度安全防护系统-WEB应用防护模块，通过网络层过滤和主机应用层自保护（RASP）相结合的技术，既能够过滤传统常见的攻击又可以对异常变形和未知漏洞的高级攻击进行识别，达到双层纵深防御的效果。  
  
  
  
**亚信安全·云主机深度安全防护系统-主机漏洞发现及补丁修复系统**  
  
  
亚信安全·云主机深度安全防护系统-发现及补丁修复模块可以为用户构建属于自己的补丁大数据仓库，用于修补可能导致安全薄弱、破坏关键系统数据或导致系统不可用的漏洞。云网不仅可以进行补丁部署，还可扫描网络漏洞、识别缺失的安全补丁和修补程序，并立即部署以降低网络空间风险。  
  
  
  
  
****  
  

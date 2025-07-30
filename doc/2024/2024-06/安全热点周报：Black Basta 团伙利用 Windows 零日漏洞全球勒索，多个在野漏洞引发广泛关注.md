#  安全热点周报：Black Basta 团伙利用 Windows 零日漏洞全球勒索，多个在野漏洞引发广泛关注   
 奇安信 CERT   2024-06-17 17:26  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 美国政府发布2023网络安全年报披露11起重大事件</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 勒索攻击迫使越南国家邮政服务瘫痪超3天</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 《网络安全标准实践指南—敏感个人信息识别指南》公开征求意见</p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.SolarWinds Serv-U 目录遍历漏洞(CVE-2024-28995)安全风险通告**  
  
  
6月14日，奇安信CERT监测到官方修复SolarWinds Serv-U 目录遍历漏洞(CVE-2024-28995)，SolarWinds Serv-U 容易受到目录横向漏洞的影响，未经身份认证的远程攻击者通过构造特殊的请求可以下载读取远程目标系统上的任意文件，对机密性造成很高的影响。目前该漏洞技术细节与EXP已在互联网上公开，鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Google Pixel 权限提升漏洞(CVE-2024-32896)**  
  
  
6月 13 日，美国网络安全和基础设施安全局 (CISA) 在其已知利用漏洞 (KEV) 目录中添加Google Pixel 权限提升漏洞(CVE-2024-32896)，由于代码中的逻辑错误，存在一种可能的绕过方法。这可能导致本地特权升级，而无需额外的执行特权。  
  
谷歌透露了有关该零日漏洞的有限信息，仅表示有迹象表明该漏洞可能受到有限的针对性利用。然而，补丁的紧迫性凸显了威胁的严重性。除了修复此零日漏洞外，谷歌的 6 月安全更新还解决了 40 多个其他漏洞，包括多个严重的特权提升问题和影响各种 Pixel 组件的高严重性远程代码执行 (RCE) 漏洞。  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/google-patches-exploited-android-zero-day-on-pixel-devices/  
  
  
**2.Windows 错误报告服务权限提升漏洞(CVE-2024-26169)**  
  
  
6月 13 日，美国网络安全和基础设施安全局 (CISA) 将勒索软件攻击中滥用的高严重性 Windows 漏洞作为零日漏洞添加到其主动利用的安全漏洞目录中。此安全漏洞编号为 CVE-2024-26169，是由 Windows 错误报告服务中不当的权限管理漏洞引起的。成功利用此漏洞可让本地攻击者在无需用户交互的低复杂度攻击中获得系统权限。  
  
赛门铁克安全研究人员发现证据表明，Black Basta 勒索软件团伙（Cardinal 网络犯罪集团，也被追踪为 UNC4394 和 Storm-1811）的运营者很可能是利用该漏洞作为零日漏洞进行攻击的幕后黑手。他们发现，在这些攻击中部署的 CVE-2024-26169 漏洞利用工具的一个变体的编译时间戳为 2 月 27 日，而第二个样本的构建时间甚至更早，为 2023 年 12 月 18 日。  
  
虽然赛门铁克承认可执行文件中的时间戳可以被修改，因此无法确定是否存在零日漏洞，但攻击者伪造时间戳的动机似乎很小，因此这种情况不太可能发生。这表明，勒索软件组织在微软发布安全更新来修补本地特权提升漏洞之前的 14 到 85 天内就已存在漏洞。  
  
为了减轻 Black Basta 对此漏洞的利用，必须应用最新的 Windows 安全更新。  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/cisa-warns-of-windows-bug-exploited-in-ransomware-attacks/  
  
  
**3.****Progress Software Telerik Report Server 身份认证绕过漏洞(CVE-2024-4358)**  
  
  
6月 13 日，美国网络安全和基础设施安全局 (CISA) 在其已知利用漏洞 (KEV) 目录中添加Progress Software Telerik Report Server 身份认证绕过漏洞(CVE-2024-4358)，Progress Telerik Report Server 包含一个通过欺骗漏洞绕过授权，允许攻击者获得未经授权的访问。  
  
供应商建议，即使没有关于主动利用 CVE-2024-4358 的报告，系统管理员也应该检查其报告服务器的用户列表，查找在“{host}/Users/Index”中添加的任何他们不认识的新本地用户。  
  
由于全球有大量组织使用该供应商的产品，因此高级网络犯罪分子通常不会忽视 Progress Software 的严重缺陷。最具代表性的案例是2023 年 3 月，Clop 勒索软件团伙利用Progress MOVEit Transfer 平台的零日漏洞发动的一系列大规模数据盗窃攻击。那次数据盗窃活动最终成为历史上规模最大、影响最大的勒索行动之一，造成 2,770 多名受害者，间接影响近 9600 万人。  
  
受影响用户必须尽快更新，升级到版本 10.1.24.514 或更高版本，以解决漏洞。  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/exploit-for-critical-progress-telerik-auth-bypass-released-patch-now/  
  
  
**4.Arm Mali GPU 内核驱动程序释放后使用漏洞(CVE-2024-4610)**  
  
  
6 月 12 日，Arm 更新了一份安全公告，警告 Bifrost 和 Valhall GPU 内核驱动程序中存在一个与内存相关的漏洞，该漏洞正在被恶意利用。该安全问题被追踪为CVE-2024-4610，是一个释放后使用漏洞 (UAF)，影响从 r34p0 到 r40p0 的所有版本的 Bifrost 和 Valhall 驱动程序。当程序继续使用已释放的内存位置指针时，就会发生 UAF 缺陷。这些错误可能导致信息泄露和任意代码执行。  
  
Arm 解释说：“本地非特权用户可以进行不当的 GPU 内存处理操作来访问已释放的内存。”该公司还表示，“已经获悉该漏洞正在被利用。如果用户受到此问题的影响，建议他们进行升级。”  
  
该芯片制造商在 2022 年 11 月 24 日发布的 Bifrost 和 Valhall GPU 内核驱动程序 r41p0 版本中修复了此漏洞。目前，驱动程序的最新版本是 r49p0。  
  
由于 Android 供应链的复杂性，许多最终用户可能会在相当长的延迟后才能获得修补的驱动程序。一旦 Arm 发布安全更新，设备制造商就需要将其集成到固件中，而且在很多情况下，运营商也需要批准。根据手机型号，一些制造商可能会选择专注于较新的设备并停止对较旧设备的支持。  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/arm-warns-of-actively-exploited-flaw-in-mali-gpu-kernel-drivers/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.美国政府发布2023网络安全年报披露11起重大事件**  
  
  
6月12日The Register消息，美国白宫管理和预算办公室发布《联邦信息安全现代化法案（FISMA）2023财年报告》，对联邦机构2023财年基于FISMA报告的网络安全状况进行了概述和分析。报告显示，2023财年各联邦机构报告的网络安全事件数量高达32211起，同比增长9.9％，数量排名前三的事件类型分别是不当使用、钓鱼和恶意电子邮件、Web攻击。报告还披露了11起重大事件，涉及卫生与公共服务部、财政部、司法部等8个联邦机构，其中多起事件与MOVEit软件漏洞被利用相关。  
  
  
原文链接：  
  
https://www.theregister.com/2024/06/12/white_house_report  
  
  
**2.勒索攻击迫使越南国家邮政服务瘫痪超3天**  
  
  
6月11日The Record消息，负责越南当地邮政服务的国企越南邮政于6月4日遭到勒索软件攻击，邮政和快递服务受到影响。该公司当时报告称，旗下邮政金融、公共物流和货物分发等部分服务未受影响。越南邮政与政府机构和当地网络专家合作，以遏制事件，保护客户数据，并恢复其系统。在发现该事件后，越南邮政联系了国家安全机构，并断开了其IT系统以隔离漏洞。截至6月7日晚上10点，越南邮政服务于客户和运营管理活动的IT系统已恢复运行。越南邮政没有透露他们认为谁是幕后黑手，或者黑客是否索要赎金。  
  
  
原文链接：  
  
https://therecord.media/vietnam-claims-restore-services-cyberattack  
  
  
**3.云存储巨头Snowflake被黑，165家知名企业遭殃**  
  
  
6月11日Ars Technica消息，谷歌旗下威胁情报公司Mandiant发布报告称，云存储巨头Snowflake的大量客户实例遭黑客攻击，导致全球165家知名企业发生大规模数据泄露，而且发生数据泄露的Snowflake客户的数量还在不断增长。据悉，此次攻击事件已经波及了票务巨头Ticketmaster、桑坦德集团（Santander Group）、汽车零配件巨头Advance Auto Parts等一大批知名企业，数以亿计的个人受到影响。Mandiant报告显示，针对Snowflake客户的黑客攻击的“爆炸半径”还在不断扩大中，Mandiant正与Snowflake合作调查与其客户数据泄露有关的一系列漏洞。Mandiant表示，一群黑客利用信息窃取恶意软件获取的凭据，对未启用多因素认证（MFA）的Snowflake账户和未对不受信任位置访问设置限制的Snowflake客户实例实施大规模攻击。黑客使用的某些凭据已有数年历史。Snowflake发表声明称，正在“制定一项安全加固计划，要求客户实施多因素认证”。  
  
  
原文链接：  
  
https://arstechnica.com/information-technology/2024/06/hackers-steal-significant-volume-of-data-from-hundreds-of-snowflake-customers/  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.国家网信办等四部门公布《网络暴力信息治理规定》**  
  
  
6月14日，国家互联网信息办公室联合公安部、文化和旅游部、国家广播电视总局公布《网络暴力信息治理规定》，自2024年8月1日起施行。该文件共七章三十四条，包括总则、一般规定、预防预警、信息和账号处置、保护机制、监督管理和法律责任、附则。该文件要求，网络信息服务提供者应采用人工智能、大数据等技术手段和人工审核相结合的方式加强对网络暴力信息的识别监测，公众账号生产运营者应当建立健全发布推广、互动评论等全过程信息内容安全审核机制，发现账号跟帖评论等环节存在网络暴力信息的，应当及时采取举报、处置等措施。  
  
  
原文链接：  
  
https://www.cac.gov.cn/2024-06/14/c_1720043894161555.htm  
  
  
**2.《网络安全标准实践指南—敏感个人信息识别指南》公开征求意见**  
  
  
6月11日，全国网络安全标准化技术委员会秘书处组织编制了《网络安全标准实践指南——敏感个人信息识别指南（征求意见稿）》，现公开征求意见。该文件提出了敏感个人信息识别方法，给出了常见敏感个人信息的类别和示例，可用于指导各组织识别敏感个人信息范围，也可为敏感个人信息处理、出境和保护工作提供参考。  
  
  
原文链接：  
  
https://www.tc260.org.cn/upload/2024-06-11/1718109653748092450.pdf  
  
  
**往期精彩推荐**  
  
  
[【已复现】SolarWinds Serv-U 目录遍历漏洞(CVE-2024-28995)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501312&idx=1&sn=ed5fac2b7c395d524cdfc90d879c5f4c&chksm=fe79e298c90e6b8edd408b4dc9deb0d69379f73e68c58bbb2522ba7017851a6c1ba1ddef1503&token=1113944905&lang=zh_CN&scene=21#wechat_redirect)  
[微软6月补丁日多个产品安全漏洞风险通告：1个紧急漏洞、10个重要漏洞](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501287&idx=1&sn=022a78e23e4ee17c8d48c6f7be7511d6&chksm=fe79e17fc90e6869e4c92a585a1dbfbc44d9a2dcc53ef03d576ac6b49348f33efce88cb24552&token=1113944905&lang=zh_CN&scene=21#wechat_redirect)  
  
[【已发现在野攻击】PHP CGI Windows平台远程代码执行漏洞(CVE-2024-4577)安全风险通告第二次更新](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501282&idx=1&sn=04048b008f0579b2dc98f180b8b7c19d&chksm=fe79e17ac90e686c1c256c1ea400ec9f5ef0276f57b81f365fb2c2633bfc559eb725b37a02c6&token=1113944905&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  

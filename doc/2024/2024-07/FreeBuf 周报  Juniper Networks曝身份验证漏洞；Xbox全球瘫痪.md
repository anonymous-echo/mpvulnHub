#  FreeBuf 周报 | Juniper Networks曝身份验证漏洞；Xbox全球瘫痪   
疯狂冰淇淋  FreeBuf   2024-07-06 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、安全事件、一周好文和省心工具，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icUnIWPZfN03PI1T8OWQsScicxb0KWpKFRxWTG2wErx1UxRsQxs5ZFbB9nibSuTQI62QHZLBBH1Klrw/640?wx_fmt=png&from=appmsg "")  
  
  
**热点资讯**  
  
  
##   
### 1. 谷歌拟允许独立 Web应用访问敏感的USB设备  
  
WebUSB 是一种 JavaScript API，能够让网络应用程序访问计算机上的本地 USB 设备。作为 WebUSB 规范的一部分，某些接口，比如HID、大容量存储、智能卡、视频、音频/视频设备和无线控制器会受保护，不能通过网络应用程序访问，以防止恶意脚本访问潜在的敏感数据。  
  
### 2. 影响大量路由器，Juniper Networks曝最严重的「身份验证」漏洞  
  
该漏洞编号为CVE-2024-2973，攻击者可利用该漏洞完全控制设备。简单来说，JuniperSession Smart 路由器、Session Smart Conductor在运行冗余对等设备时，存在使用替代路径或通道绕过身份验证的漏洞，从而使得攻击者可以有效绕过身份验证，并对设备具有高控制度。  
  
### 3. OpenSSH漏洞预警：无需用户交互，可提权至 root  
  
成功利用该漏洞的攻击者可以以 root 身份进行未经身份验证的远程代码执行 (RCE)。在某些特定版本的 32 位操作系统上，攻击者最短需 6-8 小时即可获得最高权限的 root shell。而在 64 位机器上，目前没有在可接受时间内的利用方案，但未来的改进可能使其成为现实。  
  
### 4. 国际行动关闭了 593 台恶意 Cobalt Strike 服务器  
  
这项为期一周的行动于 2024 年 6 月 24 日开始，代号为「墨菲斯行动」，由英国国家犯罪局（NCA）牵头，由欧洲刑警组织协调。参与的机构包括联邦调查局、澳大利亚联邦警察和加拿大皇家骑警，针对 27 个国家和地区的 129 家互联网服务提供商的 690 个恶意 Cobalt Strike 软件实例。  
  
### 5. 100 亿条密码汇编集合 RockYou2024 泄露，酿成史上最大密码泄露事件  
  
RockYou2024密码汇编集合里包含世界各地个人使用的真实密码。研究人员认为，黑客将数量如此庞大的密码泄露出去，大大增加了凭证填充攻击的风险。  
  
  
**安全事件**  
  
  
##   
### 1. GitLab 曝一严重漏洞，威胁软件开发管道  
  
在 GitLab 中，管道可以自动完成构建、测试和部署代码的过程。从理论上讲，攻击者如果有能力以其他用户的身份运行管道，就可以访问他们的私有存储库，并操作、窃取或外泄其中包含的敏感代码和数据。  
  
### 2.Kimsuky 组织利用 TRANSLATEXT Chrome 扩展程序窃取敏感数据信息  
  
网络安全公司 CyberArmor 指出，该恶意程序后门似乎此前从未公开记录过，允许威胁攻击者执行基本侦察，并投放额外的有效载荷来接管或远程控制机器。目前，尚不清楚与新发现活动相关的初始访问的确切模式，但是，研究人员已经获悉该组织利用鱼叉式网络钓鱼和社交工程攻击来激活感染链。  
  
### 3. 澳大利亚男子炮制虚假航空公司WIFI骗取乘客账户凭证  
  
该男子42岁，通过便携式设备模仿航空公司及飞机上提供的官方WIFI名称建立虚假网络，当用户尝试连接时会被定向到虚假登录页面或强制门户网页，要求他们使用电子邮件地址、密码或其他凭证登录。  
  
### 4. Xbox 全球瘫痪，多个平台用户受影响  
  
这次中断影响了不同平台的用户，包括云游戏、Xbox One 游戏机、Windows 上的 Xbox、安卓设备、苹果设备和网络服务等。在第一批用户报告出现在网上几个小时之后，Xbox 团队承认了这一问题。  
  
### 5. 黑客滥用 API 端点验证了数百万个Authy MFA 电话号码  
  
Twilio 表示，有威胁分子使用了一个未经验证的 API 端点编译了电话号码列表。目前，Twilio 检测到由于使用了未经身份验证的端点，威胁行为者能够识别与 Authy 账户相关的数据，包括电话号码。Twilio 现已采取措施保护该端点的安全，不再允许未经身份验证的请求。  
  
  
**一周好文共读**  
  
  
##   
### 1. PowerShell 技术在网络安全测试中的应用  
  
在现代网络安全领域，渗透测试工具的选择和使用方式显得尤为关键。PowerShell，作为一种强大的自动化和配置管理工具，不仅仅是系统管理员的利器，同样也是渗透测试者的得力助手。本文将探讨如何利用 PowerShell 的高级功能，如动态函数定义、反射、文件系统监控以及并行处理，来增强渗透测试的效率和效果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibxXCMBvobgCKmWuAOBcoCWBMoHR3vibWPspfBxqq4Asf3Q3ZVcxg9q7Qh3qW3cuzw5sWFTCQx2Jqw/640?wx_fmt=png&from=appmsg "")  
  
### 2. 攻防演练中的IPv6（上）针对IPv6的扫描与攻击  
  
IPv6是（Internet Protocol version 6）是互联网协议的一种版本，用来为连接到互联网的设备来分配唯一的IP地址以便于标识。本身IPV6的设计是为了接替IPv4（Internet Protocol version 4），因为IPv4现在面临一个巨大的问题，那就是IPV4的地址空间不足。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibxXCMBvobgCKmWuAOBcoCWJplKbIQ9mVmhfrN3Wiamq1Aia676HUgCETCQP7CXs7GTDH5nicsO7l34w/640?wx_fmt=png&from=appmsg "")  
  
### 3. 深度好文 | 从零开始构建大模型安全测试基准  
  
通过自动发现LM有害的地方（「红队」）来补充手动测试并减少这种疏忽。为此，我们使用AI本身生成测试输入，并使用分类器检测测试输入上的有害行为。基于LM的红队使我们能够发现成千上万的多样化失败案例，而无需手工编写它们。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibxXCMBvobgCKmWuAOBcoCWwh6ydVPV9pz7D47bHaBICOXB7yKI8oTvsqgg5aHCcp1p8CKRHzDARQ/640?wx_fmt=png&from=appmsg "")  
  
  
**省心工具**  
  
  
##   
### 1. CrimsonEDR：一款恶意软件模式识别与EDR策略评估工具  
  
CrimsonEDR是一个功能强大的开源项目，该项目旨在帮助广大研究人员识别特定的恶意软件模式，以此来优化终端检测与响应（EDR）的策略方案。通过使用各种不同的检测方案，可以加深开发人员与研究人员加深对安全规避策略的理解。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39LcdUTibWwO2fKdibMKDKm2AiafBMEqkACxbftxib9XGGcHc0zniayF5Rm6JtYzATbPEiaGU7QDPBblyCQ/640?wx_fmt=png&from=appmsg "")  
  
### 2. APKDeepLens：一款针对Android应用程序的安全扫描工具  
  
APKDeepLens是一款针对Android应用程序的安全扫描工具，该工具基于Python开发，旨在扫描和识别Android应用程序（APK文件）中的安全漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39gF1icmjhPwHiactKvDYdZOlZHxRCVh7ibAxWMOwnOpbicO1ZsibLESBoPvlstw75FDDVhn1EyNjgfUYg/640?wx_fmt=jpeg&from=appmsg "")  
  
### 3. AttackGen：一款基于LLM的网络安全事件响应测试工具  
  
AttackGen是一款功能强大的网络安全事件响应测试工具，该工具利用了大语言模型和MITRE ATT&CK框架的强大功能，并且能够根据研究人员选择的威胁行为组织以及自己组织的详细信息生成定制化的事件响应场景。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38uOwkolTprFg5U4fmh6gSErgd5EkgGlOAh0tfoDoBVbuA0hrEQMCqSrrkkf57XeTUewmRbZiam68g/640?wx_fmt=png&from=appmsg "")  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494513&idx=1&sn=d121e4f2e20b5ccd61ecf0ad3d8c2106&chksm=ce1f11eef96898f81380d9a50b1420949d8ab4fb9df77944c1d0a9368a1aa2df63106b75b47b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493976&idx=1&sn=70a35df0a9bd52d9ac09818483ff8810&chksm=ce1f13c7f9689ad10260fd6af11bcf78034d697b75e295281d4d5ce4a941d42ec8a24b9fc044&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

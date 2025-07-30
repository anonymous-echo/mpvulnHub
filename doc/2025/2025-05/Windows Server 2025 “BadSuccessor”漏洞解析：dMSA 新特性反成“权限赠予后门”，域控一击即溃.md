#  Windows Server 2025 “BadSuccessor”漏洞解析：dMSA 新特性反成“权限赠予后门”，域控一击即溃   
原创 Hankzheng  技术修道场   2025-05-26 09:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wWBwsDOJT49Oa2SVTNsGcKVibk2RdrhqG1UibXclOJa77xIqzTV3Aciahtl6MibZzOiaLbWYDFspy9TQGsdjUYGhhXg/640?wx_fmt=png&from=appmsg "")  
  
大家好！安全攻防的战场上，意想不到的“友军火力”往往最为致命。Windows Server 2025 被寄予厚望用以加固防线的新特性——委派托管服务账户 (dMSA)，竟被曝出存在一个名为 **“BadSuccessor”**  
 的灾难级权限提升漏洞。据 Akamai 安全研究团队的最新披露，该漏洞允许攻击者在默认配置下，通过一系列“技术上简单”的操作，滥用 dMSA 的核心迁移与权限继承机制，从而仿冒 Active Directory (AD) 域内任意用户身份，包括至高无上的域管理员，最终实现对整个企业核心身份中枢的全面控制。  
## dMSA 的光环与阴影：为抗 Kerberoasting 而生，却意外“开门揖盗”  
  
理解**“BadSuccessor”**  
的凶险，需先回顾 dMSA (Delegated Managed Service Account) 的“初心”。在 Windows Server 2025 中隆重登场的 dMSA，其核心使命是作为传统服务账户的更安全替代品，旨在终结长期困扰 AD 环境的 **Kerberoasting 攻击**  
。Kerberoasting 攻击者能够请求服务账户的 Kerberos 服务票据 (TGS)，若账户密码薄弱，便可离线破解票据，窃取凭据，进而冒充服务。dMSA 通过引入新的、不依赖静态密码的身份验证和管理框架，力图根除这一顽疾。  
  
微软的设计蓝图是：当一个 dMSA 被配置为取代某个“遗留服务账户”时，该遗留账户基于密码的传统认证方式将被禁用。所有对该服务的认证请求，将由本地安全机构 (LSA) 接管，并使用 dMSA 的身份进行。此过程的核心在于，dMSA 将被设计为自动“继承”并被授予该遗留账户在 AD 中所拥有的全部访问权限、组成员身份及相关特权。  
## “BadSuccessor”漏洞原理：被操纵的 PAC 与 KDC 的“致命信任”  
  
**“BadSuccessor”**  
漏洞的症结，深植于 dMSA 进行 Kerberos 身份验证时，其**特权属性证书 (PAC)**  
 的构建与解析逻辑。PAC，作为 Kerberos 票据（如TGT、TGS）的“灵魂”，封装了用户的核心授权信息，包括用户的安全标识符 (SID) 及其所属的所有安全组的 SID。域内的密钥分发中心 (KDC) 在颁发服务票据时，正是依据 PAC 来裁定用户的访问权限。  
  
在正常的 dMSA 迁移场景下，当 KDC 为一个已正确配置“取代关系”的 dMSA 颁发票据时，其 PAC 中会包含：  
1. dMSA 账户自身的 SID。  
  
1. 被该 dMSA 合法取代的遗留账户的 SID。  
  
1. 至关重要的是，**该遗留账户所属的所有安全组的 SID（例如，如果遗留账户是域管理员组的成员，则 PAC 中会包含域管理员组的 SID）**  
。  
  
## 攻击链条深度剖析：四步窃取域控权限，技术实现“异常简单”  
  
攻击者巧妙地扭曲了这一权限继承机制，通过“模拟迁移”实现权限的非法僭越：  
1. **第一步：获取对任一 dMSA 对象的写权限**  
1. 攻击者首要目标是获得对至少一个 dMSA 对象属性的写入权限。这通常通过在某个组织单位 (OU) 上拥有 **CreateChild 权限**  
（允许创建新的计算机或用户对象，dMSA本质上是一种特殊计算机对象）来实现。拥有此权限后，攻击者便能在该 OU 下“名正言顺”地创建一个全新的 dMSA 对象，从而对其所有属性拥有生杀予夺之权。  
  
1. Akamai 的调查揭示了一个惊人事实：在高达91%的受检环境中，均发现非域管理员组的用户拥有此类看似普通、实则危险的权限。这往往是由于不当的 OU 权限委派策略或长期累积的配置漂移所致。  
  
1. **第二步：篡改 dMSA 关键属性，指定“高攀”目标**  
1. 攻击者将他们所控制的 dMSA 对象（姑且称之为 BadDMSA  
）的 msDS-SupersededAccount  
 属性（或功能等价的其他LDAP属性），恶意指向一个高权限目标用户，例如某个特定的域管理员账户 VictimDomainAdmin  
 的 SID 或其可分辨名称 (Distinguished Name)。  
  
1. **核心要点：此操作完全无需对 VictimDomainAdmin 账户本身拥有任何直接权限。**  
1. **第三步：以被篡改的 dMSA 身份请求 Kerberos 票据**  
1. 攻击者使用 BadDMSA  
 的身份（该身份本身可能毫无特权），向 KDC 请求访问任意服务的服务票据 (TGS)。  
  
1. **第四步：KDC “盲目信任”并授予“不义之财”——包含目标权限的 PAC**  
1. KDC 在处理来自 BadDMSA  
 的票据请求时，会检查其 msDS-SupersededAccount  
 属性。当 KDC 发现该属性指向 VictimDomainAdmin  
 时，它会“天真地”假定这是一次合法的、经过授权的账户迁移行为。  
  
1. 因此，在为 BadDMSA  
 生成新的 TGT 或 TGS 时，KDC 会在其 PAC 中慷慨地包含 BadDMSA  
 的 SID，**并且，如同对待合法继承者一般，将 VictimDomainAdmin 的 SID 及其所属所有特权组（如 Domain Admins 组）的 SID 一并置入！**  
  
1. 攻击者至此功成。他们手中的 Kerberos 票据，虽然名义上属于低权限的 BadDMSA  
，但其 PAC 中却“注入”了 VictimDomainAdmin  
 的全部“灵魂”——包括域管理员级别的特权。凭借此“超级票据”，攻击者便能以 VictimDomainAdmin  
 的身份在域内为所欲为。  
  
Akamai 指出，此攻击的实现“异常简单”(trivial to implement)，可能仅需标准的 AD 管理命令行工具（如 PowerShell 的 Set-ADObject  
）配合常见的 Kerberos 票据操作工具（如 Rubeus、Kekeo 等的某些功能模块）即可完成。其最终效果，足以媲美臭名昭著的 **DCSync 攻击**  
。DCSync 攻击允许攻击者模拟域控制器行为，向其他DC发起目录复制请求，从而非法获取域内所有账户（包括 KRBTGT 这种“万能钥匙”账户）的密码哈希数据，进而能够伪造可长期使用的“黄金票据”(Golden Tickets)，实现对整个AD域的绝对、持久化控制。  
## 微软官方立场 vs Akamai 严正警示：风险评级的博弈  
  
微软在2025年4月1日接到 Akamai 的漏洞报告后，将此问题初步定性为“中等”严重性。其主要依据是，漏洞的成功利用要求攻击者必须预先具备对 dMSA 对象属性的写入权限，这在微软看来属于一种“已有初始访问权限后的本地权限提升”(EoP)。然而，Akamai 的研究数据（91%环境存在易被获取的前置权限）及攻击手法的简易性，均强烈暗示该漏洞的实际利用门槛远低于“中等”评级所传递的乐观情绪。目前，微软官方确认正在为**“BadSuccessor”**  
开发修复补丁。  
## 补丁发布前的紧急自救：亡羊补牢，刻不容缓  
  
鉴于官方补丁尚在途中，且漏洞利用条件在真实环境中普遍存在，企业组织必须立即行动，刻不容缓：  
1. **严控 dMSA 创建权限，斩断源头**  
对 AD 林中所有OU进行彻底审查，识别哪些用户、组或计算机主体被授予了创建 dMSA 对象（LDAP类名为 msDS-DelegatedManagedServiceAccount  
）的权限。特别关注OU级别委派的 CreateChild - All validated writes  
 权限，以及针对特定对象类型的 Create msDS-DelegatedManagedServiceAccount objects  
 权限。坚决移除一切非绝对业务必要（且经过严格审批）的此类授权。  
  
1. **强化现有 dMSA 对象安全，严防属性篡改**  
对于环境中已存在的（合法的）dMSA 对象，必须严格控制其 msDS-SupersededAccount  
 及其他关键属性的写入权限。确保只有极少数、经过严格授权的管理员才能修改这些敏感配置。  
  
1. **利用 Akamai 检测脚本，主动排查隐患**  
Akamai 发布了一款 PowerShell 脚本，可协助管理员快速枚举出环境中所有非默认的、被授予了创建 dMSA 权限的主体及其所作用的 OU 范围。获取此列表后，安全团队应：  
  
1. **逐项核实授权的合法性与必要性**  
判断该主体是否确实因不可替代的业务需求，而必须在此特定 OU 内创建 dMSA。  
  
1. **遵循最小权限原则，果断回收多余授权**  
对于任何非必要或权限过宽的授权，立即予以撤销或收紧至最小范围。优先处理那些包含管理员账户、关键业务服务账户或现有重要 dMSA 对象的 OU。  
  
1. **增强对 dMSA 对象创建及关键属性变更的监控与告警**  
部署针对性的审计策略，对 msDS-DelegatedManagedServiceAccount  
 对象的创建事件以及 msDS-SupersededAccount  
 等属性的修改操作，建立实时监控和异常告警机制。  
  
## 警惕“安全特性”的双刃剑效应，AD 防御永无终点  
  
Windows Server 2025 的 dMSA 本是一片好心，旨在通过技术革新提升 AD 的整体安全水位。然而，**“BadSuccessor”**  
漏洞的横空出世，如同一盆冷水，再次无情地揭示了任何新技术、新特性在复杂系统中所固有的“双刃剑”效应。在 Active Directory 这个庞大而精密的身份管理体系中，权限的委派与继承、对象的属性与访问控制，每一个环节的微小疏忽都可能被攻击者放大为颠覆性的安全灾难。面对层出不穷、手法日益精进的高级威胁，企业唯有将持续的安全审计、严格的权限管控、实时的威胁检测以及快速的应急响应能力，内化为日常安全运营的肌肉记忆，方能在这场永无终点的攻防对抗中，守住数字身份的最后一道防线。  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzNDU5NTI4OQ==&mid=2247489437&idx=1&sn=1e4298f03de6ef16d2e8a61fd667f0ef

#  网络安全周刊#7: Fortinet FortiWeb 严重SQL注入漏洞剖析  
原创 知机安全  知机安全   2025-07-14 01:00  
  
1. 本周安全焦点  
  
软件供应链安全警钟再次被敲响，攻击者将目光精准地投向了开发者生态。从Laravel框架因APP_KEY泄露导致的大规模远程代码执行风险，到Ethcode VS Code扩展被恶意pull request注入后门，再到合法红队工具Shellter遭破解并被用于分发恶意软件，一系列事件揭示了攻击者正通过污染开发工具、框架和代码库来构建高效的攻击链。  
## 2. 重要资讯  
### 2.1. 数据泄露与攻击事件  
1. **数百个Laravel应用面临RCE风险：**  
因应用程序密钥（APP_KEY）被泄露至GitHub等公共平台，超过600个Laravel应用程序面临远程代码执行（RCE）的严重风险。攻击者可利用泄露的密钥和反序列化漏洞（如   
CVE-2018-15133  
）在服务器上执行任意代码。  
  
1. **英国多家大型零售商遭网络攻击：**  
据报道，Marks & Spencer和Co-op等英国主要零售商遭到网络攻击，据信与名为Scattered Spider的高度组织化网络犯罪团伙有关。该团伙以其复杂的社会工程学策略（如SIM卡交换和冒充IT服务台）来绕过MFA并部署勒索软件。  
  
1. **虚假初创公司通过社交媒体诱骗加密货币用户安装恶意软件：**  
一个持续进行的社会工程活动正在利用伪装成AI、游戏和Web3初创公司的虚假身份，在Telegram和Discord等平台上接近目标。攻击者以软件测试为诱饵，诱导受害者下载恶意软件，从而窃取其Windows和macOS系统上的数字资产。  
  
### 2.2. 漏洞预警与分析  
1. **GPUHammer：新型RowHammer攻击可致NVIDIA GPU上的AI模型失效：**  
研究人员发现一种名为GPUHammer的新型RowHammer攻击变体，能够绕过TRR等缓解措施，在NVIDIA GPU（如A6000）上引发位翻转。该攻击可严重破坏AI模型的完整性，甚至将模型的准确率从80%降至不足1%。NVIDIA建议用户启用系统级ECC作为防御。  
  
1. **微软7月补丁星期二修复130个漏洞，含“蠕虫级”RCE漏洞：**  
微软发布了7月份的安全更新，修复了130个漏洞，其中10个为“严重”级别。最引人注目的是SPNEGO扩展协商中的一个严重RCE漏洞（  
CVE-2025-47981  
，CVSS评分9.8），该漏洞无需身份验证即可远程利用，存在“蠕虫化”传播的潜力。此外，更新还修复了一个已公开披露的SQL Server信息泄露漏洞（  
CVE-2025-49719  
）。  
  
1. **Citrix NetScaler关键漏洞（Citrix Bleed 2）遭在野利用：**  
美国CISA已将Citrix NetScaler ADC和Gateway中的一个关键身份验证绕过漏洞（  
CVE-2025-5777  
，CVSS评分9.3）添加到其KEV（已知被利用漏洞）目录中。该漏洞被称为“Citrix Bleed 2”，攻击者可利用它读取设备内存，窃取会话令牌等敏感信息。  
  
1. **Fortinet修复FortiWeb中的严重SQL注入漏洞：**  
Fortinet发布了针对其FortiWeb Web应用防火墙中一个严重SQL注入漏洞（  
CVE-2025-25257  
，CVSS评分9.6）的补丁。未经身份验证的攻击者可通过构造恶意的HTTP(S)请求，执行未授权的SQL命令，可能导致远程代码执行。  
  
1. **Wing FTP Server严重漏洞（CVE-2025-47812）遭在野利用：**  
Wing FTP Server中一个CVSS评分为10.0的严重漏洞正在被积极利用。该漏洞源于服务器Web界面在处理空字节（'\0'）时的缺陷，允许攻击者（甚至匿名账户）注入任意Lua代码，从而以root或SYSTEM权限执行系统命令。  
  
1. **PerfektBlue漏洞使数百万车辆面临蓝牙攻击风险：**  
研究人员在OpenSynergy的BlueSDK蓝牙协议栈中发现四个被称为“PerfektBlue”的漏洞（包括   
CVE-2024-45434  
）。攻击者可在蓝牙范围内利用这些漏洞链，对大众、斯柯达、梅赛德斯-奔驰等多个汽车品牌的车载信息娱乐（IVI）系统实现远程代码执行。  
  
1. **其他值得关注的漏洞：**  
1. **AMD Transient Scheduler Attacks (TSA):** 一类影响多种AMD CPU的新型推测执行侧信道漏洞，可能导致信息泄露（  
CVE-2024-36350  
,   
CVE-2024-36357  
 等）。  
  
1. **ServiceNow平台数据推断漏洞:**   
CVE-2025-3648  
，在特定ACL配置下，用户可通过范围查询推断出无权访问的数据。  
  
1. **mcp-remote RCE漏洞:**   
CVE-2025-6514  
，一个影响用于AI模型集成的开源工具的严重RCE漏洞，影响超过43万次下载。  
  
1. **Citrix NetScaler ADC/Gateway漏洞:**   
CVE-2025-6543  
，与Citrix Bleed 2一同被CISA加入KEV目录，已遭在野利用。  
  
1. **Ethcode VS Code扩展供应链攻击:** 恶意pull request导致流行的以太坊开发扩展被注入后门。  
  
1. **老漏洞新利用:** CISA将多个旧漏洞（如   
CVE-2014-3931  
,   
CVE-2016-10033  
,   
CVE-2019-5418  
,   
CVE-2019-9621  
）加入KEV目录，表明其仍在被积极利用。  
  
### 2.3. 恶意软件与威胁情报  
1. **Anatsa安卓银行木马通过Google Play感染9万用户：**  
Anatsa银行木马伪装成一款名为“PDF Update”的文档查看器应用，在Google Play商店上架。该应用在获得大量下载后通过更新植入恶意代码，针对北美地区的银行用户进行覆盖攻击和按键记录，以窃取凭证并实施设备接管欺诈。  
  
1. **DoNot APT组织使用LoptikMod恶意软件攻击欧洲外交部：**  
与印度有关的APT组织DoNot Team被发现针对一个欧洲外交事务部发起攻击。攻击者通过钓鱼邮件分发LoptikMod恶意软件，该软件能够对受感染主机进行持久监控、数据窃取和长期访问。  
  
1. **泄露的Shellter工具被用于传播Lumma Stealer等恶意软件：**  
一个商业红队规避框架Shellter的许可证被泄露后，被网络犯罪分子滥用。攻击者利用该工具打包Lumma Stealer、Rhadamanthys Stealer和SectopRAT等信息窃取器，以绕过杀毒软件和EDR的检测。  
  
1. **RondoDox僵尸网络利用DVR和路由器漏洞发起DDoS攻击：**  
一个新的僵尸网络RondoDox正在利用TBK DVR中的   
CVE-2024-3721  
 和四信路由器中的   
CVE-2024-12856  
 等漏洞进行传播。该僵尸网络能够模仿游戏平台或VPN流量以逃避检测，并对目标发起DDoS攻击。  
  
1. **macOS恶意软件ZuRu伪装成Termius应用进行分发：**  
研究人员发现macOS恶意软件ZuRu的新变种，其通过伪装成合法的SSH客户端Termius进行传播。该恶意软件利用修改版的开源后渗透工具Khepri，对受感染的macOS系统实现远程控制。  
  
1. **SEO投毒活动利用虚假AI工具传播恶意软件：**  
攻击者利用SEO投毒技术，在用户搜索PuTTY、WinSCP等IT工具或AI相关关键词时，将流量导向恶意网站。这些网站分发木马化软件，最终植入Oyster、Vidar、Lumma等恶意软件加载器和信息窃取器。  
  
### 2.4. 网络犯罪与执法行动  
1. **四名Scattered Spider团伙成员在英国被捕：**  
英国国家犯罪局（NCA）逮捕了四名与网络犯罪组织Scattered Spider有关的嫌疑人。该团伙被认为对Marks & Spencer、Co-op和Harrods等大型零售商发动了网络攻击，涉嫌计算机滥用、勒索和洗钱等罪行。  
  
1. **美国制裁一名与Andariel黑客组织有关的朝鲜人员：**  
美国财政部对朝鲜黑客组织Andariel的一名成员Song Kum Hyok实施制裁。他被指控参与了朝鲜的IT工作者欺诈计划，利用伪造身份和雇佣的外国IT人员在美国公司寻求远程工作，为该政权创造非法收入。  
  
1. **Pay2Key勒索软件即服务死灰复燃：**  
与伊朗有关的勒索软件即服务（RaaS）平台Pay2Key在沉寂后再次活跃。该组织现以Pay2Key.I2P的名义运作，将其基础设施托管在I2P网络上，并为攻击美国和以色列等目标的附属机构提供高达80%的利润分成。  
  
## 3. 技术剖析  
### 1. Fortinet FortiWeb 严重SQL注入漏洞（CVE-2025-25257）剖析  
  
本周披露的FortiWeb漏洞是一个未经身份验证的SQL注入，可导致远程代码执行。其根本原因在于Fabric Connector组件中的一个函数未能正确处理用户输入。  
  
**攻击流程：**  
1. **漏洞根源:**  
1. 漏洞存在于名为 `get_fabric_user_by_token` 的函数中，该函数被用于处理与其他Fortinet产品的连接。  
  
1. 此函数会从三个不同的API端点（如 `/api/fabric/device/status`）被调用。  
  
1. **注入点:**  
1. 攻击者可以通过在HTTP请求的 `Authorization` 头中构造一个恶意的 `Bearer` 令牌来利用此漏洞。  
  
1. 令牌中的恶意输入被直接传递给一个SQL数据库查询，而没有进行充分的净化或参数化处理。  
  
1. **代码执行:**  
1. 通过注入恶意的SQL语句，攻击者可以执行任意数据库命令。  
  
1. **权限提升与文件写入:**  
1. 由于数据库查询是以“mysql”用户身份运行的，攻击者可以进一步利用此权限。  
  
1. 通过嵌入 `SELECT ... INTO OUTFILE` 语句，攻击者可以将命令执行的结果写入底层操作系统的任意文件中，从而实现从SQL注入到远程代码执行的升级。  
  
**修复方式：**  
  
Fortinet在新版本中用预处理语句（Prepared Statements）替换了原先的格式化字符串查询，这是一种标准的、有效的防止SQL注入攻击的方法。  
### 2. Citrix Bleed 2（CVE-2025-5777）内存泄露漏洞原理  
  
被称为“Citrix Bleed 2”的漏洞允许未经身份验证的攻击者远程读取NetScaler设备内存中的敏感数据，如会话令牌。  
  
**漏洞原理：**  
1. **触发点:**  
1. 漏洞可通过向特定端点（如 `/p/u/doAuthentication.do`）发送一个特制的HTTP登录请求来触发。  
  
1. **核心缺陷:**  
1. 漏洞源于C语言函数 `snprintf` 的不当使用，特别是在处理 `%.*s` 格式化字符串时。  
  
1. 此格式化字符串意为“打印最多N个字符，或在遇到第一个空字节（\0）时停止”。  
  
1. **内存泄露过程:**  
1. 当攻击者发送的请求中，`login=` 参数没有等号或值时，`snprintf` 函数在处理响应时会读取栈上未初始化的内存。  
  
1. 由于缺少正确的终止符，该函数会继续读取并返回一小段（约127字节）内存数据，直到在内存中遇到一个空字节为止。  
  
1. 攻击者可以重复发送此类请求，每次都能“榨取”出一段新的内存数据，就像“流血”（Bleeding）一样，直到获取到有价值的信息，如有效的会话令牌。  
  
**攻击影响：**  
  
一旦窃取到有效的会话令牌，攻击者便可劫持用户会话，绕过认证访问内部应用和网络，对企业构成严重威胁。  
## 4. 工具与资源  
1. **ysoserial.net:**  
 一款开源的.NET反序列化载荷生成器。Gold Melody等初始访问代理利用其ViewState插件来构建攻击载荷，利用泄露的ASP.NET machine key进行攻击。 https://github.com/pwntester/ysoserial.net  
  
1. **Khepri:**  
 一款开源的macOS后渗透利用工具包。ZuRu恶意软件的变种利用修改版的Khepri来远程控制受感染的Mac主机。 https://github.com/geemion/Khepri  
  
1. **Shellter:**  
 一款商业化的红队工具，用于帮助载荷绕过AV/EDR检测。近期其泄露版本被网络犯罪分子广泛用于打包和分发信息窃取恶意软件。 https://www.shellterproject.com/  
  
1. **phpggc:**  
 一款强大的PHP反序列化载荷生成工具。在涉及PHP应用（如部分Laravel配置）的漏洞利用中，该工具可用于生成能触发RCE的小工具链（gadget chains）。 https://github.com/ambionics/phpggc  
  
## 5. 言论  
1. “启用纠错码（ECC）可以降低这种风险，但在A6000 GPU上，ECC可能会给机器学习推理工作负载带来高达10%的性能下降，并减少6.25%的内存容量。”  
—— Chris Lin, Joyce Qu, and Gururaj Saileshwar (关于GPUHammer的影响)  
  
1. “开发者绝不应只是从仓库中删除暴露的APP_KEY而不进行轮换。正确的响应包括：立即轮换受损的APP_KEY，用新密钥更新所有生产系统，并实施持续的密钥监控以防止未来暴露。”  
—— GitGuardian (关于Laravel密钥泄露)  
  
1. “尽管勒索软件是一个持续存在的威胁，但Scattered Spider代表了一个持续且有能力的对手，即使是针对拥有成熟安全计划的组织，其行动在历史上也是有效的。”  
—— Grayson North, GuidePoint Security (关于Scattered Spider黑客团伙)  
  
1. “RondoDox是一种复杂且新兴的恶意软件威胁，它采用先进的规避技术，包括反分析措施、XOR编码的配置数据、定制库和强大的持久性机制。”  
—— Vincent Li, Fortinet FortiGuard Labs (关于RondoDox僵尸网络)  
  

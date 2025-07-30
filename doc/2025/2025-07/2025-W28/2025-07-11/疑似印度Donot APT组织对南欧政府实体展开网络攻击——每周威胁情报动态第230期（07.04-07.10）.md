> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MTE4ODY3Nw==&mid=2247492687&idx=1&sn=7b17f600ecd1563da70724957ca72a67

#  疑似印度Donot APT组织对南欧政府实体展开网络攻击——每周威胁情报动态第230期（07.04-07.10）  
原创 BaizeSec  白泽安全实验室   2025-07-11 01:01  
  
APT攻击  
- 疑似印度  
Do  
n  
ot  
   
APT组织对南欧政府实体  
展开  
网络攻击  
  
- 俄罗斯黑客组织  
Blind Eagle利用  
运营商  
Proton66针对拉美金融机构发动大规模网络攻击  
  
攻击活动  
- 黑客利用  
WordPress与ClickFix技术传播NetSupport RAT恶意软件  
  
数据泄露  
- 美国税务咨询公司  
Rockerbox  
   
286GB敏感信息数据泄露  
  
恶意软件  
- 新型跨平台木马  
SparkKitty  
针对  
东南亚及中国地区  
用户展开攻击  
  
勒索软件  
- 新兴  
BERT勒索软件  
组织针对亚洲和欧洲展开  
攻击  
活动  
  
  
  
APT攻击  
  
疑似印度Donot APT组织对南欧政府实体展开网络攻击  
  
近期，网络安全机构  
Trellix发布深度分析报告，披露疑似印度背景的  
Donot APT组织（别名“肚脑虫”、  
APT-C-35等）针对南欧多国政府机构发动了一场精心策划的网络攻击。该组织作为自2016年起便在网络空间中频繁活跃，长期聚焦亚洲地缘政治利益，将政府实体、外交部、国防组织及非政府组织作为主要攻击目标，尤其在亚洲和欧洲地区活动频繁。其核心动机为网络间谍窃密活动，攻击者通过持续监视、数据窃取和长期控制目标系统来获取敏感信息。此次攻击活动以高度隐蔽的钓鱼诱饵为起点，通过多阶段、模块化的技术手段实现系统渗透与数据窃取，最终在目标网络中建立持久化后门，其技术复杂性与战术针对性都引发行业的高度关注。  
  
此次攻击活动中，攻击始于一封看似普通的电子邮件。攻击者伪装成欧洲国防官员，以“访问孟加拉国”为诱饵，向目标发送包含恶意谷歌云端硬盘链接的钓鱼邮件，邮件源自Gmail邮箱（int.dte.afd.1@gmail[.]com），主题围绕外交活动展开，极具迷惑性。受害者点击邮件中的谷歌云端硬盘链接（drive[.]usercontent[.]google[.]com/download?id=1t-fBZBgVtW_S81qYGn9loubWZwIXjI_T）后，会下载名为SyClrLtr.rar的恶意压缩包，解压后运行其中的notflog.exe——该文件伪装成PDF文档，带有“侠盗猎车手IV”的元数据信息，且由“Ebo Sky Tech Inc.”进行数字签名，进一步降低了目标的警惕性。  
  
攻击过程呈现出精密的多阶段入侵链条。notflog.exe运行后，会在%TEMP%目录部署批处理文件djkggosj.bat，随后通过该批处理文件创建名为“PerformTaskMaintain”的计划任务，每10分钟运行一次，以此实现持久化控制。接着，恶意软件与C2服务器（Totalservices[.]info，对应IP地址64.52.80[.]252）建立通信，开始收集受害者系统信息，包括CPU型号、操作系统名称和版本、用户名、主机名等，这些信息经AES加密和Base64编码后，通过HTTPS POST请求发送至C2服务器完成数据窃取。此外，攻击还会下载后续payload“socker.dll”至“% LocalAppdata%\moshtmlclip\”目录，并通过另一个批处理文件sfs.bat创建名为“MicorsoftVelocity”的计划任务，确保该payload持续执行，形成完整的攻击闭环。  
  
此次攻击活动中，攻击者在伪装与社会工程学利用上，不仅让邮件模仿官方通信、提及真实外交情境。还让恶意文件借用知名游戏程序身份、依托谷歌云端硬盘等可信平台传播，大幅提升了诱骗成功率。代码混淆技术方面，恶意软件中存在二进制编码字符串，解码为ASCII字符后才会显露计划任务名称、C2服务器域名等真实功能；仅对二进制文件的特定关键部分进行压缩或加密（选择性混淆），而非整个文件；同时减少导入表中的API数量，在运行时通过LoadLibrary和  
GetProcAddress动态加载所需API，这些都增加了静态分析的难度。反分析与反虚拟机技术的应用也十分突出，通过创建名为“08808”的互斥体确保单一实例运行，使用“IN”汇编指令检测虚拟环境以躲避沙箱分析。而多阶段攻击链的设计，从钓鱼邮件到数据窃取涉及多个阶段和多种恶意组件的协同，再加上通过多个计划任务实现的持久化机制，以及HTTPS加密通信和数据加密传输的保护，使得整个攻击体系更为稳固，难以被一次性彻底清除。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NpPydsaAMIMS9WfQuYsvCVeEKziajec2p4Im6ZD0hiaCpPqXVLCjcbqOc8Ldht04BE8XkbcDkFIIanodGiaHNhRNw/640?wx_fmt=png&from=appmsg "")  
  
图   
1   
Donot APT组织攻击流程示意图  
  
参考链接：  
  
https://www.trellix.com/blogs/research/from-click-to-compromise-unveiling-the-sophisticated-attack-of-donot-apt-group-on-southern-european-government-entities/  
  
  
  
俄罗斯黑客组织Blind Eagle利用运营商Proton66针对拉美金融机构发动大规模网络攻击  
  
近日，网络安全研究人员发现俄罗斯黑客组织  
Blind Eagle（又称APT-C-36）与俄罗斯防弹（  
bulletproof hosting）托管服务提供商  
Proton66之间存在高度关联。该组织长期活跃于拉丁美洲地区，尤其针对哥伦比亚的金融机构，持续发动网络攻击，严重威胁当地金融安全。根据研究人员的追踪分析，  
Blind Eagle组织自2024年以来，利用Proton66提供的网络基础设施，构建了一个高度活跃且相互关联的恶意网络集群。攻击者通过注册大量遵循特定命名规则的域名，并将其解析至Proton66所属的网络地址段，搭建起用于托管恶意内容的攻击平台。这些域名通常使用免费的动态DNS服务，并频繁复用SSL证书，虽然技术手段并不复杂，但却能有效支撑其攻击行动。  
  
该组织的攻击活动有着明确的流程与技术特点。其基础设施以多个相互关联的域名和  
IP地址群为支撑，专门利用Visual Basic Script（VBS）文件作为初始攻击向量，且高度依赖免费动态DNS（DDNS）服务，部署现成的远程访问木马（RAT）作为第二阶段恶意软件。在具体攻击过程中，相关域名被用于托管各类恶意内容，其中钓鱼页面精准模仿Bancolombia、BBVA、Banco Caja Social、Davivienda等哥伦比亚知名金融机构的登录门户，通过复制合法页面的HTML、CSS及图像文件，诱导用户输入敏感信息以窃取凭证。同时，这些基础设施还托管着作为第一阶段恶意软件部署工具的VBS脚本，部分VBS代码与“Crypters and Tools”订阅服务关联的Vbs-Crypter生成样本存在重叠，该服务能对VBS payload进行混淆和打包，规避静态检测。  
  
VBS脚本的运行机制呈现出清晰的攻击逻辑：首先会检查自身是否具备管理员权限，若权限不足，则通过Windows脚本方法重新以elevated权限执行，成功后为C:\驱动器在Defender中添加排除项以逃避检测；部分脚本还会删除与COM/ActiveX类、CLSID及WOW6432Node路径相关的Windows注册表项进行清理。多数VBS脚本作为第一阶段加载器，在清理掉6000至20000行注释后，会先创建计划任务，如“schtasks/create/tn coJb /tr "% TEMP%\GLPd.vbs" /sc  
   
minute /mo 1”，接着解码Base64字符串并通过PowerShell执行，随后从paste.ee、  
textbin.net、  
store3.gofile.io等平台或直接通过IPv4地址下载下一阶段payload。下一阶段payload通常是带有MZ头的文件，被重命名为如dll02.txt的DLL文件，用于加载最终从其他URL下载的payload，该文件经Base64解码后仍是MZ文件，最终部署Remcos或AsyncRAT等远程访问木马，建立命令与控制（C2）连接。  
  
值得注意的是，尽管攻击目标具有高价值属性，但攻击者在基础设施隐藏方面投入极少。大量开放目录被发现，其中不仅存在重复的恶意文件，甚至包含完整的仿冒哥伦比亚银行的钓鱼页面及第一阶段恶意软件。其基础设施的各个组件，包括恶意软件托管服务器、  
C2面板和钓鱼相关文件，在域名命名模式、SSL证书重用及共享工件上保持一致，缺乏基本的分割与隐蔽措施，许多组件可通过开放目录公开访问，这体现出威胁者更注重快速部署和可访问性，而非隐身或长期可持续性。此次持续的攻击活动表明，即便威胁基础设施并非高度复杂，结合针对特定区域目标的钓鱼诱饵，仍能实现成功入侵。目前，虽然哥伦比亚金融机构是主要攻击焦点，但整体趋势显示其正逐步具备在整个拉丁美洲地区扩大攻击范围的能力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NpPydsaAMIMS9WfQuYsvCVeEKziajec2pzf6RF3K9CKJ776NLzMsiaQBxSkyyMzWgQIA0GliaBFI1dWLjaYD0ptiag/640?wx_fmt=png&from=appmsg "")  
  
图   
2 DuckDNS.org具有类似命名模式的域注册  
  
参考链接：  
  
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tracing-blind-eagle-to-proton66/  
  
  
攻击活动  
  
黑客利用WordPress与ClickFix技术传播NetSupport RAT恶意软件  
  
近期，网络安全厂商Cybereason发现一起利用WordPress网站传播NetSupport远程访问木马（RAT）的网络攻击事件。攻击者通过通过搭建恶意WordPress网站，分发经过篡改的合法远程访问工具NetSupport Manager的恶意版本，即NetSupport RAT（远程访问木马）。这一攻击活动借助复杂的技术链，从诱导用户访问恶意网站到最终实现对受害设备的远程控制，对个人及企业网络安全构成严重威胁。  
  
攻击者通过精心设计的钓鱼邮件、  
PDF 附件及gaming网站等渠道，将用户引导至恶意网站。一旦用户访问此类网站，隐藏在页面中的恶意脚本便会启动攻击流程：首先，恶意JavaScript（j.js）通过iframe注入技术嵌入被篡改网站的元描述或“首页”链接中，当用户加载页面或点击看似正常的链接时，脚本会自动执行，判断用户设备是否为Windows系统、记录访问时间，并生成iframe加载另一恶意PHP文件（index.php）。为避免重复攻击暴露行踪，脚本还会通过浏览器本地存储的“lastvisit”数据项追踪用户访问记录，仅对首次访问者触发后续攻击。  
  
随后，  
index.php会动态生成脚本文件，加载名为  
select.js的文件，该文件通过DOM操纵技术彻底改写网页外观，植入一个伪装成“人机验证”的虚假CAPTCHA页面。页面会引导用户按下“Win+R”打开运行窗口，再通过“Ctrl+V”粘贴并执行一段恶意命令——而这段命令实则是通过浏览器剪贴板API预先复制的，其作用是调用curl.exe从指定恶意域名下载批处理文件（如jfgf.bat）到用户设备的公共目录。批处理文件运行后，会进一步利用PowerShell下载并解压包含NetSupport客户端组件的ZIP压缩包，其中不仅有核心程序client32.exe，还有配置文件client32.ini、远程命令提示符工具remcmdstub.exe等关键组件，并通过修改Windows注册表的“Run”项实现持久化驻留，确保受害设备重启后仍能被攻击者控制。  
  
此次攻击所利用的  
NetSupport Manager本是一款用于远程系统管理的合法工具，但其强大的功能（如文件传输、远程命令执行、实时监控等）被恶意滥用后，成为攻击者窃取数据、部署更多恶意软件的利器。根据配置文件  
client32.ini中的设置，恶意客户端会连接至位于摩尔多瓦MivoCloud SRL数据中心的控制服务器（IP段94.158.245.0/24），这些服务器暴露了RDP（3389端口）和HTTPS（443端口），为攻击者远程操控受害设备提供了通道。在入侵后的数小时内，攻击者便会通过NetSupport的远程命令提示符执行侦察操作，例如查询域内计算机账户，为进一步扩大攻击范围做准备。  
  
从技术特点来看，此次攻击展现了高度的隐蔽性与欺骗性：通过合法网站伪装降低用户警惕，利用  
DOM操纵和剪贴板劫持绕过常规安全检测，借助合法工具的恶意滥用规避防御机制，且整个攻击链环环相扣，从初始访问到持久化控制仅需用户完成几个简单操作，极易得手。  
  
参考链接：  
  
https://www.cybereason.com/blog/net-support-rat-wordpress-clickfix  
  
  
数据泄露  
  
美国税务咨询公司Rockerbox 286GB敏感信息数据泄露  
  
近日，美国得克萨斯州一家知名税务信用咨询公司  
Rockerbox遭遇严重数据泄露事件，大量敏感客户信息暴露于公众视野之下。据网络安全研究人员披露，此次数据泄露源于一个未设置密码保护的数据库，该数据库被意外暴露于互联网，导致数以万计的个人信息面临暴露风险。  
  
Rockerbox是一家专注于税务抵免咨询的企业，主要为美国各地企业提供雇主相关税务激励的识别与管理服务，业务涵盖工作机会税收抵免（WOTC）、员工保留税收抵免（ERTC）、研发抵免及empowerment区域抵免等项目。服务对象涵盖餐饮、酒店、医疗、制造、食品加工及技术行业等多个领域。  
  
根据  
Fowler的报告，此次暴露的数据库涉及245,949条记录，数据总量高达  
286.9GB，内容包含大量个人身份信息（PII），诸如姓名、出生日期、社会安全号码（SSN）、 家庭地址等，这些信息可直接或间接识别个人身份，而SSN作为美国用于追踪收入及各类政府事务的九位唯一标识符，其泄露无疑加剧了风险。此外，暴露的数据中还包括敏感身份证件的截图，例如驾照以及美国国防部颁发的DD214表格——这是证明退伍军人服役经历的正式文件。更令人担忧的是，数据库中还包含大量与就业和税务相关的材料，例如税收抵免项目的申请表、官方批准或拒绝信函等，这些文件中往往包含详细的财务和个人信息。同时，大量与就业和税务相关的材料也遭泄露，涵盖税收抵免项目的申请资料、官方批准或拒绝信函等，其中常包含复杂的财务和个人细节。尽管部分文件显示访问受限，但许多文档在互联网上可被任意获取。值得注意的是，一些加密PDF文件的文件名也被暴露，其中包含雇主和申请人姓名等个人信息，这些文件名中的数字部分理论上可能包含密码信息。  
  
参考链接：  
  
https://hackread.com/rockerbox-server-tax-firm-exposed-sensitive-records/  
  
  
恶意软件  
  
新型跨平台木马SparkKitty针对东南亚及中国地区用户展开攻击  
  
近日，网络安全研究人员发现一款名为“SparkKitty”的新型木马程序，该木马程序自  
2024年初以来持续活跃，专门针对东南亚和中国的移动设备用户，尤其聚焦于加密货币、博彩及成人娱乐等高价值行业。SparkKitty被认为是此前SparkCat攻击活动的进化版本，具备更强的隐蔽性和跨平台攻击能力，能够同时感染iOS与Android系统，并成功渗透进官方应用商店及第三方下载网站，对移动生态安全构成严重威胁。  
  
SparkKitty的传播方式多样且隐蔽。在Android平台上，该木马程序通常伪装成合法应用，例如一款名为  
SOEX的加密货币社交交易平台，曾在Google Play商店中获得超过一万次下载，后被发现内置恶意代码。该应用使用Java和Kotlin编写，部分变种还利用Xposed框架注入代码，实现对系统级应用的操控。在iOS平台，SparkKitty则通过伪造知名开发框架（如AFNetworking）或滥用企业签名配置文件进行分发。例如，一款名为“币coin”的加密货币行情追踪应用，就通过企业签名绕过App Store审核机制，成功安装至用户设备。  
  
一旦用户安装并运行这些被篡改的应用，  
SparkKitty便会立即启动其恶意行为。在iOS系统中，它利用Objective-C语言的类加载机制，在应用启动时自动触发恶意代码。通过检查应用配置文件中的特定键值，确保只在目标设备上运行，随后使用AES-256加密算法解密Base64编码的配置信息，进而访问用户相册，并将所有图片上传至远程服务器。在Android系统中，SparkKitty则在应用启动或用户触发特定操作时激活，获取存储权限后全面扫描并上传设备中的所有图片。  
  
与以往  
SparkCat仅通过OCR技术识别特定图片不同，SparkKitty采取更为激进的数据采集策略，不加筛选地上传用户相册中的所有图像。这一策略大幅提升了其获取敏感信息的概率，包括加密货币钱包助记词、身份证件、银行卡照片等。该木马程序还在本地建立数据库，记录已上传的图片，并持续监控相册变化，以便实时窃取新增内容。  
  
SparkKitty的后端基础设施同样具备高度的抗打击能力。其恶意载荷和控制服务器广泛部署于AWS S3和阿里云OSS等主流云服务平台，增强了其持续运营能力。此外，其命令与控制（C2）通信通过“/api/putImages”接口实现图片上传，整个流程高度自动化，难以被用户察觉。  
  
研究人员在技术分析中指出，  
SparkKitty的技术设计虽未对地域作出明确限制，但其目标应用多聚焦于东南亚和中国用户常用的加密货币、博彩和娱乐类应用，显示出明显的地域定向特征。不过更令人担忧的是，该木马还侵入多款高风险应用，包括被篡改的  
TikTok修改版，并且已成功绕过  
Google Play和Apple App Store的安全审核机制，存在全球扩散的潜在风险。  
  
参考链接：  
  
https://blog.polyswarm.io/sparkkitty-trojan-targets-mobile-users-with-cross-platform-espionage  
  
  
勒索软件  
###   
  
新兴BERT勒索软件组织针对亚洲和欧洲展开攻击活动  
  
近日，研究人员发现一个名为  
BERT（又称  
Water Pombero）的新兴勒索软件组织正在对亚洲和欧洲多个国家的机构发起网络攻击。该组织自2025年4月起开始活跃，攻击目标涵盖医疗、科技、活动服务等多个行业，影响范围已扩展至美国、亚洲和欧洲地区。BERT勒索软件组织虽然采用了相对简单的代码结构，但其攻击手段却极具效率。该组织同时针对Windows和Linux平台发动攻击，利用PowerShell脚本作为初始加载器，通过远程服务器下载并执行勒索软件载荷。在Windows系统中，攻击者使用名为“start.ps1”的PowerShell脚本，首先提升系统权限，随后关闭Windows Defender防火墙和用户账户控制（UAC）等安全机制，最终从位于俄罗斯境内的IP地址（185.100.157.74）下载勒索软件主程序（payload.exe）并执行。该IP地址归属于俄罗斯注册的ASN 39134，尽管仅凭此信息尚无法确定攻击者的具体归属，但使用俄罗斯基础设施可能暗示其与该地区存在某种关联。  
  
在攻击过程中，  
BERT勒索软件会主动终止与Web服务器、数据库及其他关键服务相关的进程，以确保加密过程顺利进行。随后，它使用标准的AES加密算法对文件进行加密，并将文件扩展名更改为“.encryptedbybert”，同时留下勒索信息，要求受害者支付赎金以恢复文件访问权限。  
  
值得注意的是，  
BERT勒索软件在开发过程中不断迭代优化。早期版本首先枚举系统驱动器，收集所有待加密文件路径并存储在数组中，然后再进行多线程加密。而最新版本则采用了更高效的并发队列（ConcurrentQueue）技术，并为每个驱动器创建独立的加密线程（DiskWorker），实现边发现边加密，大幅提升了加密速度和效率。  
  
除了  
Windows平台外，BERT组织还积极针对Linux系统，尤其是运行VMware ESXi虚拟化平台的服务器。在Linux环境下，该勒索软件默认启用高达50个线程进行并发加密，以最大限度地提高加密速度，降低被检测或中断的风险。此外，它还会主动执行ESXi命令，强制关闭所有正在运行的虚拟机进程，从而严重破坏受害者的业务连续性并阻碍数据恢复工作。  
  
技术分析显示，  
Linux变体的配置以JSON格式嵌入二进制文件，包含公钥、Base64编码的勒索信息等关键内容，且可能复用了2021年出现的Revil勒索软件Linux版本的代码，与Babuk源码及Conti、Revil相关的ESXi攻击工具存在技术重叠，体现出对成熟恶意代码的改造与再利用。  
  
从技术特点来看，  
BERT虽依赖简单代码库，却通过多重策略实现高效攻击与防御规避：在执行层面，借助PowerShell的脚本解释能力加载恶意payload；在防御规避上，通过修改注册表、禁用防火墙、绕过UAC等方式削弱系统防护；在发现阶段，枚举文件目录、虚拟机及关键进程以精准定位目标；在影响阶段，除加密数据外，还通过破坏数据、加密虚拟机快照等手段阻止恢复，形成“加密 + 破坏”的双重打击。这种“简单代码+高效执行”的模式，使得该组织无需复杂技术即可达成攻击目标，凸显了新兴威胁组织的灵活性与危害性。  
  
参考链接：  
  
https://www.trendmicro.com/en_us/research/25/g/bert-ransomware-group-targets-asia-and-europe-on-multiple-platforms.html  
  
往期推荐  
  
  
[LockBit勒索组织发布声明并重建泄露网站——每周威胁情报动态第166期（2.23-2.29）](http://mp.weixin.qq.com/s?__biz=MzI0MTE4ODY3Nw==&mid=2247492114&idx=1&sn=8d7c5643b4d7b9e6ba5fdb73db25f5ac&chksm=e90dc838de7a412e358185c880ff13f5960c816f47faef975adecc92aa229dd947eaed7c1543&scene=21#wechat_redirect)  
  
  
[GoldFactory组织开发针对iOS系统的GoldPickaxe木马病毒——每周威胁情报动态第165期（2.9-2.22）](http://mp.weixin.qq.com/s?__biz=MzI0MTE4ODY3Nw==&mid=2247492108&idx=1&sn=9a94a877d19aae993613beabfed515b9&chksm=e90dc826de7a4130e9c14fbecc4bb470c785600d65f4eca984822a3772b801007188d753444b&scene=21#wechat_redirect)  
  
  
[新APT组织APT-LY-1009针对亚美尼亚政府投递VenomRAT——每周威胁情报动态第164期（02.02-02.07）](http://mp.weixin.qq.com/s?__biz=MzI0MTE4ODY3Nw==&mid=2247492097&idx=1&sn=53ec18ecbac467ab6dddeef971e8630f&chksm=e90dc82bde7a413df05e08bc4d6136b60d4a339310cdb66a046cc0645bb90e447b8564e16180&scene=21#wechat_redirect)  
  
  
[APT28组织对全球多个组织发起NTLMv2哈希中继攻击——每周威胁情报动态第163期（01.26-02.01）](http://mp.weixin.qq.com/s?__biz=MzI0MTE4ODY3Nw==&mid=2247492083&idx=1&sn=2c985de24dfa929181ba8e6ae63b02ab&chksm=e90dcbd9de7a42cf2f738cbe44a3859ab3f78636b84ef2b930dfc29ecbfc05542ae161ab4e16&scene=21#wechat_redirect)  
  
  

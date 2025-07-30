#  警惕隐藏在网络社交媒体中的“猎密者”；CNNVD通报PHP 操作系统命令注入漏洞 | 牛览   
 安全牛   2024-06-14 12:04  
  
点击蓝字·关注我们   
/   
aqniu  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBjwIRcuxcIx3fvDBydiaqkxw4o55dLPMJBKVsRbYl7ULkJDmFtatY9fWSIcZttiaeQm76cm0TXSBCA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**新闻速览**  
  
  
**ㆍ**警惕隐藏在网络社交媒体中的“猎密者”  
**ㆍ**CNNVD通报PHP 操作系统命令注入漏洞  
**ㆍ**卡巴斯基在ZkTeco生物扫描识别设备中发现多个安全缺陷  
**ㆍ**一种新的网络钓鱼工具包现身，可使用PWA窃取登录凭证  
**ㆍ**黑客在暗网上兜售 Google子域缺陷  
**ㆍ**Conti和LockBit勒索软件加密器核心开发者被捕  
**ㆍ**一种针对求职者的新型“WarmCookie”网络攻击**ㆍ**Black Basta组织利用 Windows权限缺陷开展攻击活动  
**ㆍ**流行多媒体播放器或遭远程代码执行攻击  
**ㆍ**可自我复制的 Morris II 蠕虫针对AI电子邮件助手发起攻击  
**ㆍ**AWS发布多项安全服务新功能  
  
**特别关注**  
  
  
  
**警惕隐藏在网络社交媒体中的“猎密者”**  
  
  
国家安全部微信公众号今日发布文章《警惕网络社交媒体中的“猎密者”》，内容显示：随着网络社交媒体平台逐渐成为我们日常生活中难以分割的一部分，境外间谍情报机关运用网络社交媒体平台窃密也愈发猖獗，并呈现以下特点。  
  
**1、隐蔽关注。**境外间谍情报机关人员往往会潜伏在网络社交媒体平台的暗处，从广大网友在网络社交媒体平台中发布的文字、照片、视频等信息中，分析寻找我涉密接密人员，并伺机展开“猎密行动”。  
  
**2、攀拉结交。**境外间谍情报机关人员发现目标后，可能会通过加好友攀拉关系、表示对相关工作内容的浓厚兴趣、开展研究合作、提供高收入“兼职”等方式，伪装其真实身份和意图，与我相关人员建立联系。  
  
**3、渗透窃密。**在初步建立信任后，境外间谍情报机关人员可能会采取金钱拉拢、诱蚀腐化等各种方式开展情报窃密，甚至会卸下伪装，以威胁警告等粗暴方式逼迫对象就范，以达到其窃密目的。  
  
对此，国家安全部门提醒，要想防范网络社交的隐形泄密风险，有效规避“猎密者”的追踪，应掌握以下“法宝”：  
  
1、时刻谨记网络社交媒体平台的开放性与匿名性，时刻保持必要的警惕心与防范心，避免成为不法分子的目标。  
  
2、不要在网络社交媒体平台中传播涉密工作场所的环境设施，显露本人证件、制服等表明工作身份物品，不要“打卡”标记涉密场所地理位置。  
  
3、不要在网络社交媒体平台中备注涉密工作人员的单位、职务等信息，严禁上传、存储涉密信息。  
  
4、不要向在网络社交媒体平台中认识的陌生网友透露自己的涉密接密人员身份，讨论涉密工作内容。  
  
一旦发现疑似境外间谍情报机关人员通过网络社交媒体平台打探、窃取我涉密信息或勾联我内部人员的情况，应立即拨打12339国家安全机关举报受理电话、通过网络举报平台（www.12339.gov.cn）、国家安全部微信公众号举报受理渠道或直接向当地国家安全机关进行举报，协助开展调查取证。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/jBkmJgcumEVSDc5uXacaMg  
  
**CNNVD通报PHP 操作系统命令注入漏洞**  
  
  
近日，国家信息安全漏洞库（CNNVD）正式通报了关于PHP 操作系统命令注入漏洞（CNNVD-202406-852、CVE-2024-4577）的相关情况。未经身份认证的攻击者可以使用特定的字符序列绕过防护，通过参数注入的方式在目标服务器上远程执行代码。PHP多个版本受该漏洞影响。  
  
  
一、漏洞介绍  
  
PHP是一种在服务器端执行的脚本语言，适用于开发动态网站和Web应用程序。未经身份认证的攻击者可以使用特定的字符序列绕过防护，通过参数注入攻击在目标PHP服务器上远程执行代码，获取敏感信息或造成服务器崩溃。  
  
  
二、危害影响  
  
  
未经身份认证的攻击者可以使用特定的字符序列绕过防护，通过参数注入的方式在目标服务器上远程执行代码。PHP 8.1至8.1.29之前版本，PHP 8.3至8.3.8之前版本，PHP 8.2至8.2.20之前版本均受该漏洞影响。  
  
  
三、修复建议  
  
  
目前，PHP官方已发布新版本修复了该漏洞，CNNVD建议用户及时确认产品版本，尽快采取修补措施。官方更新版本下载链接：  
  
https://www.php.net/downloads.php  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/7HZHbIbjBITcmaRw-O-uVw  
  
  
  
**热点观察**  
  
  
  
**卡巴斯基在ZkTeco生物扫描识别设备中发现多个安全缺陷**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBGGFFsCJ1AL3Q9zV5L09xfibkeSzdf9COWgxLHb0Aic0Dl2icQrzIRhjxRQpqLgtNfGuAlMcHRpxCvg/640?wx_fmt=png&from=appmsg "")  
  
  
卡巴斯基实验室的研究人员近期发现，一款被广泛使用的流行生物识别扫描仪存在多个严重安全缺陷，这些缺陷可能使得攻击者得以非法访问医疗等关键系统的敏感数据。研究人员共披露了6个CVE缺陷编号，涉及ZkTeco生产的生物识别硬件存在代码注入问题。通过制作含有恶意代码的二维码，攻击者能够强制这些设备执行通常无法访问的系统指令。这些生物识别设备被广泛应用于包括核电厂、化工厂以及医院和办公室在内的各个领域，为黑客提供了潜在的攻击切入点。  
  
  
尽管这次研究关注点在于ZkTeco的产品，但卡巴斯基的研究人员表示，这些发现暗示了生物识别技术普遍存在严重的安全隐患。黑客可利用这些缺陷，入侵医疗系统窃取病患隐私数据。研究人员模拟的攻击过程显示，黑客首先可以通过制作假的二维码来访问设备本身，然后利用被入侵的硬件进一步渗透主数据库，获取医疗记录等敏感信息，甚至可以借助额外的缺陷下载合法用户的照片，制作伪造的生物识别凭证绕过身份验证。  
  
  
原文链接：  
  
https://www.scmagazine.com/news/kaspersky-researchers-punch-holes-in-biometrics-hardware-security  
  
  
**一种新的网络钓鱼工具包现身，可使用PWA窃取登录凭证**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBGGFFsCJ1AL3Q9zV5L09xfLjiaS244jDqIGMq9q1HDwTzSicJgO9e0icZIibnaTZcPtw9WzegdgQ378Q/640?wx_fmt=png&from=appmsg "")  
  
  
近日，安全研究员披露了一种新型的网络钓鱼工具包，可以利用渐进式网络应用程序（PWA）技术，来欺骗用户输入企业账号密码。这种新型网络钓鱼手法，利用了PWA应用程序能够集成到操作系统并模拟正常桌面程序的特性，让恶意应用程序看起来更加真实可信。  
  
  
PWA是一种基于Web技术（HTML、CSS和JavaScript）开发的应用程序，可以像原生桌面程序一样安装在操作系统上，并获得推送通知、离线工作等功能。安全研究员发现，这一技术也可能被利用进行网络钓鱼攻击。攻击者通过创建模仿企业登录界面的PWA应用，即使在显示正常公司网址的情况下，也能欺骗用户输入账号密码，从而窃取宝贵的企业凭证信息。攻击者通常会在感染恶意软件的网站上分发这种PWA网络钓鱼应用，诱导用户安装。一旦用户安装并运行该应用，它就会在浏览器中以桌面程序的形式运行，隐藏所有标准的浏览器控件，显示精心制作的企业登录界面，以窃取用户的登录凭证。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/new-phishing-toolkit-uses-pwas-to-steal-login-credentials/  
  
  
**黑客在暗网上兜售 Google子域缺陷**  
  
  
近日，一名自称"Tombstone"的黑客在暗网犯罪论坛Exploit上公布了多个影响 Google LLC 子域的缺陷，声称这些缺陷包括 XSS-DOM 和原型污染缺陷，并提供了受影响的 "edu.google.com" 域名的截图。Tombstone 在帖子中未透露具体价格，而是要求有兴趣方进行私下交流以获取更多细节。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBGGFFsCJ1AL3Q9zV5L09xfvWAdV0cjic1iaVySU0icyicKI14SjJxymib50TOR5W5vgxDsbr1wHsRw0MA/640?wx_fmt=png&from=appmsg "")  
  
  
XSS-DOM 缺陷能让攻击者将恶意客户端脚本注入其他用户查看的网页，可能导致会话劫持、网络钓鱼攻击、恶意软件分发和数据盗窃等后果；而原型污染缺陷涉及操纵 JavaScript 对象的原型以实现意外行为，通常会导致未经授权的数据操作或代码执行。  
  
  
原文链接：  
  
https://thecyberexpress.com/xss-dom-risks-in-google-subdomains/  
  
  
**Conti和LockBit勒索软件加密器核心开发者被捕**  
  
  
日前，乌克兰网络警察在“Operation Endgame”国际执法行动中，成功逮捕了一名28岁的嫌疑人，他涉嫌参与开发了用于勒索软件Conti和LockBit的加密组件，并在其中发挥了关键作用。  
  
  
加密器是一种软件，用于对恶意代码进行混淆或加密，以防止被杀毒软件和其他安全工具检测到。加密器通过将恶意软件转换为不可读形式，并将其与解密程序打包在一起，以在执行时恢复原始恶意代码。加密器在网络犯罪生态系统中起着重要作用，使恶意软件作者能够绕过安全防御。  
  
乌克兰网络警察表示：本次执法活动得到了荷兰警方的支持，目前调查仍在进行中，该男子将会根据乌克兰刑法第361条第5款被提起刑事起诉，最高可能面临15年的监禁。  
  
原文链接：  
  
https://securityaffairs.com/164475/breaking-news/developer-crypter-conti-lockbit-ransomware.html  
  
  
  
**网络攻击**  
  
  
  
**一种针对求职者的新型“WarmCookie”网络攻击**  
  
  
近日，网络安全研究人员发现了一种针对求职者的新型网络攻击活动，该攻击被称为“WarmCookie”，为网络攻击者提供了对目标系统的初始访问权限，一旦攻击者进入系统，就会频繁发起勒索软件攻击。这一网络攻击活动的操作流程如下：攻击者首先通过网络钓鱼电子邮件，向受害者发送有关新工作机会的信息，试图诱使受害者点击链接查看职位描述，一旦受害者点击链接，就会触发“WarmCookie”恶意软件的部署。该恶意软件正被用来破坏全球组织，它采用自定义加密、动态代码加载和反分析检查等方法逃避检测。  
  
  
WarmCookie是一种“轻量级后门”，为黑客提供了访问受害者信息、监控受害者以及部署其他有效载荷的能力。为应对这种新型网络攻击，安全专家建议实施高级电子邮件安全解决方案，限制使用PowerShell等异地二进制文件，保持端点防护系统的最新状态，并监控入侵和持久性机制的指标。  
  
  
原文链接：  
  
https://www.cybertalk.org/malware-campaign-targeting-job-seekers-2/  
  
  
**Black Basta组织利用 Windows权限缺陷开展攻击活动**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBGGFFsCJ1AL3Q9zV5L09xfYZ2BQ6LfsHlQEFjgjoKTnRD0Us045sRbRzYiaPJXkcq07UoTxlsO75A/640?wx_fmt=png&from=appmsg "")  
  
  
安全研究人员表示,勒索软件犯罪集团Black Basta 可能一直在利用最近修补的 Windows 权限提升缺陷 CVE-2024-26169 作为零日攻击手段。这个缺陷发生在Windows错误报告服务中，如果被利用，攻击者可能会提升其权限。尽管微软在3月份已经发布了修复补丁，但据称Black Basta可能早就在补丁发布之前，就获得了这个缺陷的利用方法。  
  
  
据赛门铁克的研究人员分析称，最近部署的Black Basta勒索软件攻击中使用的缺陷利用工具，发现有证据表明该缺陷可能已经被利用作为零日缺陷。尽管这次攻击未能成功部署勒索软件，但研究人员表示，所使用的策略、技术和程序与微软之前报告的Black Basta活动非常相似。安全专家们正在密切关注Black Basta的动向，因为其近期攻击医疗系统等关键行业引起了高度关注。与其他勒索软件团伙不同，Black Basta除了要求赎金外，还威胁发布受害者的敏感数据和知识产权。尽管CVE-2024-26169已经打了补丁，但大部分安全团队可能还没有及时更新，因为这个缺陷的严重性评分相对较低。  
  
  
原文链接：  
  
https://www.scmagazine.com/news/black-basta-exploits-patched-windows-privilege-escalation-bug  
  
  
**流行多媒体播放器或遭远程代码执行攻击**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBGGFFsCJ1AL3Q9zV5L09xfDrKBnBztI1eZzXDGIWzWxd2dJDt3fPcAsMuyFibSyWcUtFsw1xkelFg/640?wx_fmt=png&from=appmsg "")  
  
  
近日，VideoLAN 组织披露了流行的 VLC 媒体播放器存在多个严重缺陷，可能允许攻击者远程执行任意代码，这些缺陷影响了 VLC 媒体播放器的桌面版和 iOS 版本。  
  
  
其中，缺陷 SB-VLC3021 影响桌面版本，涉及一个潜在的整数溢出，可通过恶意构造的 MMS 流触发，导致堆溢出。如果成功利用，该缺陷可能允许恶意第三方使 VLC 媒体播放器崩溃或以目标用户的权限执行任意代码。尽管地址空间布局随机化（ASLR）和数据执行保护（DEP）有助于缓解代码执行风险，但这些保护机制仍可能被绕过。利用此缺陷需要用户明确打开恶意构造的 MMS 流，VLC 开发团队已在版本 3.0.21 中解决了此问题，用户被敦促更新到此最新版本以保护自己免受此缺陷的影响。  
  
  
另一个缺陷 SB-VLC-iOS359 影响 iOS 版本，涉及 VLC 的 WiFi 文件共享功能中发现的一个潜在的路径遍历缺陷。该缺陷可能允许本地网络上的恶意方上传任意数据到应用程序上下文中不可见的存储位置，可能导致设备上的拒绝服务（DoS）状况。VLC-iOS 版本 3.5.9 解决了此问题，建议用户更新到此版本以保护设备免受此缺陷的影响。到目前为止，尚未发现通过该缺陷执行代码的利用案例，但潜在风险仍然很高，建议用户采取预防措施。  
  
  
原文链接：  
  
https://cybersecuritynews.com/vlc-media-player-vulnerabilities/  
  
  
**可自我复制的 Morris II 蠕虫针对AI电子邮件助手发起攻击**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBGGFFsCJ1AL3Q9zV5L09xfniamRFt6s9vIVE773tFyFJNO3w3iaFad6LYpiapE1XOzShHZh5cdTIS1w/640?wx_fmt=png&from=appmsg "")  
  
  
近期，据研究发现，基于先进人工智能和自然语言处理技术的自我复制恶意软件"Morris II"，正在针对新兴的生成式人工智能（GenAI）电子邮件助手发起攻击。这种新型蠕虫利用对抗性自我复制提示，通过操纵GenAI模型的语言处理能力，实现数据窃取、账户劫持和在互联系统间的自动传播。  
  
  
该恶意软件针对OpenAI的GPT-3、Google的Smart Compose等主流GenAI电子邮件助手进行了测试，展现出高度的自主传播能力和破坏性。Morris II通过制作看似无害的提示诱导AI助手执行恶意命令，并利用GenAI生态系统的互联性，将自身快速传播到更多受害系统。这种新型攻击手段，不仅可能造成信息泄露和通信中断，还可能引发规模性的二次感染。  
  
  
原文链接：  
  
https://securityintelligence.com/posts/morris-ii-self-replicating-malware-genai-email-assistants/  
  
  
  
**产业动态**  
  
  
  
**AWS发布多项安全服务新功能**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkBGGFFsCJ1AL3Q9zV5L09xfKn40lAq5UJl7ABVMYaCiaXp7PkfVRxsjGYfSzVjh8SHkeN5eNkX5auw/640?wx_fmt=png&from=appmsg "")  
  
  
日前，AWS公司发布了多项新的和改进的安全功能，这些新功能涵盖了多方面领域，包括身份验证、访问管理、恶意软件防护以及人工智能应用程序的治理。首先，AWS增加了对FIDO2密钥的支持，作为第二种多因素身份验证选项，适用于有严格安全要求的客户；其次，AWS改进了Identity and Access Management （IAM） Access Analyzer，可以帮助组织识别和删除未使用的角色、访问密钥和密码，并设置、验证和细化未使用的权限；AWS还将Amazon GuardDuty Malware Protection的功能扩展到检测上传到S3存储桶的恶意文件。  
  
此外，AWS Audit Manager的AI最佳实践框架也得到了更新，这个框架简化了证据收集，并使客户能够持续审核和监控其生成式AI工作负载的合规性状况。这些新功能旨在帮助AWS客户在云上实现更出色的安全性和合规性。除此之外，AWS还推出了其他有帮助的新增功能和改进，包括简化存储在AWS CloudTrail Lake中的日志分析，以及简化网络服务集成等。  
  
  
原文链接：  
  
https://www.helpnetsecurity.com/2024/06/12/aws-security-features/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kuIKKC9tNkAfZibz9TQ8KWj4voxxxNSGMnicXSRCtG4URyLibbqPegjnnibfRB0z4zIzwghbLOkV5fqGYM8vhuQdqw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
合作电话：18311333376  
  
合作微信：aqniu001  
  
投稿邮箱：editor@aqniu.com  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/kuIKKC9tNkAfZibz9TQ8KWj4voxxxNSGMAGiauAWicdDiaVl8fUJYtSgichibSzDUJvsic9HUfC38aPH9ia3sopypYW8ew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

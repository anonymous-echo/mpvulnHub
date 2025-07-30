#  商用间谍软件pcTattletale惊现漏洞和后门！17TB敏感数据遭泄露！   
 网络安全应急技术国家工程中心   2024-05-28 14:52  
  
**一位独立研究人员曝光了商业级pcTattletale间谍软件工具中可能危及录音的漏洞后不久，该工具的网站就被黑客入侵并遭到破坏。****该黑客声称已访问了至少17TB的受害者截图和其他敏感数据，在研究人员披露有限信息以防止不良行为者利用该漏洞后，他将该网站的黑客攻****击视为个人挑战。黑客事件发生后，亚马逊立即对该网站的AWS基础设施进行了官方锁定。据悉，美国至少三家温德姆酒店的入住系统中已发现这款消费级间谍软件应用程序在运行****。****目前披露出来的受影响的客户已不仅限城酒店业，家族、大型企业本、****政府机构均有涉及。文发布时，pcTattletale网站似乎已关闭。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVprrTk7GmiaHicF8QKobLoPc0nWjyJ4Ir6nrntm9ia0OrA53kenS62WcGroOGV9UTdNLJibfhe1LEpdg/640?wx_fmt=webp&from=appmsg "")  
  
**pcTattletale间谍软件简介**  
  
pcTattletale间谍软件由一家名为pcTattletale LLC的美国公司开发和提供。该公司专注于开发监控和追踪软件，旨在帮助家长、雇主和其他用户监视其设备和员工的活动。  
  
该软件的主要功能包括，实时屏幕截图、位置跟踪、远程监控和键盘记录等。用户可以通过该软件实时查看目标设备的屏幕活动，了解设备的使用情况，并跟踪设备的位置。此外，pcTattletale还提供了远程监控和控制功能，允许用户远程访问目标设备并执行操作。  
  
pcTattletale通常以软件形式部署在目标设备上，并在后台运行，监控和记录设备的活动。用户可以通过pcTattletale的在线控制面板远程访问和管理目标设备。  
pcTattletale为Android和Windows开发间谍软件应用程序，这两款应用程序都需要物理访问目标设备才能安装。根据TechCrunch自己对间谍软件的测试和分析，pcTattletale提供其Windows间谍软件应用程序，只需单击下载即可，几秒钟内即可安装。   
  
pcTattletale还提供一项名为“我们为您服务”的服务，该公司表示，这项服务将代表客户帮助在目标计算机上安装间谍软件。   
  
pcTattletale间谍软件最早应用的时间可以追溯到2011年左右。随着技术的发展和监控需求的增加，pcTattletale不断更新和改进其功能，以满足不同用户的需求。  
  
pcTattletale的主要用户包括家长、雇主、监管机构和个人用户等。家长可以使用pcTattletale监控和控制他们的孩子在互联网上的活动，雇主可以使用pcTattletale监控和追踪员工的工作表现，监管机构可以使用pcTattletale进行调查和侦查，个人用户可以使用pcTattletale保护他们的设备和数据安全。  
  
pcTattletale间谍软件的缺陷架构及其发现表明常见间谍软件应用程序中存在固有漏洞，可能不仅影响个人，还会影响整个组织和家庭。  
  
**pcTattletale涉嫌漏洞与泄露事件缘起**  
  
**5月22日，TechCrunch报道称美国多家酒店的登记入住电脑正在运行一款远程访问应用程序，该应用程序正在将客人信息的截图泄露到互联网上。**  
  
TechCrunch获悉，美国至少三家温德姆酒店的入住系统中发现运行着一款消费级间谍软件应用程序。  
  
这款名为pcTattletale的应用程序会秘密持续截取酒店预订系统的屏幕截图，其中包含客人详细信息和客户信息。由于这款间谍软件存在安全漏洞，互联网上的任何人都可以获取这些屏幕截图，而不仅仅是间谍软件的目标用户。   
  
这是最近一次消费者级间谍软件因自身安全漏洞而泄露敏感信息的例子。这也是pcTattletale第二次泄露安装该应用程序的设备的屏幕截图。近年来，其他几款间谍软件应用程序也存在安全漏洞或配置错误，导致不知情的设备所有者的私人和个人数据被泄露，在某些情况下，政府监管机构采取行动。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVprrTk7GmiaHicF8QKobLoPcLLXYTApIlPMAnmMfIicgz7JudTwfQIadC6eLVZ3PRtJ2bjibH7YqptoQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVprrTk7GmiaHicF8QKobLoPcPohqibeZoRNVPrw7vuZFn43tFLZlF4ia2W92tCZQRZuwUoLAoBfHq3cg/640?wx_fmt=png&from=appmsg "")  
  
**pcTattletale间谍软件漏洞和不良数据处理实践**  
  
pcTattletale间谍软件工具的主要功能是实时提供受害者设备的屏幕截图，此外还有位置跟踪等典型间谍软件功能。然而，这种建立在糟糕基础设施和数据处理实践基础上的广泛监控功能也成为了其败笔，数据泄露事件会暴露目标的私人数据。  
  
首先，2021年的数据泄露事件暴露了间谍软件工具域基础设施中存在个人目录覆盖(IDOR)漏洞，可能允许通过可猜测的Amazon S3 URL访问敏感数据。  
  
上周，研究员Eric Daigle发现了一个API漏洞，该漏洞也可能允许跨注册设备访问敏感数据。此漏洞允许未经授权的用户以全面屏幕录制的形式访问私人信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVprrTk7GmiaHicF8QKobLoPcicFHRZU2ic6JicOzJeFXKHbg4JjVo18sOzNuianUJyAM7Nu9stJpJNUa3Q/640?wx_fmt=png&from=appmsg "")  
  
随后的一次黑客攻击将pcTattletale的后端暴露给公众，暴露了其对安全实践的惊人漠视。黑客发现，该间谍软件附带了硬编码的AWS凭证，可通过隐藏的Webshell访问，从而可能导致多年未被发现的数据泄露。这一疏忽因其简单性和持续时间而引人注目，凸显了用户数据处理方面的重大失误。  
  
**pcTattletale间谍软件最新破解**  
  
黑客破坏了pcTattletale的官方网站，取而代之的是操作记录和从该网站的AWS基础设施获取的受感染数据的链接。pcTattletale存储的数据量惊人，黑客报告称，他们发现了来自10,000多台设备的超过17TB的受害者设备截图，其中一些截图可追溯到2018年。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVprrTk7GmiaHicF8QKobLoPcSnjYCx2gCicmnKqF6bTlkuDLw2Ptlx8npYcxNqqzcpEWeVXianL9DbzA/640?wx_fmt=webp&from=appmsg "")  
  
虽然发布的数据转储中没有包含这些屏幕截图，但据报道它包含数据库转储、stalkerware服务的完整webroot文件以及其他 S3存储桶内容，暴露了多年的敏感信息。  
  
**pcTattletale间谍软件还存在一个隐藏的Shell**  
  
此次入侵还发现了一个简单的Webshell，它至少从2011年12月起就隐藏在间谍软件的后端代码中。**这个后门允许通过使用cookie来执行任意PHP代码，这让人怀疑它的来源——它是pcTattletale自己放置的后门，还是威胁行为者放置的。**  
  
黑客随后更新了被破坏的网站并分享了一段视频，声称这是pcTattletale创始人尝试恢复网站的镜头。  
  
被破坏的网站花了20多个小时才被关闭，而pcTattletale的服务继续将截图发送到S3存储桶，直到亚马逊正式锁定该间谍软件服务的AWS账户。  
  
pcTattletale间谍软件AWS Amazon Lock  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVprrTk7GmiaHicF8QKobLoPcSh5Kus8ficrdRx1ZWWJd0sxJsUN2OE4vuSw7jXlg5UKrt864YUibuPcg/640?wx_fmt=other&from=appmsg "")  
  
在该网站的AWS基础设施正式关闭后，安全研究员Eric Daigle进一步披露了此前披露的有限漏洞，并逐步利用了漏洞。他指出，虽然该网站的攻击者利用了一个不相关的漏洞，但其复杂性同样微不足道。  
  
**受pcTattletale间谍软件数据泄露影响的受害者**  
  
pcTattletale数据泄露尤其令人担忧，因为有多家组织使用该工具来监控员工和客户，泄露了银行、律师事务所、教育机构、医疗保健提供商甚至政府机构等各个部门的机密信息。安全研究员maia  crimew探讨了这一 事件并在博客文章中分享了数据，他指出受数据泄露影响的受害者包括：  
  
**酒店泄露客人信息，例如个人数据和信用卡详细信息。**  
  
**律师事务所曝光律师与客户之间的沟通以及客户银行路由信息**  
  
**一家银行泄露机密客户数据**  
  
**学校、托儿所等教育机构监视员工或学生，泄露个人数据。**  
  
**医疗保健提供者泄露患者信息。**  
  
**巴勒斯坦政府机构雇员受到监控。**  
  
**波音公司供应商的人力资源部门泄露员工个人信息。**  
  
**科技公司在涉嫌不法行为的员工设备上秘密安装pcTattletale，暴露内部系统和源代码。**  
  
**一名漏洞赏金猎人安装了该软件并希望进行渗透测试，然后立即试图卸载它。**  
  
令人担忧的是，这款间谍软件还可以让父母和配偶监视各自的孩子和伴侣，从而有可能在随后的入侵中暴露这些信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVprrTk7GmiaHicF8QKobLoPcicSXtzEW7EFpicGsaql4yDn8iaezdhAVdia2bsgAagXpfCiaysHmiajtPhpQ/640?wx_fmt=jpeg&from=appmsg "")  
  
鉴于受影响的公司范围广泛且存在重大安全漏洞，安全研究员maia crimew指出，pcTattletale可能面临严重后果，可能导致其停止运营，因为美国联邦贸易委员会(FTC)此前已下令其他美国跟踪软件开发商在发生违规行为后停止运营，而pcTattletale的案件也将面临类似的后果。  
  
**间谍软件滥用危害是个复杂问题**  
  
pcTattletale的广泛滥用和系统性安全漏洞凸显了跟踪软件和服务所固有的危险，以及迫切需要对这些工具进行严格的监管监督和强有力的安全措施，以保护个人和组织的数据和隐私。  
  
2023年，研究人员发现一家西班牙间谍软件供应商的工具在其漏洞链中使用了多个零日漏洞和n日漏洞，并通过短信中的一次性链接传递间谍软件模块。这些工具被用来攻击阿拉伯联合酋长国(UAE)的目标。  
  
上个月，苹果向92个不同国家的用户发出通知，提醒他们警惕雇佣间谍软件攻击。同月，美国政府对被确定与商业间谍软件的使用/传播有关或从中获利的个人发布了多项签证限制。  
  
美国政府在通知中表示，他们担心这些应用程序可能会被用来侵犯人权或进行反情报活动，因此才发布这些限制措施。一些隐私倡导人士、反跟踪软件联盟 等组织以及美国国家网络安全联盟等非营利组织也表达了同样的担忧。  
  
  
**参考资源**  
  
1、https://thecyberexpress.com/amazon-locks-pctattletale-spyware-hack/  
  
2、https://thecyberexpress.com/pctattletale-stalkerware-leaks-recordings/#google_vignette  
  
3、https://techcrunch.com/2024/05/22/spyware-found-on-hotel-check-in-computers/  
  
4、https://www.ericdaigle.ca/pctattletale-leaking-screen-captures/  
  

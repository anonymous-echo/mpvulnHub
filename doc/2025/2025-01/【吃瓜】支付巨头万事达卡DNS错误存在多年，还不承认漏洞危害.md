#  【吃瓜】支付巨头万事达卡DNS错误存在多年，还不承认漏洞危害   
 独眼情报   2025-01-23 03:19  
  
支付卡巨头**万事达**刚刚修复了域名服务器设置中的一个明显错误。通过注册一个未使用的域名，攻击者本可拦截或转移该公司的互联网流量。这一配置错误持续了近五年，直到一位安全研究员花费300美元注册了这个域名，防止被网络犯罪分子利用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnTaSia36B3CsibxluGiaOeQ9uLGOYz3fHPnOK5jTawiaGhJBUY5VpjGkiawBj5ibO2JDwAzgFwjMXutopZA/640?wx_fmt=png&from=appmsg "")  
  
2025 年 1 月 14 日对域名 az.mastercard.com 进行 DNS 查找，显示错误输入的域名 a22-65.akam.ne  
  
从2020年6月30日到2025年1月14日，万事达用于定向mastercard.com网络部分流量的一个核心互联网服务器被错误命名。万事达依赖互联网基础设施提供商**Akamai**的五个共享域名系统（DNS）服务器。  
  
所有万事达使用的Akamai DNS服务器名称本应以"akam.net"结尾，但其中一个被错误配置为依赖"**akam.ne**"域。  
  
这个看似微小但可能极其关键的拼写错误最近被安全咨询公司Seralys的创始人**Philippe Caturegli**发现。Caturegli推测没人注册过akam.ne域名，该域名隶属于尼日尔国家顶级域名管理机构。  
  
Caturegli表示，他花了300美元和近三个月的时间在尼日尔注册了这个域名。启用DNS服务器后，他注意到每天有数十万个来自全球各地的DNS请求访问他的服务器。显然，万事达并非唯一一个在DNS条目中出现"akam.ne"的组织，但绝对是规模最大的。  
  
若他在新域名akam.ne上启用了邮件服务器，可能会收到发往mastercard.com的错误邮件。如果滥用访问权限，他甚至可能获得授权接受和转发相关网站流量的网站加密证书（SSL/TLS），甚至被动接收受影响公司员工电脑的微软Windows身份验证凭据。  
  
但该研究员表示他没有尝试这些行为。相反，他通知万事达，这个域名可供他们使用。几小时后，万事达承认了错误，但表示对其运营安全没有实际威胁。（**没有影响****，忽略😂）**  
  
"我们已调查此事，我们的系统没有风险，"一位万事达发言人写道。"这个拼写错误现已更正。"  
  
与此同时，Caturegli收到了Bugcrowd的一项请求。在LinkedIn上公开披露万事达DNS错误后，该平台认为他的行为不符合道德安全实践，并传达了万事达要求删除该帖子的请求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnTaSia36B3CsibxluGiaOeQ9uLNWy0ibZNtF6lydSTVjtXxIiawJYUyFicd1PKeXab8DqqE812t0U4HNW6Q/640?wx_fmt=png&from=appmsg "")  
  
MasterCard 向 infosec.exchange 上的 Caturegli（又名“Titon”）发出的请求  
  
Caturegli 表示，虽然他在 Bugcrowd 上有一个账户，但他从未通过 Bugcrowd 程序提交过任何东西，并且他直接向万事达卡报告了这个问题。  
  
“我没有通过 Bugcrowd 披露这个问题，”Caturegli 在回复中写道。“在公开披露之前，我确保受影响的域名已注册，以防止被利用，从而减轻万事达卡或其客户面临的任何风险。我们自费采取的这一行动表明了我们对道德安全实践和负责任披露的承诺。”  
  
大多数组织至少拥有两个权威域名服务器，但有些组织处理的 DNS 请求太多，因此需要将负载分散到其他 DNS 服务器域上。在万事达卡的案例中，这个数字是五个，因此可以推断，如果攻击者设法控制其中一个域，他们只能看到大约五分之一的整体 DNS 请求。  
  
但Caturegli表示，现实情况是，许多互联网用户至少在一定程度上依赖公共流量转发器或 DNS 解析器，如Cloudflare和Google。  
  
Caturegli 表示：“因此，我们只需要让其中一个解析器查询我们的名称服务器并缓存结果。”通过为 DNS 服务器记录设置较长的 TTL 或“生存时间”（一种可以调整网络上数据包寿命的设置），攻击者针对目标域的毒化指令可以通过大型云提供商进行传播。  
  
“有了较长的 TTL，我们可能会重新路由远超 1/5 的流量，”他说。  
  
这位研究人员表示，他希望这家信用卡巨头可能会感谢他，或者至少愿意承担购买域名的费用。  
  
Caturegli 在 LinkedIn 上针对万事达卡公开声明的后续帖子中写道：“我们显然不同意这一评估。但我们让你来判断——以下是我们在报告问题之前记录的一些 DNS 查询。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnTaSia36B3CsibxluGiaOeQ9uLfCRiasSK8FdD1icBSXYv8QktefvA2cvZXuEQ0ZYyA9UFQlc1lBGh3cTw/640?wx_fmt=png&from=appmsg "")  
  
Caturegli 发布了万事达卡域名的屏幕截图，该域名可能因配置错误而存在风险  
  
如上图所示，Caturegli 发现配置错误的 DNS 服务器涉及 MasterCard 子域名az.mastercard.com。目前尚不清楚 MasterCard 如何使用该子域名，但其命名惯例表明这些域名与 Microsoft Azure云服务的生产服务器相对应。Caturegli 表示，这些域名均解析为 Microsoft 的 Internet 地址。  
  
“不要效仿万事达卡，”Caturegli在他的 LinkedIn 帖子中总结道。“不要忽视风险，也不要让你的营销团队处理安全披露问题。”  
  
最后需要注意的是：akam.ne 域名之前已被注册——2016 年 12 月，注册者使用电子邮件地址 um-i-delo@yandex.ru。俄罗斯搜索巨头 Yandex 报告称，该用户帐户属于莫斯科的“Ivan I”。DomainTools.com 的被动 DNS 记录显示，2016 年至 2018 年间，该域名连接到德国的互联网服务器，并且该域名将于 2018 年到期。  
  
有趣的是，Caturegli 的 LinkedIn 帖子上有一条来自前 Cloudflare 员工的评论，该员工链接到他合著的一份报告，该报告涉及一个类似的拼写错误域名，该域名显然是在 2017 年为一些组织注册的，这些组织可能将其 AWS DNS 服务器错误地输入为“ awsdns-06.ne ”而不是“ awsdns-06.net ”。DomainTools 报告称，这个拼写错误的域名也注册给了一位 Yandex 用户 (playlotto@yandex.ru)，并托管在同一个德国 ISP — Team Internet (AS61969) 上。  
  
  

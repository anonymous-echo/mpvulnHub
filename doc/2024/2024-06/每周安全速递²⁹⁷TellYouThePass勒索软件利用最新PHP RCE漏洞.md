#  每周安全速递²⁹⁷|TellYouThePass勒索软件利用最新PHP RCE漏洞   
 第59号   2024-06-14 14:28  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/gauNkjeXJb6GJE526lRyWDkreiaDuL8zly4jaGrCq5tM1iajOpEpFgMhfZYAkR5GcO1CUsNiaDv8dxQNaiaeQOdsoA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**第**  
**297期**  
  
****  
**本周热点事件威胁情报**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gauNkjeXJb6OMngSWljIP2vdukqAgFUggnyDGsaHn4gXclcbftlTyLTwDB86dsPYfIN0orjh03WBAdAyOOKx2Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
1  
  
  
**TellYouThePass勒索软件利用最新PHP RCE漏洞**  
  
TellYouThePass勒索软件团伙一直在利用最近修补的CVE-2024-4577远程代码执行漏洞，通过PHP传递webshell并在目标系统上执行加密器负载。攻击于6月8日开始，仅在PHP维护者发布安全更新后不到48小时，攻击者就利用了公开的漏洞利用代码。TellYouThePass勒索软件以快速利用具有广泛影响的公共漏洞而闻名。去年11月，他们在攻击中使用了Apache ActiveMQ RCE漏洞，2021年12月，他们采用了Log4j漏洞来入侵公司。研究人员发现的最新攻击中，TellYouThePass利用了严重级别的CVE-2024-4577漏洞来执行任意PHP代码，使用Windows的mshta.exe二进制文件运行恶意HTML应用程序（HTA）文件。该文件包含一个带有base64编码字符串的VBScript，该字符串解码为一个二进制文件，将勒索软件的.NET变种加载到主机的内存中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gauNkjeXJb6WqeeyhibN8HiaO7eBs3aAQ76ComHkOziaFdkq8mecYAIYAWcUMtOyJY1T62JlH9u3qheic7Rza7BsxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
参考链接：  
  
https://www.imperva.com/blog/update-cve-2024-4577-quickly-weaponized-to-distribute-tellyouthepass-ransomware/  
  
  
2  
  
  
**英国拍卖行Christie's声称遭遇RansomHub勒索组织攻击**  
  
英国拍卖行Christie's正在通知其数据在最近的网络泄露事件中被RansomHub勒索软件团伙盗取的个人。Christie's发现自己在2024年5月9日成为了影响其部分系统的安全漏洞的受害者。在意识到事件后，Christie's采取措施保护其网络，并聘请外部网络安全专家帮助调查事件的影响。拍卖行表示，它还通知了执法部门，并正在努力支持他们的调查。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb6WqeeyhibN8HiaO7eBs3aAQ7Lpz9wsGFtJUxOtl0ISo5awWVSgkSTyygLRfteLQjs5C1wsxZavzm6g/640?wx_fmt=png&from=appmsg "")  
  
  
参考链接：  
  
https://oag.ca.gov/system/files/Christie%27s%20Individual%20Notification%20Letter%20Template.pdf  
  
3  
  
  
**美国通信提供商Frontier声称遭遇勒索威胁影响75万客户数据**  
  
Frontier Communications正警告750000名客户，他们的信息在4月的网络攻击中被曝光，攻击由RansomHub勒索软件组织声称负责。Frontier是美国领先的通信提供商，通过光纤网络向25个州的数百万消费者和企业提供千兆互联网速度。该电信提供商表示，在2024年4月中旬遭受了一次网络攻击，黑客能够访问其系统中存储的客户个人信息。“2024年4月14日，我们检测到未经授权访问我们的一些内部IT系统。”受影响客户收到的数据泄露通知中写道。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb6WqeeyhibN8HiaO7eBs3aAQ7oicOfABruj7iboGGTaCho0KiczPHK8zJ8L6VXN5rAL5tC3L97nDibial3Ow/640?wx_fmt=png&from=appmsg "")  
  
参考链接：  
  
https://apps.web.maine.gov/online/aeviewer/ME/40/8391c11f-2946-414a-bdc1-6ceff4ae0caa.shtml  
  
4  
  
  
**Fog勒索软件窃取VPN凭证攻击美国教育部门**  
  
一种名为“Fog”的新型勒索软件操作于2024年5月初启动，使用被攻破的VPN凭证侵入美国教育机构的网络。研究人员发现了Fog，并报告称该勒索软件操作尚未建立勒索门户，也未发现窃取数据的行为。该勒索软件团伙通过窃取数据进行双重勒索攻击，利用数据作为杠杆吓唬受害者支付赎金。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb6WqeeyhibN8HiaO7eBs3aAQ7twRRCzfNDG1HwWEsDP4cYoOZ3K5xzeRgCXibcaPImic4spDS32HxPjtQ/640?wx_fmt=png&from=appmsg "")  
  
  
参考链接：  
  
https://bbs.antiy.cn/forum.php?mod=attachment&aid=NDg1NDE4fDU4MWMwYTA4fDE3MTgzMjk5ODh8MHwyMDgzMTY%3D  
  
5  
  
  
**研究人员披露攻击者入侵并清除GitHub仓库进行勒索**  
  
攻击者正在瞄准GitHub仓库，擦除其内容，并要求受害者通过Telegram联系获取更多信息。这场活动背后的威胁行为者，在Telegram上使用Gitloker的用户名并冒充网络事件分析师，很可能是使用被盗凭证入侵目标的GitHub账户。随后，他们声称窃取了受害者的数据，创建了一个备份，可以帮助恢复被删除的数据。然后，他们会重命名仓库，并添加一个README.me文件，指示受害者通过Telegram联系。“希望这条信息能找到你。这是一个紧急通知，告知你的数据已被泄露，我们已确保备份，”勒索信中写道。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb6WqeeyhibN8HiaO7eBs3aAQ7DJEE61kwUZ8m5e7qGuia1fLic8FworZGIb6J034DGF02wCOvSkPWgGxQ/640?wx_fmt=png&from=appmsg "")  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/new-gitloker-attacks-wipe-github-repos-in-extortion-scheme/  
  
6  
  
  
**FBI向受害者公开7000个LockBit勒索软件解密密钥**  
  
美国联邦调查局（FBI）披露，它掌握了超过7000个与LockBit勒索软件相关的解密密钥，以帮助受害者免费找回他们的数据。“我们正在联系已知的LockBit受害者，并鼓励任何怀疑自己是受害者的人访问我们的互联网犯罪投诉中心（ic3.gov），”FBI网络部助理局长布莱恩·沃恩德兰在2024年波士顿网络安全大会（BCCS）的主题演讲中说道。LockBit曾经是一个活跃的勒索软件团伙，与全球超过2,400起攻击有关，其中至少有1,800起影响了美国的实体。今年2月，由英国国家犯罪局（NCA）领导的代号为Cronos的国际执法行动拆除了其在线基础设施。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gauNkjeXJb6WqeeyhibN8HiaO7eBs3aAQ72YKBqBx8fia6RY9gNl8MkiaDUSLsDTDWAa0iaAQicXibhEiaJCbKiawgeeMxw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
参考链接：  
  
https://www.fbi.gov/news/stories/fbi-cyber-lead-urges-potential-lockbit-victims-to-contact-internet-crime-complaint-center  
  
7  
  
  
**伦敦多家医院勒索攻击事件被归因于Qilin勒索软件组织**  
  
本周一袭击病理服务提供商Synnovis并影响伦敦多家主要NHS医院的勒索软件攻击现已被归因于Qilin勒索软件团伙。英国国家网络安全中心（NCSC）首任首席执行官Ciaran Martin今天表示，Qilin团伙可能对这一事件负责。此次攻击导致Synnovis无法访问其系统，并引起Guy's和St Thomas' NHS Foundation Trust、King's College Hospital NHS Foundation Trust以及整个伦敦东南部的多个初级保健提供者的持续服务中断。目前，Synnovis客户服务门户上的警报警告称存在数据中心问题，所有系统目前均无法访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gauNkjeXJb6WqeeyhibN8HiaO7eBs3aAQ7hH9leDTA2L8IS9Nq1FZ07nUm8fzEfFNsvNrVJuVIBlsBQmkDfOFqPA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/qilin-ransomware-gang-linked-to-attack-on-london-hospitals/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/C6nwdaicQKwWT4HLCv7hz9cCjEYLXqWZJayhCdh0Ix1GdDpSicv8wAlW178gA8TSndNp9mZcsYGr6ubhibS8Odomg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
美创科技第59号安全实验室，专注于数据安全技术领域研究，聚焦于安全防御理念、攻防技术、漏洞挖掘等专业研究，进行知识产权转化并赋能于产品。自2021年起，累计向CNVD、CNNVD等平台提报数千个高质量原创漏洞，并入选国家信息安全漏洞库（CNNVD）技术支撑单位（二级）、信创政务产品安全漏洞库支撑单位，团队申请发明专利二十余项，发表多篇科技论文，著有《数据安全实践指南》、《内网渗透实战攻略》等。  
  
  
  
  
  

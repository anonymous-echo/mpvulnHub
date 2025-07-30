#  网安瞭望台第5期 ：7zip出现严重漏洞、识别网络钓鱼诈骗的方法分享   
原创 扬名堂  东方隐侠安全团队   2024-11-26 14:28  
  
网安资讯分享  
  
DAILY NEWS AND KNOWLEDGE  
  
  新鲜资讯&知识 抢先了解    
  
隐侠安全客栈  
  
**国内外要闻**  
  
  
    **7 - Zip存在高危漏洞，请立刻更新**  
  
2024 年 11 月 24 日，do son 报道了 7 - Zip 中存在的一个高严重性漏洞 CVE - 2024 - 11477。7 - Zip 是一款广受欢迎的文件压缩软件，而这个漏洞可能会让攻击者在存在漏洞的系统中执行恶意代码。  
  
    该漏洞由趋势科技安全研究人员 Nicholas Zubrisky 发现，问题出在 7 - Zip 程序的 Zstandard 减压功能上。由于对用户提供的数据验证不充分，会产生整数下溢的情况，这就为攻击者在受影响的进程中执行任意代码提供了机会。  
  
    此漏洞的 CVSS 评分为 7.8，意味着风险相当大。攻击者能够通过诱骗用户打开特别制作的存档文件来利用这个漏洞。一旦漏洞被成功利用，后果不堪设想，从数据被盗取到整个系统被完全控制都有可能发生。安全公告中提到，“要利用这个漏洞需要与该库进行交互，但攻击向量可能因具体实现方式的不同而有所变化”。  
  
    为了防止受到攻击，用户被强烈要求立即更新到 7 - Zip 24.07 或更高版本，因为最新版本已经解决了这个漏洞和整数下溢的缺陷。  
  
****  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
**WordPress 关键反垃圾插件漏洞使 20 万 + 网站**  
  
**面临远程攻击风险**  
  
    2024年11月26日，Ravie Lakshmanan报道了一则令人担忧的消息：WordPress的反垃圾插件存在两个关键安全漏洞，分别为CVE - 2024 - 10542和CVE - 2024 - 10781，这些漏洞对网站安全构成严重威胁。该反垃圾、防火墙插件被宣传为能阻止垃圾评论、注册等的“通用反垃圾插件”，安装量超过20万个WordPress站点。  
  
    这两个漏洞非常严重，CVSS评分高达9.8。它们都涉及授权绕过问题，CVE - 2024 - 10781是由于在6.44及之前版本的“perform”函数中没有对“api_key”值进行空值检查，导致攻击者能够进行未经授权的任意插件安装。而CVE - 2024 - 10542则是通过checkWithoutToken()函数上的反向DNS欺骗实现授权绕过。无论通过哪种方式绕过授权，攻击者一旦成功利用漏洞，就可以在受影响的网站上随意安装、激活、停用甚至卸载插件，更可怕的是，攻击者可能会通过安装恶意插件来实现远程代码执行。  
  
    在本月发布的6.44和6.45版本中，这些漏洞已得到修复。因此，插件用户务必将站点更新到最新版本，防止潜在的威胁。此外，Sucuri也发出警告，目前存在多个利用被入侵的WordPress网站进行恶意操作的活动，比如注入恶意代码，这些代码会通过虚假广告重定向网站访客，窃取登录凭证，投放捕获管理员密码的恶意软件，将用户重定向到VexTrio Viper诈骗网站，甚至在服务器上执行任意PHP代码，网站安全形势严峻。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH7Wrf5Ndia4uic8dE9qx5zhVtS2RDjZcTzicTK8NicL7bbOu0FCeBPgq23PbFyqdbxWMLQ2micdFtBN9Ew/640?wx_fmt=other&from=appmsg "")  
  
  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
**Intruder 发布 Intel：一个助力领先最新威胁的免费漏洞情报平台**  
    
  
      
2024年11月26日，The Hacker News报道了Intruder发布的Intel——一个免费的漏洞情报平台，旨在帮助用户领先于最新威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH7Wrf5Ndia4uic8dE9qx5zhVtZFxHG1udX1RNrAOPA68j3epHfNrwWQl1TVyhZMvicHDXSWibwcqU5qkQ/640?wx_fmt=other&from=appmsg "")  
  
    在网络安全领域，当漏洞（CVEs）广泛传播时，从众多信息中甄别出关键漏洞对保护组织安全至关重要。Intruder作为攻击面管理的领先者，构建了Intel平台。这个平台的诞生是为了填补追踪新兴漏洞资源方面的空白。去年，Intruder的一个常用工具关闭后，他们便着手打造这样一个不仅能满足自身需求，还能造福整个信息安全社区的解决方案。  
  
    Intel会追踪过去24小时内最热门的漏洞（CVEs），并给每个漏洞赋予一个“热度评分”（满分100），该评分以年内最高热度为基准。除了提供实时洞察外，Intel还有Intruder安全团队的专家评论，并整合了来自美国国家标准与技术研究院（NVD）和美国网络安全与基础设施安全局（CISA）等可靠来源的最新信息，将所有信息汇集一处。  
  
    Intel在五个方面帮助用户保持领先：一是能够让用户紧跟趋势，即时了解哪些漏洞在社交媒体上受到关注，确保用户知晓潜在高风险的CVEs；二是帮助用户理解漏洞热度，热度评分能让用户快速衡量和判断一个CVE所受到的关注程度；三是有专家提供背景分析，通过Intruder安全团队的分析，用户能更好地理解关键CVEs的实际影响，评估自身环境是否面临风险；四是提供集中的CVE洞察，Intel通过在一处提供最新信息（包括风险评分、已知漏洞利用等）来简化用户的研究；五是提供实时更新，通过Intel的RSS订阅源，每小时直接向用户的控制面板推送更新，确保用户不会错过热门CVE。用户可以从今天开始使用Intel，拨开迷雾，专注于最重要的威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH7Wrf5Ndia4uic8dE9qx5zhVtFG2KElwFe4xLEM0xdcTicjWIGvdS67BcARkLXZ7hian1tXIWwyjDJYKg/640?wx_fmt=other&from=appmsg "")  
  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
### RomCom 利用火狐与 Windows 零日漏洞发动复杂网络攻击   
  
        
2024年11月26日消息，与俄罗斯有关联的威胁行为体RomCom利用火狐和Windows的零日漏洞发动复杂网络攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH7Wrf5Ndia4uic8dE9qx5zhVtYrGpa53xSOgv4aThoRiaLf9qk1OS6j3G1uia5lxicDHWVWC8KaibgTP8MA/640?wx_fmt=other&from=appmsg "")  
  
    涉及的两个漏洞分别为：CVE - 2024 - 9680，是Firefox动画组件中的释放后使用漏洞，CVSS评分9.8，Mozilla于2024年10月修复；CVE - 2024 - 49039，为Windows任务计划程序中的权限提升漏洞，CVSS评分8.8，微软在2024年11月修复。  
  
    RomCom，又名多个别称，自2023年起就有网络犯罪和间谍活动记录。其攻击中会部署RomCom RAT恶意软件，能在受害者机器执行命令、下载模块。攻击链是利用虚假网站（economistjournal[.]cloud）将受害者重定向到托管恶意载荷的服务器（redjournal[.]cloud），借此串联两个漏洞实现代码执行并植入RomCom RAT。  
  
    关于攻击过程，虽不清楚虚假网站链接分发方式，但从易受攻击的Firefox版本访问该网站就会触发漏洞。访问相关网页时，外壳代码在内容进程执行，由两部分组成，最终实现Firefox沙箱逃逸，借助嵌入式库“PocLowIL”利用Windows任务计划程序漏洞获提升权限，得以在受感染系统下载执行RomCom RAT。ESET遥测数据显示，多数受害者位于欧洲和北美。  
  
    此外，CVE - 2024 - 49039由谷歌威胁分析小组发现并报告给微软，可能有多威胁行为体利用。这也是RomCom第二次利用零日漏洞，此前2023年6月曾通过Microsoft Word滥用过其他漏洞，此次利用凸显其获取隐蔽能力的手段和意愿。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH7Wrf5Ndia4uic8dE9qx5zhVtnfmfTXUMBIaRvs7MzjlRh0mdQE68icEQz7ibNMCDicpLz9zUYTUVDYadw/640?wx_fmt=other&from=appmsg "")  
  
  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
### CISA 督促各机构在遭受攻击期间修补 Array Networks 关键漏洞  
  
  
    近年  
2024年11月26日消息，美国网络安全与基础设施安全局（CISA）因有报告显示相关漏洞在野外被积极利用，将影响Array Networks AG和vxAG安全访问网关的关键安全漏洞（CVE-2023-28461，CVSS评分9.8）添加到已知被利用漏洞（KEV）目录。   
  
    此漏洞存在缺失认证问题，可被利用实现远程任意代码执行。Array Networks早在2023年3月就发布了修复版本（9.4.0.484）。其原理是攻击者能利用HTTP头中的flags属性，在无需认证的情况下于SSL VPN网关上浏览文件系统  
或执行远程代码，通过易受攻击的URL便可实施利用。   
  
    此前，趋势科技透露与中国有关联的网络间谍组织Earth Kasha（又名MirrorFace），一直在利用包括Array AG此漏洞在内的多款面向公众企业产品的安全漏洞获取初始访问权限。Earth Kasha常以日本实体为主要目标，近年也攻击过台湾、印度和欧洲等地。  
  
    本月早些时候，ESET还披露Earth Kasha针对欧盟某外交实体的活动，利用2025年大阪世界博览会作诱饵投放名为ANEL的后门。

鉴于该漏洞正遭积极利用，联邦民用行政部门（FCEB）机构被建议在2024年12月16日前应用补丁保障网络安全。   
  
    同时，据VulnCheck报告，在60个  
被点名的威胁行为体中，有15个中国黑客组织与2023年最常被利用的15个漏洞中至少一个漏洞的滥用有关，且已确定超440,000个暴露于互联网且可能易受攻击的主机。  
  
    相关人士建议组织评估自身对相关技术的暴露情况，强化风险监控，利用威胁情报，做好补丁管理并实施缓解控制措施以减少设备互联网暴露。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH7Wrf5Ndia4uic8dE9qx5zhVtA8jHGmJyiaVqTeK4fXwGIMyGf7vNBP1qj6icjHOd5ItwJI9iapWqibA3WA/640?wx_fmt=other&from=appmsg "")  
  
  
**知识分享**  
  
  
**识别网络钓鱼诈骗的方法**  
- 检查发件人的电子邮件地址。例如，你收到一封来自 “support@apple.com” 而不是 “support.apple.com” 的邮件。域名的微小变化是一个危险信号。  
  
- 当发件人地址存在细微的拼写错误或使用类似但非官方的域名时，很可能是钓鱼邮件。  
  
- 如果邮件以 “Dear User” 而不是你的实际姓名开头，这可能是钓鱼邮件。  
  
- 正规的公司通常会使用你的名字来称呼你。  
  
- 邮件声称 “你的账户将在 24 小时内被暂停，除非你验证你的信息”。这会制造一种紧迫感，诱使你不加思考地迅速行动。  
  
- 钓鱼邮件常通过这种方式迫使收件人在未仔细核实的情况下采取行动。  
  
- 如果你收到银行发来的要求你提供密码或 PIN 码的邮件，这很可能是钓鱼邮件。银行通常不会通过电子邮件索取此类敏感信息。  
  
- 任何涉及敏感个人信息请求的邮件都需要谨慎对待。  
  
  
  
16日，吉林舒兰灾后住房重建（修缮）工作已启动，舒兰市已统计需要重建的受灾户924户，预计10月20日前完成所有受灾户的住房安置工作。。  
  
**OSI Model VS TCP/IP Model**  
  
    OSI 模型分为 7 层，每层都有特定的功能。物理层规定了介质的物理特性，涉及电气连接和无线传输，硬件包括电线、光纤等。数据链路层负责节点间通信和数据传输，并附加物理地址，相关硬件是网络接口卡，协议有 ARP 和 Ethernet。网络层连接不同网络的主机，处理逻辑寻址，硬件是路由器，协议为 IP。传输层确保数据无丢失和进行流量控制，相关协议有 TCP 和 UDP。会话层控制主机间通信会话。表示层格式化数据，并能加密和解密数据，协议包括 SSL 和 TLS。应用层最接近用户，是用户与网络的接口，协议有 HTTP 和 FTP。  
  
  
    TCP/IP 模型分为 4 层。网络接口层结合了 OSI 模型物理层和数据链路层的功能，硬件包括网络接口卡、蓝牙、ISDN 等，协议有 Ethernet 和 L2TP。互联网层类似 OSI 模型的网络层，处理 IP 地址和路由，硬件为路由器，协议有 IP 和 ICMP。传输层与 OSI 模型的传输层功能相同，确保数据无丢失。应用层合并了 OSI 模型的会话层、表示层和应用层的功能，协议有 HTTP、FTP 和 SMTP 等。  
  
    
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7Wrf5Ndia4uic8dE9qx5zhVtO3fQwrC187DQAdFIma7PABpSHF1jZxvqlfib1ib7sx73tPZdp9byC5mA/640?wx_fmt=png&from=appmsg "")  
  
  
知识大陆：内部交流群：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH7Wrf5Ndia4uic8dE9qx5zhVtzKNmz2UstBzSt0uFGQjdzszTZLRz3icg9cCibDwN9gsWTQibq794qDYzg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
关注东方隐侠安全团队 一起打造网安江湖  
  
        
  东方隐侠安全团队，一支专业的网络安全团队，将持续为您分享红蓝对抗、病毒研究、安全运营、应急响应等网络安全知识，提供一流网络安全服务，敬请关注！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7zgibKsqKmX3H4AatvwPeXFsrHGpp0RsxLJpzgd0cyiaPH2HDnfv4GMdxf0lkGjAibiaBtFcLmnm2ZkA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
公众号｜东方隐侠安全团队  
  
  

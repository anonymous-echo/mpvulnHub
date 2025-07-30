#  微软与VMware零日漏洞紧急修复指南   
 FreeBuf   2025-03-15 18:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
首席信息安全官（CISO）需督促管理员尽快修复Windows和VMware产品中的零日漏洞  
  
，避免其被广泛利用。  
  
  
此外，Windows管理员还需留意一个已有公开利用证明的漏洞，威胁者很可能会对此发起攻击。  
  
  
同时，使用OpenSSH进行安全远程登录的应用程序在发现两处中间人（MiTM）攻击和服务拒绝漏洞后，也需进行审查和修复，其中一处漏洞已存在超过十年。  
  
  
这些漏洞是微软、VMware母公司博通、思科系统等公司在三月“补丁星期二”发布的关键安全更新之一。  
  
  
其中，MiTM漏洞（CVE-2025-26465）最早出现在2014年12月发布的OpenSSH 6.8p1中，并潜藏了十多年未被发现。如果启用了VerifyHostKeyDNS选项，该漏洞将影响OpenSSH客户端。目前，OpenSSH开发者已发布修复更新。  
  
  
**VMware关键漏洞需紧急修复**  
  
  
  
博通已发布紧急公告，警告客户VMware产品中存在三处正在被积极利用的零日漏洞。这些漏洞影响VMware ESX，包括VMware ESXi、vSphere、Workstation、Fusion、Cloud Foundation和Telco Cloud Platform。补丁管理提供商Action1指出：“这些漏洞如果被串联利用，可能导致虚拟机沙箱逃逸，使已控制访客操作系统的攻击者突破至虚拟机管理程序本身。”  
  
  
Action1总裁Mike Walters在电子邮件中表示，CISO应对VMware零日漏洞“高度关注”。这些漏洞被称为ESXicape。他解释道：“这些漏洞允许攻击者逃离隔离的虚拟机环境（VM沙箱），并在虚拟机管理程序级别（ESXi主机）执行任意代码。一旦虚拟机管理程序被攻破，攻击者将获得对服务器上所有虚拟机乃至整个VMware vSphere基础设施的完全控制权。”  
  
  
Walters还提到，勒索软件运营商和高级持续性威胁组织正积极瞄准这些漏洞，作为ESXicape活动的一部分。他指出：“据报道，全球有数万个易受攻击的系统，包括金融、医疗、政府、关键基础设施和电信领域的系统。这给企业环境带来了迫在眉睫的大规模风险。”  
  
  
为缓解这些威胁，Walters建议受影响VMware产品的CISO应超越标准补丁周期，紧急部署VMware发布的补丁，评估基于VMware的虚拟化基础设施是否受到攻击迹象，并加强对可疑活动的监控。  
  
  
**Windows系统漏洞修复迫在眉睫**  
  
  
  
Windows管理员需要修复六处零日漏洞、六处关键漏洞，以及一处已有公开利用证明的漏洞。Fortra安全研发副总监Tyler Reguly指出：“微软标记为‘检测到利用’的六处漏洞均已通过每月累积更新修复。这意味着只需一次更新即可同时修复所有这些问题。幸运的是，这些漏洞均无需补丁后的配置步骤。六处关键漏洞中有五处也是如此。”剩下的关键漏洞（CVE-2025-24057）和公开披露的漏洞（CVE-2025-26630）均需要Office更新。幸运的是，这大大限制了解决重大问题所需的补丁数量。  
  
  
**Windows零日漏洞包括：**  
- **Windows NTFS信息泄露漏洞（CVE-2025-24984）**  
，影响所有使用NFTS文件系统的系统。该漏洞源于NTFS日志文件中对敏感内核或堆内存数据的错误处理；  
  
- **Windows NTFS远程代码执行漏洞（CVE-2025-24993）**  
，这是一处基于堆的缓冲区溢出漏洞，由挂载特制虚拟硬盘（VHD）文件触发；  
  
- **Windows NTFS越界读取信息泄露漏洞（CVE-2025-24991）**  
，由解析NTFS元数据时的约束检查错误引起；  
  
- **Windows Fast FAT文件系统驱动远程代码执行漏洞（CVE-2025-24985）**  
，影响所有使用FAT/FAT32文件框架的Windows系统；  
  
- **Windows Win32内核子系统特权提升漏洞（CVE-2025-24983）**  
，这是一处新披露的零日漏洞，源于“释放后使用”问题。  
  
**网络基础设施厂商发布补丁**  
  
  
  
网络基础设施厂商思科系统和瞻博网络也发布了补丁。如思科修复了Webex for BroadWorks 45.2版中的一个漏洞，该漏洞可能导致未经授权的远程访问凭证；而瞻博网络则修复了Session Smart路由器（SSR）中的一处关键身份验证绕过漏洞。  
  
  
此外，Progress Software、Fortinet、Citrix和Ivanti也分别发布补丁以修复其产品中的关键漏洞。管理员需尽快部署这些更新，以降低潜在风险。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

#  勒索软件攻击中利用了关键的 Cleo 漏洞   
天唯科技  天唯信息安全   2024-12-26 01:56  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
  
根据 CISA 最新发现，确定 Cleo Harmony、VLTrader 和 LexiCom 文件传输软件中的一个关键安全漏洞正在被勒索软件攻击所利用。  
  
此漏洞编号为 CVE-2024-50623，影响 5.8.0.21 之前的所有版本，使未经身份验证的攻击者，能够在在线暴露的易受攻击的服务器上远程执行代码。  
  
Cleo 于 10 月份发布了安全更新来修复该问题，并警告所有客户“立即升级实例”以应对其他潜在的攻击媒介。目前尚未透露 CVE-2024-50623 是在野外的攻击目标。然而，CISA 将该安全漏洞添加到其已知被利用漏洞的目录中，并将其标记为用于勒索软件活动。  
  
在添加到 KEV 目录后，美国联邦机构必须按照 2021 年 11 月发布的具有约束力的操作指令 (BOD 22-01) 的要求，在 1 月 3 日之前提出申请，确保其网络免受攻击。  
  
虽然网络安全机构没有提供有关针对易受 CVE-2024-50623 漏洞，利用的 Cleo 服务器的勒索软件活动的任何其他信息，但这些攻击与之前利用 MOVEit Transfer、GoAnywhere MFT 中的零日漏洞的 Clop 数据盗窃攻击惊人地相似，以及近年来的Accellion FTA。  
  
一些人还认为该漏洞被 Termite 勒索软件操作所利用。然而，这个链接只是因为 Blue Yonder 拥有暴露的 Cleo 软件服务器，并且在勒索软件团伙声称的网络攻击中遭到破坏。  
  
**Cleo 零日漏洞也被积极利用**  
  
  
正如 Huntress 安全研究人员首次发现的那样，经过全面修补的 Cleo 服务器仍然受到威胁，很可能使用 CVE-2024-50623 绕过（尚未收到 CVE ID），使攻击者能够导入和执行任意 PowerShell 或 bash 命令通过利用默认的自动运行文件夹设置。  
  
Cleo 现已发布补丁来修复这个被积极利用的零日漏洞，并敦促客户尽快升级到版本 5.8.0.24，以保护暴露在互联网上的服务器免受破坏尝试。应用补丁后，系统会记录启动时发现的与此漏洞相关的任何文件的错误，并删除这些文件。  
  
建议无法立即升级的管理员通过从系统选项中清除 Autorun 目录来禁用自动运行功能，以减少攻击面。正如 Rapid7 在调查零日攻击时发现的那样，威胁者利用零日攻击来删除 Java Archive (JAR) 有效负载 [VirusTotal]，该负载是更大的基于 Java 的后利用框架的一部分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibibmE7O1f1vT47LaO8NURG5fdfASXdpYd08ZvhO5cAw7hzCCX5BA3lKoAib1qIibTuDCibtyG51xqo1Q/640?wx_fmt=png&from=appmsg "")  
  
Cleo 攻击流程  
   
  
Huntress 也分析了该恶意软件并将其命名为 Malichus，目前只发现它部署在 Windows 设备上。  
  
根据另一家调查正在进行攻击的网络安全公司 Binary Defense ARC Labs 的说法，恶意软件操作者可以使用 Malichus 进行文件传输、命令执行和网络通信。  
  
到目前为止，Huntress 已发现多家公司的 Cleo 服务器遭到入侵，并表示可能还有其他潜在受害者。Sophos 的 MDR 和实验室团队还在 50 多个 Cleo 主机上发现了妥协迹象。截止到目前，Cleo 发言人确认 CVE-2024-50623 漏洞已被作为零日攻击利用。  
  
参考及来源：  
  
https://www.bleepingcomputer.com/news/security/cisa-confirms-critical-cleo-bug-exploitation-in-ransomware-attacks/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
  
天唯科技专注于大型组织信息安全领域及IT基础设施解决方案的规划、建设与持续运维服务。帮助客户提高IT基础设施及信息安全管控水平和安全运营能力，使客户在激烈的市场环境中保持竞争力。  
  
我们一直秉承“精兵强将，专业专注”的发展理念。  
先后在江门、深圳成立分公司，在武汉、长沙成立办事处以及成立广州的服务支撑中心。公司已获得高新技术企业认证、已通过IS09001、IS027001、CCRC信息安全集成服务、CCRC信息安全风险评估、CCRC信息安全应急处理等认证。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNRytkPMNOKYRW452LxR5Ez5Wee8X6KlbhoUMt9XyhhbRxHafKcCLWJic3ib0umJiaH3fl6sOx8KMBiaQ/640?wx_fmt=png "盾牌单图.png")  
  
**END**  
  
  
  
**往期推荐:**  
  
  
  
  
  
[《数据中心业务连续性等级评价准则》（GB/T 42581-2023）将于今年12月1日起正式实施。](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247491478&idx=3&sn=709db0495fa0f68ff39c48bd3377ee60&chksm=c25ed336f5295a20d86ee1fed3a27e5fe68e154c4c7e46792e721a10b4fcc2b90b04239b1e37&scene=21#wechat_redirect)  
  
  
  
[《数据论文出版元数据》（GB/T 42813-2023）](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247491447&idx=2&sn=f3358492df1a38b8a1a9df86f30c973a&chksm=c25ed3d7f5295ac1562015a559ff6b5cc75e4d4de577ce2794970228772957a40ed176b95d2d&scene=21#wechat_redirect)  
  
  
  
[《工业互联网平台 开放应用编程接口功能要求》（GB/T 42569-2023）将于今年12月1日起正式实施。](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247491405&idx=2&sn=614ff1165b86237b146788699decfe8e&chksm=c25ed3edf5295afb831aa482d7fd3bca49fc9d14c7555d5b60ebf3760335a9e5e4cdd4ab9ddf&scene=21#wechat_redirect)  
  
  
  
**征文通道:**  
  
  
  
  
  
[发钱！征文！让真诚的分享更有价值](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247490310&idx=1&sn=db4b524d1d9f5aabb4af2184dd831de3&chksm=c25ed7a6f5295eb053d3f90e2dc8cd22a2d8ce1a62561ffa62966340ee563734cd4fd32045f3&scene=21#wechat_redirect)  
  
  

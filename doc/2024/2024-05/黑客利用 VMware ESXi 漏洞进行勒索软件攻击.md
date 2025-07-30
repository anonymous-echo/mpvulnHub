#  黑客利用 VMware ESXi 漏洞进行勒索软件攻击   
 关键基础设施安全应急响应中心   2024-05-27 15:34  
  
针对 VMware ESXi 基础架构的勒索软件攻击无论部署何种文件加密恶意软件，都遵循一种既定模式。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibEhaJRItpTlghAd8LH0u4Wqluj4AKYsr0kLvPsHtujzdGamcosic3XdhRfst4DJIztT02DyBRrJVw/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
网络安全公司Sygnia在与《黑客新闻》共享的一份报告中提到：虚拟化平台是组织IT基础设施的核心组成部分，但它们往往存在固有的错误配置和漏洞，这使它们成为威胁行为者有利可图和高度有效的滥用目标。  
  
这家以色列公司通过对LockBit、HelloKitty、BlackMatter、RedAlert (N13V)、Scattered Spider、Akira、Cactus、BlackCat和Cheerscrypt等各种勒索软件家族的事件响应工作发现，对虚拟化环境的攻击遵循类似的行动顺序。  
  
这包括以下步骤：  
- 通过网络钓鱼攻击、恶意文件下载和利用面向互联网资产的已知漏洞获取初始访问权限  
  
- 利用暴力攻击或其他方法提升权限，获取 ESXi 主机或 vCenter 的凭证  
  
- 验证他们对虚拟化基础架构的访问权限并部署勒索软件  
  
- 删除或加密备份系统，或在某些情况下更改密码，使恢复工作复杂化  
  
- 将数据渗出到外部位置，如 Mega.io、Dropbox 或他们自己的托管服务  
  
- 启动勒索软件的执行以加密 ESXi 文件系统的「/vmfs/volumes」文件夹  
  
- 将勒索软件传播到非虚拟化服务器和工作站，以扩大攻击范围  
  
为降低此类威胁带来的风险，建议企业确保实施充分的监控和日志记录，创建强大的备份机制，执行强有力的身份验证措施，加固环境，并实施网络限制以防止横向移动。  
  
网络安全公司 Rapid7 警告称，自 2024 年 3 月初以来，该公司一直在利用常用搜索引擎上的恶意广告，通过错别字域名分发 WinSCP 和 PuTTY 的木马安装程序，并最终安装勒索软件。  
  
这些伪装安装程序充当了投放 Sliver 后期漏洞工具包的渠道，该工具包随后被用于投放更多有效载荷，包括用于部署勒索软件的 Cobalt Strike Beacon。  
  
该活动与之前的 BlackCat 勒索软件攻击在战术上有共同之处，后者使用恶意广告作为初始访问载体，是交付氮气恶意软件的重复性活动的一部分。  
  
安全研究员Tyler McGraw说：该活动一定程度上影响了 IT 团队的成员，他们最有可能在寻找合法版本的同时下载木马文件。  
  
**勒索软件攻击**  
  
恶意软件一旦被成功执行可能会为威胁行为者提供更多便利，让其通过模糊后续管理操作的意图来阻碍分析。  
  
此次攻击也是继Beast、MorLock、Synapse和Trinity等新勒索软件家族出现后的又一次最新事件披露，其中MorLock家族广泛针对俄罗斯公司，并在不先外泄文件的情况下对文件进行加密。  
  
Group-IB在俄罗斯的分支机构F.A.C.C.T.表示：为了恢复数据访问，MorLock攻击者要求支付相当高的赎金，赎金数额可达数千万或数亿卢布。  
  
根据 NCC 集团共享的数据，2024 年 4 月全球勒索软件攻击比上月下降了 15%，从 421 起降至 356 起。  
  
值得注意的是，2024 年 4 月也标志着 LockBit 结束了长达 8 个月的受害者最多的威胁行为体统治，这也说明了其在今年早些时候执法部门大举打击后的艰难生存状况。  
  
然而，令人惊讶的是，LockBit 3.0 并不是本月最突出的威胁组织，其观察到的攻击次数还不到 3 月份的一半。反倒 Play 成为了最活跃的威胁组织，紧随其后的是 Hunters。  
  
除了勒索软件领域的动荡之外，网络犯罪分子还在宣传隐藏的虚拟网络计算（hVNC）和远程访问服务，如 Pandora 和 TMChecker，这些服务可被用于数据外渗、部署额外的恶意软件和促进勒索软件攻击。  
  
Resecurity表示：多个初始访问代理（IAB）和勒索软件操作员使用 TMChecker 来检查可用的受损数据，以确定是否存在企业VPN和电子邮件账户的有效凭证。  
  
因此，TMChecker 的同时崛起意义重大，因为它大大降低了那些希望获得高影响力企业访问权限的威胁行为者的进入成本门槛，这些访问权限既可以用于初次利用，也可以在二级市场上出售给其他对手。  
  
**参考资料：**  
  
https://thehackernews.com/2024/05/ransomware-attacks-exploit-vmware-esxi.html  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  

#  【安全圈】黑客利用 VMware ESXi 漏洞进行勒索软件攻击   
 安全圈   2024-05-24 19:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
勒索软件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljuaFSo6043c6GeS8s1vLmO4iaRdrsJ2ibvmZG8JNTIOuTQsbytiaicEMTnKicpXziccgaFdpQMUZv04hrQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
针对 VMware ESXi 基础架构的勒索软件攻击无论部署何种文件加密恶意软件，都遵循一种既定模式。  
  
网络安全公司Sygnia在与《黑客新闻》共享的一份报告中提到：虚拟化平台是组织IT基础设施的核心组成部分，但它们往往存在固有的错误配置和漏洞，这使它们成为威胁行为者有利可图和高度有效的滥用目标。  
  
这家以色列公司通过对LockBit、HelloKitty、BlackMatter、RedAlert (N13V)、Scattered Spider、Akira、Cactus、BlackCat和Cheerscrypt等各种勒索软件家族的事件响应工作发现，对虚拟化环境的攻击遵循类似的行动顺序。  
  
这包括以下步骤：  
- 通过网络钓鱼攻击、恶意文件下载和利用面向互联网资产的已知漏洞获取初始访问权限  
  
- 利用暴力攻击或其他方法提升权限，获取 ESXi 主机或 vCenter 的凭证  
  
- 验证他们对虚拟化基础架构的访问权限并部署勒索软件  
  
- 删除或加密备份系统，或在某些情况下更改密码，使恢复工作复杂化  
  
- 将数据渗出到外部位置，如 Mega.io、Dropbox 或他们自己的托管服务  
  
- 启动勒索软件的执行以加密 ESXi 文件系统的"/vmfs/volumes "文件夹  
  
- 将勒索软件传播到非虚拟化服务器和工作站，以扩大攻击范围  
  
为降低此类威胁带来的风险，建议企业确保实施充分的监控和日志记录，创建强大的备份机制，执行强有力的身份验证措施，加固环境，并实施网络限制以防止横向移动。  
  
网络安全公司 Rapid7 警告称，自 2024 年 3 月初以来，该公司一直在利用常用搜索引擎上的恶意广告，通过错别字域名分发 WinSCP 和 PuTTY 的木马安装程序，并最终安装勒索软件。  
  
这些伪装安装程序充当了投放 Sliver 后期漏洞工具包的渠道，该工具包随后被用于投放更多有效载荷，包括用于部署勒索软件的 Cobalt Strike Beacon。  
  
该活动与之前的 BlackCat 勒索软件攻击在战术上有共同之处，后者使用恶意广告作为初始访问载体，是交付氮气恶意软件的重复性活动的一部分。  
  
安全研究员Tyler McGraw说：该活动一定程度上影响了 IT 团队的成员，他们最有可能在寻找合法版本的同时下载木马文件。  
## 勒索软件攻击  
  
恶意软件一旦被成功执行可能会为威胁行为者提供更多便利，让其通过模糊后续管理操作的意图来阻碍分析。  
  
此次攻击也是继Beast、MorLock、Synapse和Trinity等新勒索软件家族出现后的又一次最新事件披露，其中MorLock家族广泛针对俄罗斯公司，并在不先外泄文件的情况下对文件进行加密。  
  
Group-IB在俄罗斯的分支机构F.A.C.C.T.表示：为了恢复数据访问，MorLock攻击者要求支付相当高的赎金，赎金数额可达数千万或数亿卢布。  
  
根据 NCC 集团共享的数据，2024 年 4 月全球勒索软件攻击比上月下降了 15%，从 421 起降至 356 起。  
  
值得注意的是，2024 年 4 月也标志着 LockBit 结束了长达 8 个月的受害者最多的威胁行为体统治，这也说明了其在今年早些时候执法部门大举打击后的艰难生存状况。  
  
然而，令人惊讶的是，LockBit 3.0 并不是本月最突出的威胁组织，其观察到的攻击次数还不到 3 月份的一半。反倒Play 成为了最活跃的威胁组织，紧随其后的是 Hunters。  
  
除了勒索软件领域的动荡之外，网络犯罪分子还在宣传隐藏的虚拟网络计算（hVNC）和远程访问服务，如 Pandora 和 TMChecker，这些服务可被用于数据外渗、部署额外的恶意软件和促进勒索软件攻击。  
  
Resecurity表示：多个初始访问代理（IAB）和勒索软件操作员使用 TMChecker 来检查可用的受损数据，以确定是否存在企业VPN和电子邮件账户的有效凭证。  
  
因此，TMChecker 的同时崛起意义重大，因为它大大降低了那些希望获得高影响力企业访问权限的威胁行为者的进入成本门槛，这些访问权限既可以用于初次利用，也可以在二级市场上出售给其他对手。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljuaFSo6043c6GeS8s1vLmONHhdc0aMVpFib9CEBLzTKe6IgprpMN6SzUr1OwCLFHLhy2HCDZIHyHA/640?wx_fmt=jpeg "")  
[【安全圈】ChatGPT 严重宕机，结果被造谣 “遭遇俄罗斯黑客入侵”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060477&idx=1&sn=34c7216f8dead66a1ca96d25900cf4c5&chksm=f36e177dc4199e6b5540c6b7611830c28d1de12d3e61936a41b9454a2ebdfbb38ed548dcb18f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtafx9Y8EsvLPGEWGUOEEPPa7OyIruF1tYNUsO1ryrLOMgvt4dqddtxbjsw90SWwf45IiafpPxtfg/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】隐私末日？微软 Windows 11“回忆功能”引发恐慌](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060477&idx=2&sn=bb3234ba8766049d5a06324b97e11c8c&chksm=f36e177dc4199e6b292bd10f43ff45285906f8b105736d474a5f8ac11a1c98eaba4ba248ada9&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljuaFSo6043c6GeS8s1vLmONxKZYtPFomSap9lEXJuwI4M8ofjZ2JvYmPTrcibM2JeJ42v5RPFX74A/640?wx_fmt=jpeg "")  
[【安全圈】曾遭国际刑警“联合围剿”金融木马 Grandoreiro 死灰复燃，瞄准 1500 多家银行发动攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060477&idx=3&sn=d0d00b8630f623729b430c30cb8cf630&chksm=f36e177dc4199e6b060c114175c3e5a051cac3d596496f927476615ac8065a7e77a1fa4870d7&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtafx9Y8EsvLPGEWGUOEEPj6OFWoibibzfT9xjrvRibZhju3rVpyASGClUNNOZCFOSRyhUicgMeuJaPQ/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】英特尔 AI 模型压缩器现满分漏洞，可导致任意代码执行](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060477&idx=4&sn=9bce7bfcfe76a7430ab4f38562be2fbe&chksm=f36e177dc4199e6ba3ce3ee51b0965ab7b1c8400884943742b3367baa278b344954cba189a66&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  

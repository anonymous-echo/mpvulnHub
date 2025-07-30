#  CVSS漏洞评分系统曝出严重缺陷   
 GoUpSec   2024-12-17 02:19  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvZodLVicdcKQ70ygXBhUdvSpt0JHwicrqZDcNUeG9UUDz7S6sOId7qLu5iaYS9xsoJOeQ23URFoNW8mw/640?wx_fmt=png&from=appmsg "")  
  
  
随着漏洞披露量的持续增长和攻击复杂性的提升，准确的风险评估对于企业防御和漏洞修复至关重要。在近日举行的Black Hat欧洲大会上，金融巨头摩根大通的网络安全专家发出警告：当前广泛使用的漏洞严重性评估系统——通用漏洞评分系统（CVSS）存在重大缺陷，可能导致安全团队对漏洞风险误判，从而延长漏洞的暴露时间，增加组织面临的风险。  
  
  
  
**CVSS漏洞评分的误导性风险**  
  
  
  
CVSS是一种行业标准方法，通过量化指标评估软件和硬件漏洞的严重性。然而，摩根大通的专家在演讲中指出，CVSS在现实风险的反映上存在多重问题，导致企业在修复优先级的排序上可能做出错误决策。这些问题具体如下：  
  
  
**一、缺乏情境因素的考量**  
  
  
CVSS评分未充分考虑漏洞所处的环境。例如，一个漏洞是否已被“野外利用”（actively exploited），或其对具体组织的风险优先级，往往被忽略。摩根大通指出，CVSS对保密性、完整性和可用性这三个维度给予了等权处理，却未能适应各个组织的独特需求，也未能充分体现漏洞的真实影响。  
  
  
**二、10%的漏洞被低估**  
  
  
2023年，全球平均每天披露80个漏洞，同比增幅约20%。其中，约18%的漏洞被评为严重（CVSS评分9或以上）。然而，摩根大通的分析表明，大约10%的漏洞可能被低估，未能体现其潜在的破坏性。  
  
  
研究人员提到，许多被低估的漏洞可能带来严重的安全后果。例如，CVE-2020-8187是Citrix NetScaler中一个分布式拒绝服务（DDoS）漏洞，其CVSS评分仅为7.5。然而，这一漏洞在COVID-19疫情期间暴露时，有可能导致企业业务全面瘫痪。  
  
  
类似地，Zoom的CVE-2019-13450漏洞（允许未经用户同意打开摄像头）被评定为中等风险。然而，该漏洞的实际影响包括隐私侵犯、安全风险，以及法律与声誉后果，远超这一评分所反映的风险级别。  
  
  
**三、依赖关系与权限的忽视**  
  
  
CVSS未充分考虑漏洞的依赖关系及特定配置要求。某些漏洞需要特定的硬件或软件配置才能被利用，而访问控制或用户权限的设定会显著影响攻击者的利用能力。例如，攻击者对系统的实际影响可能因权限设置而大幅变化，但这些因素在CVSS评分中的反映极为有限。  
  
  
  
**CVSS 4.0：改进与不足**  
  
  
  
CVSS 4.0框架即将推出，新增了影响指标、时间维度的优化，以及辅助评分指标，以期提高评估的准确性。然而，摩根大通专家指出，4.0版本仍未解决几个核心问题：  
  
- 隐私问题的忽视：CVSS评分中的“保密性”指标过于通用，无法准确体现漏洞对隐私的具体影响。  
  
- 高级持续性威胁（APT）的考量不足：CVSS评分未能充分体现漏洞与APT攻击之间的关联性。  
  
- 依赖关系与可利用性权重不足：攻击者对漏洞的利用能力与环境配置的关联未被适当体现。  
  
- 摩根大通提出改进框架  
  
为了弥补CVSS现有的不足，摩根大通开发了一种新的漏洞评估框架。该框架纳入了以下改进要素：  
  
- 权重分配：增加对APT关联性和漏洞利用难度的权重考量。  
  
- 依赖分析：将漏洞的依赖性和环境条件纳入风险评估。  
  
- 隐私影响评估：增强对数据泄露和隐私风险的重视。  
  
这一概念框架已向网络安全社区公开，摩根大通呼吁其他安全组织共同参与完善，以推动行业标准的改进。  
  
  
  
**新方法并非万灵药**  
  
  
  
摩根大通首席安全架构师Syed Islam在接受采访时表示，网络安全行业亟需一个更科学、更全面的漏洞评估体系，以应对复杂的威胁格局。但是，只有具备一定安全成熟度的组织才能充分受益于这种新的评估方法。例如，这些组织需要建立全面的技术和应用清单，以明确其业务依赖的核心系统和资产。  
  
  
对于安全能力较弱的组织，Islam建议逐步提高其安全治理水平，从完善资产管理和漏洞响应流程开始。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/INYsicz2qhvZRDUnojiaba5EGXQ7vEkEX8iar6wfVEW8pJj4v4XBgG48Lt1Ga5seakLRcfZJdGmq4yUsZXdLh2ZfA/640?wx_fmt=other "")  
  
  
  
END  
  
  
  
相关阅读  
  
  
  
[MITRE公布最危险软件漏洞TOP25榜单](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501504&idx=2&sn=741da5d8dcc2e08936f21c432a3b1f0e&scene=21#wechat_redirect)  
  
  
[立即修复！五眼联盟公布最常被利用的15个漏洞名单](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501433&idx=2&sn=26dab7b46c410a8e7d56e6b78f742e15&scene=21#wechat_redirect)  
  
  
[25家跨国企业数据泄露，MOVEit漏洞引发重大安全危机](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501422&idx=1&sn=312c9acb659009fdafc7e2bd665d45ad&scene=21#wechat_redirect)  
  
  
[重大突破！AI首次发现内存安全漏洞](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501362&idx=1&sn=11733a657772038607843a4e8ce5c2be&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/INYsicz2qhvbgcN4QY36lK2wjCavZiadQThpmM11FR4xkwyVG7K24lkpoLRcFHuZ7gAHgZEsr6Mia7BmKuwDJqX4g/640?wx_fmt=jpeg "")  
  
  

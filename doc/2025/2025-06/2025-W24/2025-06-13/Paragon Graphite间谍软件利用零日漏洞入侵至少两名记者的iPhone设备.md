#  Paragon Graphite间谍软件利用零日漏洞入侵至少两名记者的iPhone设备  
鹏鹏同学  黑猫安全   2025-06-13 01:37  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9dic6O6aPVzo6mXgCsSjibibTPZwVx2VPgrFWyic58G0ytxVPnYVn86vV1BibWV4eLGzvO1SfWjxzzkqw/640?wx_fmt=png&from=appmsg "")  
  
公民实验室确认，欧洲至少两名记者的iPhone设备在保持系统最新更新的情况下，仍遭Paragon公司Graphite间谍软件入侵。调查人员发现，两部手机与同一间谍软件服务器通信的法医证据。苹果公司于今年早些时候悄然向受害者发出警报，这标志着Paragon监控工具首次被证实用于实际攻击。  
  
2025年4月29日，苹果向特定iOS用户发出间谍软件攻击警报。法医分析确认包括Ciro Pellegrino在内的两名记者感染了Paragon Graphite间谍软件，两起事件均关联至同一攻击者。苹果已在iOS 18.3.1版本中修补了此次攻击使用的零点击漏洞（现编号为CVE-2025-43200）。  
  
2025年4月，一位要求匿名的欧洲记者收到苹果警报后寻求技术协助。设备取证显示，该设备在2025年1月至2月运行iOS 18.2.1系统期间，通过iMessage零点击攻击感染了Paragon Graphite间谍软件。  
  
公民实验室在报告中指出："我们的法医分析证实，记者设备于2025年1月至2月初运行iOS 18.2.1系统期间遭Paragon Graphite间谍软件入侵。设备日志显示其曾向某服务器发起系列请求，该服务器特征与我们已公开的指纹P1高度吻合，因此我们以极高置信度判定为Graphite所为。"  
  
研究人员在日志中发现设备与已知Paragon服务器的连接证据，该连接指纹特征匹配。苹果随后在iOS 18.3.1版本中修复了被利用的漏洞（CVE-2025-43200）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9dic6O6aPVzo6mXgCsSjibibT06WDnicpoEl4UibuibuzsmzlibpRA6ic77viaa4XMuiazsnfhWh3fiajd9zQTA/640?wx_fmt=png&from=appmsg "")  
  
意大利记者西罗·佩莱格里诺（Ciro Pellegrino）于2025年4月29日收到苹果公司发出的间谍软件攻击警报。法医分析证实其iPhone同样成为Paragon Graphite间谍软件的攻击目标。日志显示攻击者使用了与先前案例相同的"ATTACKER1"iMessage账户，表明两起事件均出自同一Graphite运营商之手。这一发现暗示某位间谍软件客户正在实施协同攻击。目前针对Paragon工具及运营的调查仍在进行中。  
  
佩莱格里诺供职于意大利媒体Fanpage.it，其同事弗朗切斯科·坎切拉托（Francesco Cancellato）早在2025年1月就收到WhatsApp通知，称其成为Paragon Graphite间谍软件的监控目标。公民实验室对坎切拉托安卓设备的分析虽未发现感染证据，但由于安卓系统日志功能有限，仍不能排除入侵可能。同一新闻机构两名记者相继成为监控目标，引发外界对该媒体可能遭遇系统性渗透的担忧。  
  
2025年6月5日，意大利情报监督委员会（COPASIR）证实政府曾使用Paragon Graphite间谍软件监控卢卡·卡萨里尼（Luca Casarini）和朱塞佩·卡恰博士（Dr. Beppe Caccia），但无法确认记者坎切拉托案的幕后主使。Paragon随后声称愿协助调查，但意大利以国家安全为由拒绝。意方同时驳斥了Paragon关于合约终止的单方面说法。截至目前，Paragon未就公民实验室最新发现作出回应。  
  
公民实验室报告指出："意大利安全情报部（DIS）当日回应称，出于向Paragon暴露监控活动的国家安全顾虑，已拒绝其协助请求。当局表示若允许Paragon介入调查，将损害意大利安全部门在国际同行中的声誉，并否认合约终止系单方面行为。"报告补充称："COPASIR委员会同日声明对Paragon的协助提议不知情，并表示愿意解密Paragon向委员会提供的证词。"  
  
本周初，Paragon指控意大利政府拒绝其协助调查记者监控事件的提议。该公司声称这一矛盾直接导致其决定终止在意业务。Paragon表示曾提出验证工具是否遭滥用的方案，但遭当局拒绝。这标志着间谍软件公司首次因涉嫌滥用问题公开与客户割席。Paragon向科技媒体TechCrunch发表的声明称："本公司向意大利政府及议会提供了验证系统是否违反意大利法律及合约条款的方案。由于当局拒绝采纳，Paragon决定终止在意大利的合同。"该公司虽确认声明内容属实，但拒绝进一步置评。  
  
  

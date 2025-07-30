#  谷歌修复了今年年初以来第二个被积极利用的Chrome零日漏洞   
鹏鹏同学  黑猫安全   2025-06-04 01:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicB40rzNAubpAUotq7qlL9YabZMImeibz5eEiaDXm52opksS6CHiamoxwVibwMehmRPDnYBDoniaP70t7w/640?wx_fmt=png&from=appmsg "")  
  
谷歌发布带外更新修复Chrome浏览器三处漏洞，其中编号CVE-2025-5419的漏洞已被黑客在野利用。该漏洞存在于旧版Chrome的V8 JavaScript引擎中，攻击者可通过特制HTML页面触发堆损坏。谷歌威胁分析小组研究员Clément Lecigne和Benoît Sevens于2025年5月27日报告该漏洞，次日谷歌即向全平台Chrome稳定版推送配置更新（Windows/Mac版本号137.0.7151.68/.69，Linux版本号137.0.7151.68）。公告称"谷歌已确认存在针对CVE-2025-5419的在野利用"，但未披露攻击技术细节。  
  
此次更新还修复了Blink渲染引擎的中危级释放后重用漏洞（CVE-2025-5068），该漏洞由研究员Walkman于2025年4月7日报告。  
  
2025年3月，谷歌曾紧急修复今年首个被在野利用的Chrome零日漏洞（CVE-2025-2783）。该高危漏洞涉及Windows版Chrome浏览器Mojo组件在特定场景下的句柄错误问题，由卡巴斯基研究员Boris Larin和Igor Kuznetsov于3月20日上报。据卡巴斯基披露，该漏洞已被用于针对俄罗斯机构的攻击。Mojo作为Chromium浏览器的进程间通信库，其漏洞可能引发沙箱逃逸和权限提升风险，但谷歌未透露相关攻击活动细节及幕后黑手信息。  
  
  

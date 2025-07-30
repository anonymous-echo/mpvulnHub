#  谷歌修复了可能导致账户完全被劫持的Chrome漏洞   
鹏鹏同学  黑猫安全   2025-05-19 01:40  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceib1zAbBLBLcJqMmT3DbWqJ9hI2l5c6361kic1o7CerlqibvdUiagx34VzlvnjVVty55kabo6bdL0NSjw/640?wx_fmt=png&from=appmsg "")  
  
谷歌发布紧急安全更新修复可导致账户完全被劫持的Chrome漏洞（编号CVE-2025-4664）。该漏洞由安全研究员Vsevolod Kokorin（@slonser_）发现，源于Chrome 136.0.7103.113之前版本中Loader组件的策略执行缺陷。攻击者可通过特制HTML页面触发漏洞，实现跨源数据泄露。  
  
查询参数可能包含敏感数据——例如在OAuth流程中，这可能导致账户接管。开发者很少考虑通过第三方资源图片窃取查询参数的可能性，使得这种攻击手法有时出奇有效。（2025年5月5日@slonser_推文）  
  
谷歌警告该高危漏洞的公开利用代码已出现。"谷歌已获悉CVE-2025-4664漏洞的野外利用报告"，官方公告称。目前Windows/Linux版Chrome 136.0.7103.113和macOS版136.0.7103.114已修复该漏洞。  
  
2025年3月，谷歌曾紧急修复Windows版Chrome另一个高危漏洞（CVE-2025-2783），该漏洞被用于针对俄罗斯机构的攻击。漏洞源于Windows系统Mojo组件在特定情况下提供错误句柄，由卡巴斯基研究员Boris Larin（@oct0xor）和Igor Kuznetsov（@2igosha）于2025年3月20日报告。  
  
Mojo是Chromium浏览器的进程间通信库，负责管理沙箱进程的安全通信。虽然它在Windows上增强了Chrome安全性，但历史漏洞曾导致沙箱逃逸和权限提升。谷歌未透露攻击细节或幕后黑手身份，仅确认"野外存在CVE-2025-2783漏洞利用"，并通过Windows版134.0.6998.177/.178更新进行修复。  
  
  

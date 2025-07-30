#  英国域名注册局 Nominet 确认遭 Ivanti VPN零日漏洞攻击   
Rhinoer  犀牛安全   2025-02-09 09:44  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmHhbBXfQiamrop040eReAczjb7KTzT3ibrv0KSEr4vSK13NYibhwuNxMN7tjyouIQBz8ViaibCp6AoI0w/640?wx_fmt=png&from=appmsg "")  
  
Nominet 是 .UK 官方域名注册机构，也是最大的国家代码注册机构之一，该公司已确认其网络两周前遭 Ivanti VPN 零日漏洞攻击。  
  
该公司管理和运营超过 1100 万个 .uk、.co.uk 和 .gov .uk 域名以及其他顶级域名，包括 .cymru 和 .wales。  
  
它还代表英国国家网络安全中心 (NCSC) 运营英国的保护域名服务 (PDNS)，直至 2024 年 9 月，保护超过 1,200 个组织和超过 700 万最终用户。  
  
Nominet 仍在调查该事件，但尚未发现其系统上部署任何后门的证据，正如ISPreview首次报道的那样。  
  
自从检测到其网络上的可疑活动以来，该公司已向包括 NCSC 在内的相关部门报告了此次攻击，并限制通过 VPN 连接对其系统的访问。  
  
Nominet 在与 BleepingComputer 分享的客户通知中表示：“入口点是通过 Ivanti 提供的第三方 VPN 软件，使我们的员工能够远程访问系统。”  
  
不过，目前我们没有数据泄露或泄漏的证据。我们已经运行了限制访问协议和防火墙来保护我们的注册系统。域名注册和管理系统继续正常运行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmHhbBXfQiamrop040eReAczjGrlqHEvTBo6xY4kX0AGuMw8mg5CbgnI1LQHic7YE5QsR96JJv8s3NA/640?wx_fmt=png&from=appmsg "")  
  
袭击疑似与某国黑客有关  
  
虽然该公司没有分享有关攻击中使用的 VPN 零日漏洞的更多信息，但 Ivanti 上周表示，黑客一直在利用关键的 Ivanti Connect Secure 零日漏洞（追踪为 CVE-2025-0282）来入侵有限数量客户的设备。  
  
据网络安全公司 Mandiant（Google Cloud 的一部分）称，攻击者从 12 月中旬开始利用此漏洞，使用自定义 Spawn 恶意软件工具包（与一个被追踪为 UNC5337 的疑似与某国有关的间谍组织有关）。  
  
他们还在受感染的 VPN 设备上部署了新的 Dryhook 和 Phasejam 恶意软件（目前与威胁组织无关）。  
  
Macnica 研究员 Yutaka Sejiyama 告诉 BleepingComputer，当 Ivanti 于周三发布针对零日漏洞的补丁时，超过 3,600 台 ICS 设备被暴露在网上。  
  
2024 年10 月份，Ivanti 发布了更多安全更新，以修复其他三个同样在攻击中被积极利用的云服务设备 (CSA) 零日漏洞。  
  
  
信息来源：BleepingComputer  
  

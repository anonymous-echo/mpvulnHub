#  超过2000台Palo Alto Networks防火墙遭到黑客攻击，攻击者利用了最近才修补的零日漏洞   
鹏鹏同学  黑猫安全   2024-11-25 03:36  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceibDhJC77BUpvs03VRK19llfNuWYmwpicibKVUNveDicfHRn7dswONGV9ULJHLCrGQ3SpHibcMyX7htpOw/640?wx_fmt=png&from=appmsg "")  
  
数千台Palo Alto Networks防火墙据报遭到黑客攻击，攻击者利用了最近才修补的零日漏洞（CVE-2024-0012和CVE-2024-9474）在PAN-OS中。  
  
CVE-2024-0012是Palo Alto Networks PAN-OS中的漏洞，允许未经身份验证的攻击者拥有网络访问权来绕过身份验证并获取管理员权限。这项访问权限使管理员可以执行管理操作、更改配置或利用其他漏洞，如CVE-2024-9474。  
  
该问题影响PAN-OS版本10.2、11.0、11.1和11.2，但不影响Cloud NGFW或Prisma Access。CVE-2024-9474是Palo Alto Networks PAN-OS软件中的特权提升漏洞，允许具有管理web界面访问权限的PAN-OS管理员执行以root身份执行的操作。这周，美国国家网络安全局（CISA）将这两个漏洞添加到其已知漏洞目录（KEV）。  
  
在11月中旬，Palo Alto Networks确认观察到某些有限的防火墙管理界面受到未经身份验证的远程命令执行漏洞的攻击。Palo Alto说，这个零日漏洞已经被用来在受感染设备上部署web壳，从而授予持久的远程访问权限。 “Palo Alto Networks和Unit 42正在跟踪与CVE-2024-0012和CVE-2024-9474相关的有限的利用活动，并与外部研究人员、合作伙伴和客户合作，分享信息透明和快速。” Palo Alto发布的报告中读到。  
  
该报告最初观察到来自以下IP地址的恶意活动：  
- 136.144.17.*   
  
- 173.239.218.251   
  
- 216.73.162.*   
  
该特别警告指出，这些IP地址可能与VPN服务相关，因此也可能与-legitimate user activity相关。 “Palo Alto Networks继续跟踪随着第三方研究人员于2024年11月19日开始公开技术见解和艺术ifacts的公开活动的威胁活动。目前，Unit 42根据moderate to high confidence评估认为，功能 exploit chaining CVE-2024-0012和CVE-2024-9474现在是公开可用的，这将使广泛的威胁活动变得可能。”  
  
报告继续说。 “Unit 42还观察到两个手动和自动扫描活动 aligning with the timeline of third-party artifacts becoming widely available.” 该调查仍在进行中，Palo Alto Networks更新了Indicators of Compromise的列表。Shadowserver研究员追踪了受感染的Palo Alto Networks防火墙数量，报告约有2000台防火墙被黑客攻击，这些攻击是CVE-2024-0012/CVE-2024-9474活动的一部分。受感染的设备大多数来自美国（554）和印度（461）。  
  
  

#  AirBorne漏洞可导致苹果设备被完全劫持   
 网络安全与人工智能研究中心   2025-05-04 08:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHibykdgfR7Bfd3D5gQ9smYkhUSicwuicfUyAydJhQTRo5N6XPD9LxvGALWdC7ZZVI2R6skN0r8WUhrjcA/640?wx_fmt=gif&from=appmsg "")  
  
**苹果AirPlay协议及SDK中的漏洞使苹果及第三方设备面临攻击风险，包括远程代码执行。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibwel8SgRI3GqzCHDH37LbY6TPLzhiaBIcb9bwX4tWKtVnQt11ZuB2S5DasHlx3HZUBkVbxwuf6uQAg/640?wx_fmt=jpeg&from=appmsg "")  
  
网络安全公司Oligo在苹果AirPlay协议及软件开发套件（SDK）中发现一系列严重漏洞（统称为AirBorne），影响苹果及第三方设备。攻击者可利用这些漏洞实施零点击/单点击远程代码执行（RCE）、绕过访问控制列表（ACL）、读取本地文件、窃取数据，以及发起中间人（MITM）或拒绝服务（DoS）攻击。这些漏洞可被组合利用，通过无线或点对点连接完全劫持设备。  
  
  
**01**  
  
  
  
**漏洞影响范围广泛**  
  
  
AirBorne漏洞虽未影响所有苹果设备，但全球有23.5亿台活跃苹果设备（包括超1亿台Mac和数千万台支持AirPlay的第三方设备），潜在影响范围极大。研究人员发现编号为CVE-2025-24252和CVE-2025-24132的两个漏洞可实现可蠕虫传播的零点击RCE，攻击者不仅能劫持支持AirPlay的设备，还能通过本地网络传播恶意软件。由于AirPlay在苹果及第三方设备中的广泛存在，这些漏洞可能导致间谍活动、勒索软件和供应链攻击等风险。  
  
  
**02**  
  
  
  
**关键漏洞技术分析**  
  
  
CVE-2025-24252是macOS系统中的高危释放后使用（use-after-free）漏洞，远程攻击者可触发该漏洞执行任意代码。当与CVE-2025-24206组合利用时，可对网络设置开放的AirPlay设备发起零点击蠕虫攻击。攻击者无需用户交互即可通过公共WiFi等途径在网络间传播恶意软件。  
  
  
CVE-2025-24132是AirPlay SDK中的基于栈的缓冲区溢出漏洞，影响所有支持AirPlay的扬声器和接收器，同样可实现零点击蠕虫式RCE。利用该漏洞可从播放媒体内容到严重入侵（如在敏感环境中通过设备麦克风窃听）等多种攻击效果。  
  
  
**03**  
  
  
  
**漏洞修复与缓解措施**  
  
  
Oligo向苹果报告了23个漏洞，其中17个获得CVE编号。双方通过合作已识别并修复问题，遵循负责任的漏洞披露流程发布更新。为降低风险，用户应：  
  
  
- 及时更新设备系统  
  
- 停用不必要的AirPlay接收功能  
  
- 通过防火墙限制7000端口的AirPlay访问  
  
- 将"允许AirPlay访问"设置为"仅限当前用户"  
  
  
  
报告特别强调："企业必须立即更新所有支持AirPlay的公司设备，安全负责人还需明确告知员工及时更新个人设备。"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibykdgfR7Bfd3D5gQ9smYkhUMk71re53Z8Xju62nS9agGCNgUNjPibQP7YZthr22UXppftxLN0kp97A/640?wx_fmt=png&from=appmsg "")  
  
来源｜“FreeBuf”公众号  
  
编辑｜音叶泽  
  
审核｜秦川原  
  
  

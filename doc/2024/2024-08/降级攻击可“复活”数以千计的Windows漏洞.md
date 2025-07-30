#  降级攻击可“复活”数以千计的Windows漏洞   
 网络安全应急技术国家工程中心   2024-08-12 18:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176lxQpQZm2TJsWPWZD1oV4DUTMmj3rtUnV6a7Lt3u8Ns7UpDk9XoyXMH32DMH6dEQqxYcNzYaCibtTw/640?wx_fmt=png&from=appmsg "")  
  
黑帽大会曝出一种降级攻击，可复活数以千计的Windows漏洞，对Windows系统实施隐蔽、持久、不可逆转的攻击，且目前没有缓解措施。  
  
在本周举行的黑帽大会（Black Hat 2024）上，安全研究员Alon Leviev曝光了一个微软Windows操作系统的“超级漏洞”，该漏洞使得攻击者可以利用微软更新进程实施降级攻击，“复活”数以千计的微软Windows漏洞，即便是打满补丁的Windows11设备也将变得千疮百孔，脆弱不堪。  
# 把微软的更新服务变成“超级木马”  
  
在与微软协调后，Leviev在黑帽大会上公布了Windows降级攻击技术Windows Downdate的细节，这是一种可以操纵Windows Update更新进程的技术，使得恶意行为者能够将系统关键组件降级，进而使安全补丁失效。  
  
“通过Windows Downdate，我可以完全控制Windows Update进程，降级对象包括DLL、驱动程序甚至NT内核在内的关键操作系统组件，包括微软的虚拟化堆栈也不能幸免。”Leviev在黑帽大会上说道：“这让我能够绕过所有验证步骤，使得完全打补丁的Windows机器也容易受到成千上万个已修复漏洞的攻击。”  
  
Leviev的技术灵感来自于2023年的BlackLotus UEFI启动套件（Bootkit），该Bootkit通过降级Windows引导管理器，利用CVE-2022-21894漏洞绕过安全引导并禁用其他操作系统安全机制（例如BitLocker、HVCI和Windows Defender）。  
  
“我发现了一些漏洞，可用于开发Windows Downdate工具，以接管Windows Update进程，制造完全不可检测、隐形、持久且不可逆转的关键操作系统组件降级，”Leviev在其研究报告中说道。  
  
Leviev还找到了绕过UEFI锁来禁用Windows基于虚拟化的安全性(VBS)、Credential Guard和虚拟机管理程序保护的代码完整性(HVCI)的方法。  
  
“我能够让一台完全修补过的Windows机器受到过去存在的数千个漏洞的攻击，将已修复的漏洞变成零日漏洞，并让世界上任何一台Windows机器上的‘完全修补’一词都变得毫无意义。”Leviev总结道。  
# 被低估的降级攻击威胁  
  
此次漏洞的发现引发了广泛关注。Everest Group的高级分析师Arjun Chauhan指出，虽然微软尚未观测到此类降级攻击在野外发生，但SafeBreach团队在六个月前报告漏洞后，微软仍未提供可靠解决方案，这引发了业界对微软响应能力的担忧。  
  
降级攻击又称版本回滚攻击，是一种通过将软件恢复到旧版本，从而利用已修复漏洞的网络攻击。Chauhan指出，此类攻击可能对严重依赖Windows环境的企业和机构产生深远影响。“这些攻击可以逆转安全补丁，使系统重新暴露于先前已经修复的漏洞，增加数据泄露、未经授权访问和敏感信息丢失的风险。”  
  
此外，降级攻击可能通过破坏关键基础设施而中断运营，导致停机和经济损失。金融服务、医疗、政府和公共部门等具有严格合规要求的行业尤其脆弱。一旦这些行业遭受成功的降级攻击，可能会导致合规处罚，品牌和客户信任也将蒙受巨大损失。  
  
Leviev表示，降级攻击的威胁不仅限于Windows系统，且难以被标准的端点安全或EDR工具检测到，业界需要对操作系统降级攻击进行广泛关注和研究。  
  
Leviev强调，操作系统的设计功能无论多旧，都应视为潜在的攻击面。尽管微软尚未对此研究结果发表公开声明，但该公司已经发布了两个公告——CVE-2024-38202和CVE-2024-21302，微软警告说Windows Backup中的提权漏洞可能允许攻击者重新引入先前已修复的漏洞或绕过虚拟化安全功能（VBS）。  
  
Chauhan建议，微软发布永久解决方案之前，企业应密切监控降级尝试，限制管理权限，并严格执行最小权限原则（PoLP）。  
  
**参考链接：**  
  
https://www.blackhat.com/us-24/briefings/schedule/index.html?_gl=1*1jz1mvp*_gcl_au*MTgxMDYyNzI1NS4xNzIzMDk0MTkw#windows-downdate-downgrade-attacks-using-windows-updates-38963  
  
  
  
原文来源  
：GoUpSec  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  

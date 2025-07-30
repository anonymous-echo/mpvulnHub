#  新发现的Ubuntu安全绕过漏洞使攻击者可利用内核漏洞   
邑安科技  邑安全   2025-04-01 17:23  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sD1ssAsORFVbleMVzjo0O7ybecyBTRTcfqgtaxORahEQjh3xL5GmjEFotcTFBLJrb5bxw85kHbyg/640?wx_fmt=png&from=appmsg "")  
  
Ubuntu Linux权限限制遭突破：攻击者可利用三组漏洞绕过命名空间防护并提权  
  
安全研究人员发现Ubuntu Linux系统中存在三组关键安全绕过漏洞，允许本地攻击者突破非特权用户命名空间限制，实现权限提升并利用内核漏洞。这些漏洞主要影响以下系统：  
  
• Ubuntu 23.10（需手动启用防护）  
• Ubuntu 24.04 LTS（默认启用防护）  
  
虽然这些漏洞本身不能直接获取系统完全控制权，但当与需要CAP_SYS_ADMIN或CAP_NET_ADMIN等管理员权限的内核漏洞结合时，将形成有效攻击链。  
  
【漏洞技术分析】  
据Qualys威胁研究部门(TRU)披露，攻击者通过三种方法绕过了Ubuntu的命名空间防护机制：  
  
1.aa-exec工具绕过法  
系统预装的aa-exec工具允许切换至宽松的AppArmor配置文件（如trinity/chrome/flatpak）。攻击者可借此执行：  
```
aa-exec -p unconfined -- unshare -Urmfp
```  
  
在新建命名空间中获得完整权限。  
  
2.Busybox绕过法  
默认Busybox shell的AppArmor配置文件未限制命名空间创建。攻击者通过Busybox启动shell后执行：  
```
unshare -Urmfp
```  
  
此方法在服务器/桌面版均有效。  
  
3.LD_PRELOAD注入法  
通过向Nautilus（GNOME文件管理器）等受信进程注入恶意共享库：  
```
LD_PRELOAD=/malicious.so nautilus
```  
  
利用宽松配置在进程中创建特权命名空间。  
  
【影响范围与风险】  
用户命名空间作为容器化与沙盒技术的核心组件，一旦配置不当就会暴露内核攻击面。研究人员强调，虽然这些绕过漏洞本身不直接导致系统沦陷，但会显著降低利用内存损坏或竞争条件等内核漏洞的攻击门槛。  
  
Canonical公司已确认这些缺陷，但将其归类为"纵深防御弱点"而非关键漏洞。建议采取以下缓解措施：  
  
【内核参数调整】  
启用内核参数可阻止aa-exec滥用：  
```
echo 1 > /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined
```  
  
【配置文件强化】  
禁用Busybox和Nautilus的宽松AppArmor策略：  
```
aa-disable /usr/bin/busybox
aa-disable /usr/bin/nautilus
```  
  
【严格化bwrap策略】  
对依赖bwrap的应用（如Flatpak）实施细粒度命名空间控制  
  
管理员可通过aa-status  
命令审计现有策略，并通过标准Ubuntu渠道获取更新——但相关修复不会以紧急补丁形式发布。Qualys公司则通过其TruRisk Eliminate平台提供自动化防护方案，包含以下功能：  
• 预测试脚本自动配置内核参数  
• 禁用存在风险的防护策略  
• 与Qualys代理集成实现集中式部署  
• 无需打补丁即可隔离关键资产风险  
  
此次事件凸显了Linux发行版在易用性与安全性之间的平衡难题。尽管Ubuntu的前瞻性防护措施已成为行业标杆，但这些绕过漏洞表明纵深防御机制可能意外引入新的复杂性。  
  
随着内核级漏洞利用的增加，对于既重视系统持续运行又需保障安全的企业而言，采用TruRisk Eliminate等解决方案及快速强化实践至关重要。Qualys与Canonical正就AppArmor的长期改进持续合作，相关更新将在未来Ubuntu版本中发布。现阶段，管理员需手动实施缓解措施保护受影响系统。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/ubuntu-security-bypasses/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  

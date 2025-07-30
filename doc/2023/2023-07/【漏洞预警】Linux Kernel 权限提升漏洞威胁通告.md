#  【漏洞预警】Linux Kernel 权限提升漏洞威胁通告   
安识科技  SecPulse安全脉搏   2023-07-19 10:54  
  
##   
  
1. **通告信息**  
  
  
  
近日，安识科技  
A-Team团队监测到Linux Kernel 权限提升漏洞（CVE-2023-31248）的漏洞细节及PoC/EXP在互联网上公开，该漏洞的CVSS评分为7.8。  
  
对此，安识科技建议广大用户及时升级到安全版本，并做好资产自查以及预防工作，以免遭受黑客攻击。  
##   
  
2. **漏洞概述**  
  
  
  
漏洞名称：  
Linux Kernel 权限提升漏洞  
  
CVE编号：  
CVE-2023-31248  
  
简述：  
Linux内核是 Linux 操作系统（OS）的主要组件，也是计算机硬件与其进程之间的核心接口。  
  
nft_chain可以通过名称、句柄或ID 进行查找（分别对应函数nft_chain_lookup、nft_chain-lookup_byhandle和nft_chain_lookup_byid），前两者通过调用nft_active_genmask来检查链是否处于活动状态。如果用户为某个链发送DELETE消息，则该链将被停用，此检查可确保另一个对象将无法引用已停用的链。  
  
但由于  
nft_chain_lookup_byid()中没有对链是否处于活动状态进行检查，可以通过引用已停用的链，导致释放后使用，在任何用户或网络命名空间中具有 CAP_NET_ADMIN 访问权限的用户可进一步利用该漏洞导致权限提升。  
##   
  
3. **漏洞危害**  
  
  
  
由于  
nft_chain_lookup_byid()中没有对链是否处于活动状态进行检查，可以通过引用已停用的链，导致释放后使用，在任何用户或网络命名空间中具有 CAP_NET_ADMIN 访问权限的用户可进一步利用该漏洞导致权限提升。  
##   
  
4. **影响版本**  
  
  
  
目前受影响的  
Linux Kernel  
版本：  
  
Linux Kernel >= v5.9-rc1  
##   
  
5. **解决方案**  
  
  
  
目前  
Debian官方已发布相关修复版本，受影响用户可升级到以下版本：  
  
Linux Kernel (buster) >= 4.19.249-2  
  
Linux Kernel buster (security)>= 4.19.282-1  
  
Linux Kernel bullseye (security)>= 5.10.179-2  
  
参考链接：  
  
https://security-tracker.debian.org/tracker/CVE-2023-31248  
  
临时措施：  
  
1.在不影响正常业务的情况下可通过将内核 netfilter 模块列入黑名单来防止加载受影响的代码，以缓解该漏洞。有关如何将内核模块列入黑名单的说明，Red Hat Enterprise Linux用户可参考：  
  
https://access.redhat.com/solutions/41278  
  
2.可以通过关闭非特权用户启用命名空间来缓解该漏洞，但可能造成一定影响。  
##   
  
6. **时间轴**  
  
  
  
【-】2023年0  
7  
月  
17  
日 安识科技A-Team团队监测到漏洞公布信息  
  
【  
-】2023年0  
7  
月  
18  
日   
安识科技  
A-Team团队根据漏洞信息分析  
  
【  
-】2023年0  
7  
月  
19  
日   
安识科技  
A-Team团队发布安全通告  
  
  
  

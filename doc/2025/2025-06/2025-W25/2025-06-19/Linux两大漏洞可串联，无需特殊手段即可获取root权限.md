> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323331&idx=3&sn=fb387b84ee719ca1c647d97b1ce9fed3

#  Linux两大漏洞可串联，无需特殊手段即可获取root权限  
 FreeBuf   2025-06-19 10:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR395uCiblRufw6peqpFEw4DlSLjBR5Mhea9gOduDMot7JaPVOJbbQTPFxKcGVhEAVQwem3gfezP30pQ/640?wx_fmt=png&from=appmsg "")  
  
  
Qualys研究人员发现两个本地提权漏洞（CVE-2025-6018、CVE-2025-6019），攻击者可通过组合利用这两个漏洞，"轻松"在多数Linux发行版上获取root权限。  
  
  
**Part01**  
### 漏洞详情分析  
###   
  
**CVE-2025-6018**  
影响openSUSE Leap 15和SUSE Linux Enterprise 15的PAM（Pluggable Authentication Modules，可插拔认证模块）配置，允许无权限的本地攻击者（例如通过远程SSH会话登录的攻击者）获取物理在场用户的"allow_active"权限。  
  
  
PAM框架控制Linux系统中的用户认证和会话启动流程，该漏洞本质上是配置错误，导致系统将任何  
本地登录都视为用户在物理控制台前操作。  
  
  
获取"allow_active"权限后，攻击者可利用**CVE-2025-6019**  
—— libblockdev组件中的漏洞，将权限提升至_root_级别。获得root权限后，攻击者能够关闭EDR代理、植入后门、修改配置等，使受控系统成为渗透整个组织的跳板。  
###   
  
**Part02**  
### 影响范围与修复进展  
  
  
Qualys安全研究产品管理高级经理Saeed Abbasi指出，CVE-2025-6019可通过udisks守护进程利用，该组件默认安装在几乎所有Linux发行版中。Qualys威胁研究部门已开发概念验证代码，确认Ubuntu、Debian、Fedora和openSUSE Leap 15等系统存在可利用的漏洞。  
  
  
漏洞技术细节和PoC已公开，补丁已于上周私下提供给各Linux发行版开发商。  
###   
  
**Part03**  
### 漏洞利用机制与缓解建议  
###   
  
Abbasi强调："这类现代'本地到root'漏洞利用技术，彻底消除了普通登录用户与完全控制系统之间的屏障。通过串联udisks循环挂载和PAM/环境特性等合法服务，控制任何活跃GUI或SSH会话的攻击者能在数秒内突破polkit的allow_active信任区，获取root权限。整个过程无需特殊条件——每个环节都预装在主流Linux发行版及其服务器版本中。"  
  
  
安全公告还指出，CVE-2025-6018为攻击者利用其他需要"allow_active"权限的新漏洞创造了条件。目前主要Linux发行版已开始通过调整规则和/或更新libblockdev、udisks软件包修复漏洞。  
  
  
Abbasi解释缓解措施："默认polkit策略对org.freedesktop.udisks2.modify-device操作可能允许任何活跃用户修改设备。应将策略改为要求管理员认证才能执行此操作。鉴于udisks的普遍性和漏洞利用的简易性，各组织必须将此视为关键且普遍的风险，立即部署补丁。"  
###   
  
**参考来源：**  
  
Chaining two LPEs to get “root”: Most Linux distros vulnerable (CVE-2025-6018, CVE-2025-6019)  
  
https://www.helpnetsecurity.com/2025/06/18/chaining-two-lpes-to-get-root-most-linux-distros-vulnerable-cve-2025-6018-cve-2025-6019/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323227&idx=1&sn=9389a366094f7a22f383800c09d6b15f&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

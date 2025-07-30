#  严重Linux漏洞致全球数百万系统密码哈希值泄露   
 FreeBuf   2025-06-02 10:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38oibDQwml8vcnQNictHAaSkw1rrK4icibdM0EdNtwpaD5YAJcV70xk5CMhcE34ktr7FlYZdTCib64XwEA/640?wx_fmt=png&from=appmsg "")  
  
  
全球数百万Linux系统受到两个严重的本地信息泄露漏洞影响，攻击者可能通过操控核心转储（core dump）获取敏感密码数据。Qualys威胁研究部门（TRU）披露了这两个针对主流Linux发行版核心转储处理程序的竞争条件漏洞：  
- CVE-2025-5054：  
影响Ubuntu的Apport崩溃报告系统  
  
- CVE-2025-4598：  
影响Red Hat Enterprise Linux 9/10及Fedora默认使用的systemd-coredump组件  
  
这两个漏洞均利用竞争条件，使本地攻击者能够操控SUID（Set User ID）程序，并越权读取生成的核心转储文件。  
  
  
**Part01**  
### 技术细节  
  
  
Qualys研究人员已开发出概念验证攻击代码，演示如何通过针对unix_chkpwd进程（大多数Linux发行版默认安装的密码验证组件）提取密码哈希值。systemd-coredump和Apport等核心转储处理程序会在程序崩溃时自动捕获内存快照，其中可能包含密码、加密密钥和客户数据等敏感信息。  
  
  
虽然这些工具实施了限制root用户访问、将转储文件存储在安全位置等防护措施，但新发现的竞争条件漏洞可绕过这些保护机制。  
  
  
**Part02**  
### 受影响范围  
  
- Ubuntu系统：  
24.04及自16.04以来的所有版本（Apport版本≤2.33.0）  
  
- Red Hat/Fedora系统：  
RHEL 9/10和Fedora 40/41（通过systemd-coredump受影响）  
  
- Debian系统：  
默认受保护（除非手动安装核心转储处理程序）  
  
潜在影响不仅限于数据泄露，组织还面临运营中断、声誉损害和合规违规风险。攻击者获取密码哈希值后可能提升权限，在受感染网络中进行横向移动。  
  
  
**Part03**  
### 缓解措施  
  
  
安全专家建议立即实施关键缓解方案：将/proc/sys/fs/suid_dumpable参数设置为0。该配置会禁用所有SUID程序的核心转储功能，在官方补丁发布前有效消除攻击途径。  
  
  
研究人员指出："虽然此修改会禁用SUID程序和root守护进程的部分调试功能，但在无法立即修补漏洞时，这是必要的临时解决方案。"Qualys还提供了经过全面测试的缓解脚本，但警告大规模部署可能带来操作风险，建议在受控环境中充分测试。  
  
  
此次事件凸显了主动漏洞管理的重要性，以及在补丁不可立即获取时制定稳健缓解策略的必要性。组织应优先更新核心转储处理程序，同时实施推荐的临时缓解措施以防范潜在攻击。  
  
  
**参考来源：**  
  
Critical Linux Vulnerabilities Expose Password Hashes on Millions of Linux Systems Worldwide  
  
https://cybersecuritynews.com/linux-vulnerabilities-expose-password-hashes/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651321972&idx=1&sn=a781cae82004337aa46c61fb54bf864c&scene=21#wechat_redirect)  
### 电台讨论  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif "")  
  

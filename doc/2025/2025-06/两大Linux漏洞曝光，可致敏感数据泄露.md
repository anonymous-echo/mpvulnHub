#  两大Linux漏洞曝光，可致敏感数据泄露   
鹏鹏同学  黑猫安全   2025-06-02 23:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9sXQEbl1cgibrsr941GQtlicxdJW88jFeH1iaJnQCOuC1Ap1XwyBko32m1maeFfo1qWoVYX14DYMxLw/640?wx_fmt=png&from=appmsg "")  
  
Qualys研究人员发现Apport与systemd-coredump存在竞争条件漏洞，本地攻击者可窃取密码哈希等关键信息  
### 漏洞概述  
  
安全公司Qualys威胁研究团队(TRU)披露两个影响Linux核心转储机制的高危漏洞：  
1. **CVE-2025-5054**  
  
1. 影响对象：Ubuntu内置崩溃报告工具Apport（2.33.0及以下版本）  
  
1. 风险场景：攻击者通过竞态条件读取SUID程序崩溃后的核心转储  
  
1. **CVE-2025-4598**  
  
1. 影响对象：RHEL 9/10、Fedora 40/41默认配置的systemd-coredump  
  
1. 攻击手法：快速替换崩溃进程以绕过/proc/pid文件分析  
  
两漏洞CVSS评分均为4.7（中危），但可能引发高严重性数据泄露。  
### 技术解析  
  
当SUID程序崩溃时，系统会生成包含内存快照的核心转储文件。研究人员发现：  
- **漏洞本质**  
：核心转储处理器未对进程替换操作进行原子性检查  
  
- **攻击演示**  
：通过操控unix_chkpwd进程崩溃，成功提取/etc/shadow中的密码哈希  
  
- **数据风险**  
：加密密钥、用户凭证、客户信息等敏感数据可能被窃取  
  
### 受影响版本  
<table><thead><tr><th style="color: rgb(64, 64, 64);padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(187, 187, 187);border-top: none;font-weight: 600;font-size: 15px;line-height: 1.72;border-right-color: rgb(187, 187, 187);border-left-color: rgb(187, 187, 187);text-align: left;"><section><span leaf="">组件</span></section></th><th style="color: rgb(64, 64, 64);padding: 10px;border-bottom: 1px solid rgb(187, 187, 187);border-top: none;font-weight: 600;font-size: 15px;line-height: 1.72;border-right-color: rgb(187, 187, 187);border-left-color: rgb(187, 187, 187);text-align: left;"><section><span leaf="">受影响系统</span></section></th><th style="color: rgb(64, 64, 64);padding: 10px;border-bottom: 1px solid rgb(187, 187, 187);border-top: none;font-weight: 600;font-size: 15px;line-height: 1.72;border-right-color: rgb(187, 187, 187);border-left-color: rgb(187, 187, 187);text-align: left;"><section><span leaf="">安全版本</span></section></th></tr></thead><tbody><tr><td style="padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">Apport</span></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">Ubuntu 16.04~24.04</span></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">待官方补丁</span></section></td></tr><tr><td style="padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">systemd-coredump</span></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">RHEL 9/10、Fedora 40/41</span></section></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section><span leaf="">待官方补丁</span></section></td></tr><tr><td style="padding: 10px 10px 10px 0px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><em><span leaf="">Debian系</span></em></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><em><span leaf="">默认配置不受影响</span></em></td><td style="padding: 10px;border-bottom: 1px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><em><span leaf="">无需处置</span></em></td></tr></tbody></table>### 处置建议  
  
**临时缓解措施**  
  
# 禁用SUID程序核心转储  
echo  
0  
>  
 /proc/sys/fs/suid_dumpable  
  
**长期解决方案**  
- 关注各发行版安全公告，及时应用补丁  
  
- 对核心转储文件实施加密存储与访问审计  
  
**企业级防护**  
- 部署实时进程行为监控工具  
  
- 对/dev/core和/var/lib/systemd/coredump实施强制访问控制  
  
### 事件影响评估  
  
Qualys在报告中强调："此类漏洞可能引发三重风险——业务中断、声誉损失及合规违规。建议企业通过分层防御策略，将漏洞修复优先级调至最高。"  
  
  

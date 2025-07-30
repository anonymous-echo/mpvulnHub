#  Linux 内核高危漏洞致系统面临权限提升攻击   
原创 铸盾安全  河南等级保护测评   2025-04-29 10:42  
  
系统管理员应优先修补受影响的系统以减轻这种威胁。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoHoqic3icgiabquhKUyI4yTDLTiaibP1jhywpXfPyDuAgibmJjNOlPqgGkzjvDIuQWibcjGmhJBjW9UL3Leg/640?wx_fmt=png&from=appmsg "")  
  
Linux 内核的虚拟套接字 (vsock) 实现中存在一个严重漏洞，编号为 CVE-2025-21756，该漏洞可能允许本地攻击者将权限提升到 root 级别。   
  
安全研究人员已确认，该漏洞的 CVSS v3.1 基本评分为 7.8（高），可在受影响的系统上被有效利用。  
## 严重 Linux 内核漏洞 - CVE-2025-21756  
  
根据 Hoefler 的报告，该漏洞源于 vsock 子系统在传输重新分配期间对套接字绑定的不当处理。   
  
具体来说，问题发生在套接字的引用计数器错误地减少的序列中，从而导致释放后使用的情况。  
  
该漏洞的核心在于Linux内核中的以下代码路径：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoHoqic3icgiabquhKUyI4yTDLTmF62EMcicWu336cibd6RyiaSq3CEIicvuOjYwgqLB5UgXzAmosq6BQpPxg/640?wx_fmt=png&from=appmsg "")  
  
  
当发生传输重新分配时，此函数会减少引用计数器，而不验证套接字是否已绑定并移动到绑定列表。   
  
这可能会导致这样一种情况：后续对 vsock_bind() 的调用假定套接字位于未绑定列表中，并调用 __vsock_remove_bound()，从而导致释放后使用的情况。  
  
Linux 内核开发人员实施的补丁通过添加一个简单的检查来解决这个问题，以保留套接字绑定直到套接字销毁：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoHoqic3icgiabquhKUyI4yTDLTlQwpBvgicvzRiblnDrRedCOYp0lKqRdLnvqIxc8Dgao2lQ6CspibD5sAA/640?wx_fmt=png&from=appmsg "")  
  
  
<table><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">风险因素</span></font></font></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">细节</span></font></font></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">受影响的产品</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">具有 vsock（虚拟套接字）实现的 Linux 内核（特别是 6.6.79、6.12.16、6.13.4 和 6.14-rc1 之前的版本）</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">影响</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">可能提升权限</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">漏洞利用前提条件</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">本地访问，能够创建和操作 vsock 套接字；攻击复杂度低；无需用户交互；攻击者必须拥有本地权限</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVSS 3.1 评分</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">7.8（高）</span></font></font></td></tr></tbody></table>## 漏洞利用方法  
  
安全社区中出现了一种详细的利用方法。该攻击涉及触发UAF漏洞，然后使用受控数据回收已释放的内存。   
  
一种特别复杂的方法是利用管道支持页面来覆盖关键的内核结构。  
  
该漏洞通过查找未受这些安全机制保护的功能来绕过 Linux 安全模块 (LSM) 保护，特别是 AppArmor。   
  
通过使用 vsock_diag_dump() 作为侧信道，攻击者可以泄露 init_net 的内存地址，从而有效地破坏内核地址空间布局随机化 (KASLR)。  
  
利用这些功能，攻击者构建了一个面向返回编程 (ROP) 链，该链调用 commit_creds(init_cred) 来提升权限。   
  
最后的漏洞利用通过调用套接字的 release() 函数触发 sk->sk_error_report 的函数指针覆盖来重定向执行。  
## 受影响的系统和补丁发布  
  
此漏洞影响所有运行易受攻击内核版本的 Linux 发行版。对于严重依赖 vsock 功能进行客户机与主机通信的云环境和虚拟化系统而言，此问题尤其令人担忧。  
  
如果被利用，攻击者可以获得 root 权限，从而可能导致整个系统被入侵、数据被盗或服务中断。  
  
主流Linux发行版均已发布修复该漏洞的补丁。用户应立即将系统更新至最新内核版本。  
  
对于无法立即修补的系统，建议限制本地用户的访问并监控与 vsock 子系统相关的可疑活动。  
  
CVE-2025-21756 对 Linux 系统构成重大安全风险。虽然要求本地访问可以限制其直接影响，但已知漏洞利用方法的可靠性使得此漏洞在多用户或容器环境中尤其危险。   
  

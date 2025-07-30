#  Veeam 备份和复制漏洞曝光：高危漏洞使数据面临风险   
 独眼情报   2024-12-05 03:11  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnQhEicGhSWcS40x9K5N4Sib8RKl8f8omGicha8BcF4PoGmzjicRtyWw7ErH9IU4ibNibM2viafp8CsgKbyQQ/640?wx_fmt=other&from=appmsg "")  
  
知名备份、恢复和数据管理解决方案提供商 Veeam Software  
发布了  
安全更新，以解决其 Veeam Backup & Replication 软件中的多个漏洞。这些漏洞可能允许经过身份验证的攻击者执行恶意代码、未经授权访问敏感信息并破坏连接系统的完整性。  
  
这些漏洞中最严重的漏洞 CVE-2024-40717 的 CVSS v3.1 评分为 8.8，表明严重程度较高。此漏洞可能使攻击者能够以提升的权限执行任意代码，从而可能导致整个系统被攻陷。此更新中解决的其他漏洞包括：  
- CVE-2024-42451：  
允许以人类可读的格式访问已保存的凭据。  
  
- CVE-2024-42452：  
允许以提升的权限将远程文件上传到所连接的 ESXi 主机。  
  
- CVE-2024-42453：  
允许控制和修改连接的虚拟基础设施主机。  
  
- CVE-2024-42455：  
促进不安全的反序列化，可能导致文件删除。  
  
- CVE-2024-42456：  
授予对特权方法的访问权限和对关键服务的控制权。  
  
- CVE-2024-42457：  
通过远程管理界面公开已保存的凭据。  
  
- CVE-2024-45204：  
利用凭证处理中的权限不足，可能导致 NTLM 哈希的泄漏。  
  
另一个漏洞 CVE-2024-45207 影响 Veeam Agent for Microsoft Windows。当不受信任的用户可写入的目录添加到 PATH 环境变量中时，利用此漏洞可以进行 DLL 注入。虽然默认的 Windows PATH 不包含此类目录，但在配置错误的环境中风险仍然很大。  
  
Veeam 已在 Veeam Backup & Replication 12.3（内部版本 12.3.0.310）和 Veeam Agent for Microsoft Windows 6.3（内部版本 6.3.0.177）中修复了这些漏洞，并敦促所有用户立即升级到此版本。作为临时缓解措施，Veeam 建议从备份服务器上的用户和角色设置中删除任何不受信任或不必要的用户。  
  
强烈建议依赖 Veeam Backup & Replication 的组织立即采取行动来保护其关键数据和基础设施。  
  
https://www.veeam.com/kb4693  
  

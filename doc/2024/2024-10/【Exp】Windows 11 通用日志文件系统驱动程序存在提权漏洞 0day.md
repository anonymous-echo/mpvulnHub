#  【Exp】Windows 11 通用日志文件系统驱动程序存在提权漏洞 0day   
 独眼情报   2024-10-26 10:45  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSas9yENMjEZDJJFbAJjuVVibh0GsWricxIyoDicic5yVfiaRSBErA2hDozqIYdnCcmA3kqRoDvn5TD84Q/640?wx_fmt=png&from=appmsg "")  
>   
> https://ssd-disclosure.com/ssd-advisory-common-log-file-system-clfs-driver-pe/  
  
  
Windows 11 的通用日志文件系统 (CLFS) 驱动程序中发现了一个严重漏洞。此漏洞使本地用户能够通过利用系统内的特定功能来获得提升的权限。  
  
问题出在CClfsBaseFilePersisted::WriteMetadataBlock函数中，该函数的返回值ClfsDecodeBlock未得到正确检查。这一疏忽使攻击者能够破坏内部 CLFS 结构，从而可能导致权限提升。  
  
此外，该漏洞还可用于泄露内核池地址，从而绕过针对 Windows 11 24H2 计划的某些缓解措施。但是，TyphoonPWN 2024 的概念验证 (PoC) 并未使用此方法，因为它针对的是 Windows 11 23H2。  
  
一位独立安全研究人员发现了该漏洞，并在 TyphoonPWN 2024 中获得第一名。在最新版本的 Windows 11 上进行的测试表明该漏洞仍然存在。尚未提供 CVE 编号或补丁详细信息。  
# 漏洞利用过程  
  
CLFS 系统管理日志文件和结构，但不会暴露内核地址等敏感数据。该漏洞利用了管理元数据块的编码和解码过程。通过操纵这些过程，攻击者可以通过破坏CLFS结构中的重要数据来实现特权提升。  
  
攻击者可以通过重叠 CLFS 系统内的容器和客户端结构来触发此漏洞。这涉及创建日志文件并直接修改其结构以操纵校验和和编码标签。  
### 该漏洞涉及几个步骤：  
- 创建日志文件并添加容器。  
  
- 操纵文件结构来控制扇区标签。  
  
- CClfsContainer在用户空间准备一个虚假的结构。  
  
- 泄露内核地址、进程线程等系统信息。  
  
- 更改系统设置以绕过安全检查并提升权限。  
  
- 一旦成功利用，攻击者可以在系统上执行特权操作，例如生成具有提升权限的进程。  
  
此漏洞凸显了 Windows 11 CLFS 驱动程序中存在重大安全问题。建议用户保持警惕并应用 Microsoft 提供的任何可用更新以降低潜在风险。  
  
**微软表示，该漏洞是重复的，并且已经得到解决。然而，研究人员报告称，该漏洞在最新版本的 Windows 11 上仍然有效。该公司尚未提供 CVE 编号或补丁信息。**  
  
  

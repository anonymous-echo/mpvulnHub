> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096390&idx=1&sn=66c0d876dfb455de07d6dd757c11785c

#  Node.js 漏洞使 Windows 应用程序面临路径遍历和 HashDoS 攻击  
 网安百色   2025-07-16 10:47  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo4G3rMHmSMjS6ggHv3Rr3x9wabRJib7za4lbUDSwbfGPdnS9mZscFDZMxK7GlqDSTvbqHmVCgWI3bQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Node.js 项目已跨多个发布系列发布了关键安全更新，以解决影响 Windows 应用程序和 V8 引擎实施的两个高严重性漏洞。  
  
安全版本现已推出 Node.js 版本 20.x、22.x 和 24.x，其中的补丁解决了可能严重影响应用程序安全性和性能的路径遍历绕过和 HashDoS 攻击媒介。  

```
Key Takeaways
1. Node.js patched two high-severity flaws - Windows path traversal bypass (CVE-2025-27210) and V8 HashDoS attack (CVE-2025-27209).
2. Windows apps on Node.js 20.x, 22.x, 24.x vulnerable to path traversal; V8 HashDoS impacts only 24.x users.
3. Attackers can access unauthorized files via Windows device names and cause service disruption through hash collisions.
4. Update immediately to patched versions - v20.19.4, v22.17.1, and v24.4.1.
```

## Windows 路径遍历漏洞  
  
在 Node.js 中发现了一个标识为 CVE-2025-27210 的严重漏洞，专门针对 Windows 设备名称，包括 CON、PRN 和 AUX。  
  
这个高严重性问题代表了对之前修补的 CVE-2025-23084 的不完整修复，展示了攻击者如何绕过 path.normalize（） 函数中的路径遍历保护机制。  
  
该漏洞会影响在活动发布行 20.x、22.x 和 24.x 中使用 path.join（） API 的所有 Windows 用户。  
  
在处理包含 Windows 保留设备名称的文件路径时，path.normalize（） 函数无法正确清理输入，从而允许攻击者遍历目录结构并可能访问预期范围之外的敏感文件。  
  
此目录遍历攻击可能启用未经授权的文件系统访问、配置文件泄露或任意文件读取，具体取决于应用程序权限。  
  
当规范化过程遇到特定于 Windows 的设备名称时，会出现技术实现缺陷，这些名称作系统视为特殊系统文件。  
  
攻击者可以制作恶意路径，例如 ../../../CON/../../sensitive.txt 绕过应阻止访问父目录的安全控制。  
## V8 HashDoS 漏洞  
  
第二个漏洞 CVE-2025-27209 影响 Node.js v24.0.0 中使用的 V8 JavaScript 引擎，引入了哈希拒绝服务 （HashDoS） 攻击媒介。  
  
这个高严重性问题源于 V8 引擎使用 rapidhash 实现计算字符串哈希的方式发生了变化，这重新引入了基于冲突的漏洞。  
  
HashDoS 攻击允许恶意行为者通过控制输入字符串来生成大量哈希冲突，即使不知道哈希种子也是如此。  
  
这可能导致算法复杂性攻击，其中哈希表作的性能从 O（1） 下降到 O（n），从而可能导致严重的应用程序速度减慢或完全中断服务。  
  
与需要了解内部哈希函数的传统哈希冲突攻击不同，此漏洞使攻击者能够构建容易发生冲突的字符串，从而迫使哈希表进入最坏的性能场景。  
  
通过基于哈希的数据结构处理用户控制数据的应用程序特别容易受到 CPU 耗尽攻击。  
  
尽管 V8 团队对其进行了分类，但 Node.js 项目仍将其作为安全漏洞进行优先级排序，并认识到它在应用程序可用性至关重要的实际部署场景中的潜在影响。  
  
<table><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="7713706" msthash="78" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVE 漏洞</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="6486077" msthash="79" style="box-sizing: border-box;font-weight: bold;"><span leaf="">标题</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="17242355" msthash="80" style="box-sizing: border-box;font-weight: bold;"><span leaf="">受影响的产品</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="8943688" msthash="81" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVSS 3.1 分数</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="4044495" msthash="82" style="box-sizing: border-box;font-weight: bold;"><span leaf="">严厉</span></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">漏洞：CVE-2025-27210</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">Windows 设备名称（CON、PRN、AUX）PATH.NORMALIZE（） 中的绕过路径遍历保护</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">Node.js 20.x、22.x、24.x</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">7.5</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">高</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE-2025-27209漏洞</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">V8 中的 HashDoS</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">Node.js 24.x</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">7.5</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">高</span></section></td></tr></tbody></table>  
运行 Node.js 应用程序的组织应立即更新到最新的修补版本：Node.js v20.19.4、v22.17.1 和 v24.4.1。  
  
这些安全版本通过 Node.js 安全团队与漏洞研究人员 oblivionsage、sharp_edged、RafaelGSS 和 targos 合作开发的全面修复程序解决了这两个漏洞。  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

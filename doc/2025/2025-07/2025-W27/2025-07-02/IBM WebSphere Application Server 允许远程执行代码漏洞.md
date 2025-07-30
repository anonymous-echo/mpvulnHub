> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096366&idx=2&sn=0bc84ccadfed7c9c2ab6818255f637c7

#  IBM WebSphere Application Server 允许远程执行代码漏洞  
 网安百色   2025-07-01 11:24  
  
在 IBM WebSphere Application Server 中发现了一个被跟踪为 CVE-2025-36038 的关键安全漏洞，使组织面临未经身份验证的攻击者远程执行代码的风险。  
  
此漏洞影响广泛部署的版本 8.5 和 9.0，CVSS 基本分数为 9.0，强调了其严重性和修复的紧迫性。  
## 漏洞详情  
  
该漏洞源于不受信任数据的反序列化 （CWE-502），允许远程攻击者在受影响的系统上执行任意代码。  
  
<table><thead><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE 编号</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">描述</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVSS 评分</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">受影响的版本</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE-2025-36038漏洞</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">通过反序列化不受信任的数据来远程执行代码</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">9.0</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">8.5, 9.0</span></section></td></tr></tbody></table>  
通过发送特制的序列化对象序列，攻击者可以在不需要身份验证的情况下获得对底层服务器的未经授权的控制权。  
  
如果成功利用，这可能会导致重大数据泄露、服务中断或进一步危害企业环境。  
  
“IBM WebSphere Application Server 可能允许远程攻击者使用特制的序列化对象序列在系统上执行任意代码。”  
  
攻击复杂性被评为高 （AC：H），但对机密性、完整性和可用性的影响被认为是严重的 （C：H/I：H/A：H），这使得这是运行受影响软件的所有组织的高优先级问题。  
  
**受影响的产品**  
  
以下 IBM WebSphere Application Server 版本被确认为易受攻击：  
  
<table><thead><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">产品</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">受影响的版本</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">IBM WebSphere 应用服务器</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">9.0</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">IBM WebSphere 应用服务器</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">8.5</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">WebSphere Service Registry and Repository</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">8.5</span></section></td></tr></tbody></table>  
IBM 强烈建议立即采取行动，因为没有可用的解决方法或临时缓解措施。官方补救步骤如下：  
- 对于版本 9.0.0.0 到 9.0.5.24：  
- 升级到所需的最低修订包级别，并应用 APAR PH66674 的临时修订  
  
- 或者  
应用 Fix Pack 9.0.5.25 或更高版本（计划于 2025 年第 3 季度推出）  
  
- 对于版本 8.5.0.0 到 8.5.5.27：  
- 升级到所需的最低修订包级别，并应用 APAR PH66674 的临时修订  
  
- 或者  
应用 Fix Pack 8.5.5.28 或更高版本（目标于 2025 年第 3 季度推出）  
  
其他临时修复程序可能可用，应通过 IBM 的官方支持渠道进行引用。  
  
IBM WebSphere Application Server 是许多企业应用程序的基础中间件平台。  
  
CVE-2025-36038 的关键性质意味着，在完全应用补丁之前，依赖这些版本的组织将面临重大风险。  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

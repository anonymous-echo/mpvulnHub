> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096358&idx=1&sn=a32f0dc44801024ee9a611408348ce40

#  IBM WebSphere Application Server 允许执行任意代码漏洞  
 网安百色   2025-06-28 11:40  
  
已在 IBM WebSphere Application Server 中发现一个严重的安全漏洞，可能允许远程攻击者在受影响的系统上执行任意代码。  
  
此漏洞根据 CVE-2025-36038 进行跟踪，源于分类为 CWE-502 的不受信任数据反序列化问题。IBM 已为此缺陷分配了 9 分的关键 CVSS 基本分数，向量为 CVSS：3.1/AV：N/AC：H/PR：N/UI：N/S：C/C：H/I：H/A：H，表示在机密性、完整性和可用性影响方面具有较高严重性。  
  
该漏洞影响了 IBM WebSphere Application Server 的 9.0 和 8.5 版本，对依赖这个广泛使用的中间件平台来托管企业应用程序的组织构成了重大风险。  
  
此漏洞可通过构建一系列恶意序列化对象来利用，使攻击者能够在不需要事先身份验证的情况下获得对系统的未经授权的控制，前提是他们能够驾驭高度复杂的攻击。  
  
在 IBM WebSphere 中发现的严重漏洞  
  
IBM 已发布强烈建议，敦促立即采取行动缓解这一威胁，因为目前没有解决方法或临时缓解措施来绕过该问题。  
  
对于使用 IBM WebSphere Application Server 传统版本 9.0.0.0 到 9.0.5.24 的组织，IBM 建议升级到必要的修订包级别并应用 APAR PH66674的临时修订，或直接更新到修订包 9.0.5.25 或更高版本，预计将于 2025 年第三季度推出。  
  
同样，对于版本 8.5.0.0 到 8.5.5.27，用户应在满足最低修订包要求或升级到修订包 8.5.5.28 或更高版本（也计划于 2025 年第 3 季度发布）后，对 PH66674应用临时修复。  
  
可以通过 IBM 的官方下载页面访问其他临时修复程序，该公司强调了及时解决此漏洞以防止潜在利用的重要性。  
  
建议组织使用安全公告参考中提供的 CVSS v3 指南和在线计算器等资源来评估对其特定环境的影响。  
  
紧急修复和建议  
  
此漏洞凸显了与 IBM WebSphere Application Server 等复杂软件系统中的反序列化缺陷相关的持续风险，其中不受信任的输入可能导致灾难性的漏洞。  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

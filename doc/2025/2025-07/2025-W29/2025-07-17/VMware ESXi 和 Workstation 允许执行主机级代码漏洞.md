> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096390&idx=2&sn=7b2eebc0e92101cb685e047f60813844

#  VMware ESXi 和 Workstation 允许执行主机级代码漏洞  
 网安百色   2025-07-16 10:47  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo4G3rMHmSMjS6ggHv3Rr3x9yjWhVvicFBIDMUSlC4KRiatCyWOAzhYhHic4dDG1aVB7HVTmRPOkMjEcw/640?wx_fmt=jpeg&from=appmsg "")  
  
Broadcom 于 2025 年 7 月 15 日披露了 VMware 虚拟化套件中的四个关键漏洞，使攻击者能够逃离虚拟机并直接在主机系统上执行代码。  
  
这些缺陷是通过 Pwn2Own 竞赛发现的，影响了企业和桌面环境中的 ESXi、Workstation、Fusion 和 VMware Tools。  
## 漏洞概述  
  
<table><thead><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="7326319" msthash="36" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVE 编号</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="3995329" msthash="37" style="box-sizing: border-box;font-weight: bold;"><span leaf="">元件</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="12134226" msthash="38" style="box-sizing: border-box;font-weight: bold;"><span leaf="">漏洞类型</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="8427770" msthash="39" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVSS 评分</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="4085822" msthash="40" style="box-sizing: border-box;font-weight: bold;"><span leaf="">冲击</span></strong></td></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE-2025-41236漏洞</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">VMXNET3 虚拟 NIC</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">整数溢出</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">9.3</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">主机级代码执行</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE-2025-41237漏洞</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">VMCI</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">整数下溢</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">9.3</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">VMX 进程泄露</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">漏洞：CVE-2025-41238</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">PVSCSI 控制器</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">堆溢出</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">9.3</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">主机级代码执行</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE-2025-41239漏洞</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">vSockets</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">信息披露</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">7.1</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">内存泄漏</span></section></td></tr></tbody></table>  
最严重的漏洞 CVE-2025-41236 位于 VMXNET3 虚拟网络适配器中。  
  
在来宾虚拟机中具有管理权限的攻击者可以触发整数溢出，从而允许在底层主机系统上执行任意代码。  
  
此缺陷会影响 VMware 最常部署的虚拟网络适配器，使其对云和企业环境特别危险。  
  
CVE-2025-41237 以虚拟机通信接口 （VMCI） 为目标，该接口可促进主来宾交互，如剪贴板共享和拖放功能。  
  
整数下溢漏洞可导致越界内存写入，从而损害 VMX 进程。虽然 ESXi 的沙箱在 VMX 进程中包含漏洞利用，但 Workstation 和 Fusion 用户面临着主机完全受损。  
  
第三个严重缺陷 CVE-2025-41238 通过堆溢出漏洞影响半虚拟化 SCSI 控制器。  
  
攻击者可以利用此问题来实现主机级代码执行，但 ESXi 实施仅在不受支持的配置中容易受到攻击。桌面虚拟化产品仍然完全暴露在外。  
  
CVE-2025-41239 虽然评分较低，为 7.1，但可通过 vSockets 中未初始化的内存读取来泄露信息。  
  
此漏洞会影响 VMware Tools for Windows，并可能泄露敏感数据，包括加密密钥和内核指针，从而可能助长其他攻击。  
  
**受影响的产品和影响**  
  
这些漏洞会影响 VMware Cloud Foundation、vSphere Foundation、ESXi、Workstation Pro、Fusion、VMware Tools 和各种电信云平台。  
  
所有产品都共享易受攻击的设备仿真代码，从而在 VMware 的整个生态系统中形成广泛的攻击面。  
  
来自 STARLabs SG、REverse Tactics、Synacktiv 和 THEORI 的安全研究人员在 2025 年东京 Pwn2Own 大会上发现了这些漏洞，并展示了成功利用这些漏洞，可靠性接近 100%。  
  
Broadcom 已为所有受影响的版本发布了补丁，但没有提供任何解决方法。  
  
组织必须立即更新到修复版本：ESXi 7.x 到 8.0 U3b、Workstation Pro 17.5.1 和 Fusion Pro 13.5.1。VMware Tools 12.5.3 解决了特定于 Windows 的 vSockets 漏洞。  
  
该公司强调，修补虚拟机管理程序和工具组件是必不可少的，因为仅更新虚拟机管理程序会使信息泄露漏洞处于活动状态。  
  
由于概念验证漏洞已经公开演示，安全团队应优先考虑紧急修补，以防止潜在的主机入侵，从而可能实现跨虚拟化基础设施的横向移动。  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

#  VMware ESXi & vCenter 执行任意命令漏洞   
 网安百色   2025-05-21 11:28  
  
Broadcom 的 VMware 部门披露了其虚拟化产品中的关键安全漏洞，包括一个高严重性漏洞，该漏洞可能允许经过身份验证的用户在受影响的系统上执行任意命令。  
  
今天的安全公告解决了影响多个 VMware 产品的四个不同漏洞，严重性等级从中等到重要不等。  
## 关键命令执行漏洞  
  
最严重的漏洞 CVE-2025-41225 会影响 VMware vCenter Server，CVSS 评分为 8.8。此经过身份验证的命令执行漏洞允许具有权限的恶意行为者创建或修改警报，并运行脚本作以在 vCenter Server 上执行任意命令。  
  
安全专家认为此漏洞特别危险，因为它为攻击者提供了破坏核心虚拟化管理基础设施的直接途径。  
  
“这个漏洞对 vCenter Server 管理关键工作负载的企业环境构成了重大风险，”VMware 安全团队的一位发言人说。“组织应立即优先进行修补，以防止潜在的漏洞利用。”  
## 修补的其他漏洞  
  
该公告还解决了其他三个安全漏洞：  
- **CVE-2025-41226：**  
 漏洞执行客户机作时，ESXi 中存在拒绝服务漏洞（CVSS 评分为 6.8）。此漏洞允许具有客户机作权限的攻击者创建拒绝服务条件，从而影响运行 VMware Tools 的虚拟机。  
  
- **CVE-2025-41227：**  
Workstation、Fusion 和 ESXi 中由于某些客户机选项而存在拒绝服务漏洞（CVSS 评分为 5.5）。来宾作系统中的非管理用户可以通过耗尽主机进程的内存资源来利用此问题。  
  
- **漏洞 2025-41228：**  
ESXi 和 vCenter Server 登录页面中存在反射性的跨站点脚本漏洞（CVSS 评分为 4.3）。对特定 URL 路径具有网络访问权限的攻击者可以利用此问题窃取 Cookie 或将用户重定向到恶意网站。  
  
这些漏洞影响了广泛的 VMware 产品，包括 ESXi 7.0 和 8.0、vCenter Server 7.0 和 8.0，以及 Workstation 17.x、Fusion 13.x、VMware Cloud Foundation、Telco Cloud Platform 和 Telco Cloud Infrastructure。  
  
VMware 已发布更新来解决这些漏洞。对于 vCenter Server，用户应更新到版本 8.0 U3e 或 7.0 U3v，具体取决于其当前版本。  
  
ESXi 客户应应用修补程序 ESXi80U3se-24659227（适用于版本 8.0）或 ESXi70U3sv-24723868（适用于版本 7.0）。VMware Workstation 和 Fusion 用户应分别更新到版本 17.6.3 和 13.6.3。  
  
此公告发布之际，人们对 VMware 产品安全性的关注日益增加。本月早些时候，Broadcom 解决了 VMware Cloud Foundation 平台中的其他三个重要漏洞，这些漏洞允许攻击者未经授权访问敏感信息和内部服务。  
  
3 月，Broadcom 发布了一份公告，解决了 VMware ESXi 中的三个关键漏洞，这些漏洞链接在一起后，允许攻击者通过运行虚拟机来访问虚拟机管理程序。  
  
运行受影响的 VMware 产品的所有组织都应立即实施提供的补丁，因为没有针对这些漏洞的解决方法。  
  
鉴于 VMware 在企业虚拟化领域的主导地位，这些漏洞对组织安全态势构成了重大风险。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

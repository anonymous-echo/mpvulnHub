#  NVIDIA GPU 显示驱动程序漏洞   
 网安百色   2025-02-05 11:31  
  
 ![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo53bk2XBvgMAicgoNIvXTLrW4DLvAngicODFFoBnunh5L46ZpyVzTBuStdCK1ec9N97VeAnbSEVtczg/640?wx_fmt=png&from=appmsg "")  
  
**NVIDIA发布了关键安全更新，修复其GPU显示驱动程序和vGPU软件中的多个漏洞，影响Windows和Linux系统。**  
  
其中包括**CVE-2024-0149**，这是一个存在于Linux平台NVIDIA GPU显示驱动程序中的漏洞，攻击者可能通过该漏洞未经授权访问文件。  
  
这些漏洞在2025年1月披露，带来了如：拒绝服务（DoS）、数据篡改、信息泄露，甚至代码执行等安全风险。  
  
强烈建议通过NVIDIA驱动程序下载页面或NVIDIA vGPU软件许可门户更新驱动程序。  
### 漏洞详情  
  
此安全更新修复了七个关键漏洞，按严重性分为不同级别：  
  
**高危漏洞：**  
- **CVE-2024-0150**：GPU显示驱动程序（Windows和Linux）中的缓冲区溢出漏洞，允许数据写入超出分配内存的区域。这可能导致信息泄露、DoS或数据篡改（CVSS评分：7.1）。  
  
- **CVE-2024-0146**：vGPU软件中的虚拟GPU管理器发现的漏洞，恶意来宾可能导致内存损坏，进而导致代码执行、DoS或数据篡改（CVSS评分：7.8）。  
  
**中危漏洞：**  
- **CVE-2024-0147**：在GPU显示驱动程序（Windows和Linux）中释放内存后仍然引用已释放内存，利用此漏洞可能导致DoS或数据篡改（CVSS评分：5.5）。  
  
- **CVE-2024-53869**：Linux统一内存驱动中的漏洞可能泄漏未初始化的内存，导致信息泄露（CVSS评分：5.5）。  
  
- **CVE-2024-53881**：vGPU软件的主机驱动程序中发现的漏洞，允许来宾在主机系统上创建中断风暴，导致DoS（CVSS评分：5.5）。  
  
- **CVE-2024-0131**：GPU内核驱动程序中的缓冲区处理问题，攻击者可以读取不正确长度的缓冲区，可能导致DoS（CVSS评分：4.4）。  
  
**低危漏洞：**  
- **CVE-2024-0149**：Linux GPU显示驱动程序中的漏洞，允许未经授权访问文件，导致有限的信息泄露（CVSS评分：3.3）。  
  
这些漏洞影响了多个NVIDIA产品，涵盖不同的驱动程序分支：  
- **Windows驱动程序**：GeForce、NVIDIA RTX/Quadro/NVS和Tesla GPU，影响R535、R550、R560、R565和R570分支。更新版本包括R535（539.19）、R550（553.62）和R570（572.16）。  
  
  
- **Linux驱动程序**：Linux驱动程序中也存在类似问题，影响R535、R550和R570分支。更新版本包括R535（535.230.02）、R550（550.144.03）和R570（570.86.16）。  
  
  
- **vGPU软件**：对于vGPU软件用户，受影响的组件包括多个平台上的来宾驱动程序和虚拟GPU管理器，如Citrix Hypervisor、VMware vSphere、Red Hat Enterprise Linux KVM和Azure Local。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  

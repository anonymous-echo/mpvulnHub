> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAwMjA5OTY5Ng==&mid=2247526818&idx=1&sn=94387d1e5ab9647a7dd70aa9f62aa3f0

#  VMware ESXi、Workstation、Fusion及Tools多个漏洞  
长亭科技  乌雲安全   2025-07-17 08:37  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicSkU00iaylusqTRnXtY8ZJjKytDzE25myoK8KianiboKhDKE98K5SkwMRUdAjHRtYFE34akhYPlATiceQ/640?wx_fmt=png&from=appmsg "")  
  
  
VMware ESXi 是一款虚拟化平台，广泛应用于企业数据中心及云环境，旨在提供高效、灵活的虚拟化解决方案。  
  
  
  
VMware Workstation 是一款允许用户在一台计算机上运行多个操作系统的程序。它是一个虚拟机管理程序，可以创建与主机同时运行的虚拟机 (VM)。  
  
  
VMware Fusion 是一款专为 macOS 系统设计的软件虚拟机管理程序。它允许运行客户机操作系统（例如 Microsoft Windows、Linux 或 macOS）的虚拟机在主机 macOS 操作系统中运行。  
  
  
2025年7月，VMware发布安全通告VMware Advisory (VMSA-2025-0013)，修复了多个影响 VMware ESXi、Workstation、Fusion 和 Tools的漏洞。漏洞编号为 CVE-2025-41236、CVE-2025-41237、CVE-2025-41238 和 CVE-2025-41239，成功利用这些漏洞可导致远程代码执行，并实现从虚拟机逃逸至宿主机。建议受影响的用户尽快应用官方补丁，并加强网络及访问控制策略，以降低安全风险。  
  
#   
  
  
**漏洞描述**  
  
   
Description  
   
  
  
  
****  
**0****1**  
  
**漏洞成因**  
  
CVE-2025-41236：VMXNET3 整数溢出漏洞  
  
  
该漏洞的危害等级为“严重”，CVSSv3 基本评分为 9.3。该整数溢出漏洞存在于 VMXNET3 虚拟网络适配器中。要利用此漏洞，攻击者必须在具有 VMXNET3 虚拟网络适配器的虚拟机上拥有本地管理员权限。成功利用后，攻击者可以在宿主机上实现远程代码执行。  
  
注意：非 VMXNET3 适配器不受此漏洞影响。  
  
  
CVE-2025-41237：VMCI 整数下溢漏洞  
  
  
该漏洞的危害等级为“严重”，CVSSv3 基本评分为 9.3。该整数下溢漏洞存在于 VMCI（虚拟机通信接口）中，可能导致越界写入。攻击者必须拥有虚拟机的本地管理员权限才能利用该漏洞。攻击者可以利用该漏洞以虚拟机在主机上运行的 VMX 进程的身份执行代码。  
  
在 ESXi 上，漏洞利用过程包含在 VMX 沙箱中；而在 Workstation 和 Fusion 上，漏洞利用可能导致在安装 Workstation 或 Fusion 的宿主机上执行代码。  
  
  
CVE-2025-41238：PVSCSI 堆溢出漏洞  
  
  
该漏洞的危害等级为“严重”，CVSSv3 基本评分为 9.3。PVSCSI（半虚拟化 SCSI）控制器中的堆溢出漏洞可能导致越界写入。攻击者必须拥有虚拟机的本地管理员权限才能利用此漏洞。攻击者可以利用此漏洞在虚拟机的 VMX 进程在主机上运行的同时执行代码。  
  
在 ESXi 上，漏洞利用过程包含在 VMX 沙箱中，并且仅在不受支持的配置下才可利用。在 Workstation 和 Fusion 上，利用此漏洞可能导致在安装了 Workstation 或 Fusion 的宿主机上执行代码。  
  
  
CVE-2025-41239：vSockets 信息泄露漏洞  
  
  
此信息泄露漏洞源于在 vSockets 中使用未初始化的内存。攻击者必须拥有虚拟机的本地管理权限才能利用此漏洞。成功利用此漏洞可能导致与 vSockets 通信的进程发生内存泄漏。  
  
  
**漏洞影响**  
  
虚拟机逃逸：漏洞利用成功后，攻击者可从虚拟机直接突破隔离层，控制宿主机，进而威胁整个虚拟化环境。  
  
数据泄露：攻击者能窃取内存中的敏感信息  
  
**处置优先级：高**  
  
**漏洞类型：**  
越界写入、信息泄露  
  
**漏洞危害等级：**  
严重  
  
**触发方式：**  
网络远程  
  
**权限认证要求：**  
需要权限  
  
**系统配置要求：**  
默认配置  
  
**用户交互要求：**  
无需用户交互  
  
**利用成熟度：POC/EXP 未公开**  
  
**修复复杂度：低，官方提供版本升级修复方案**  
  
  
  
  
  
**影响版本**  
  
   
Affects  
   
  
  
  
**02**  
  
****  

```

VMware Fusion 13.0.x < 13.6.4 VMware Workstation 17.0.x  < 17.6.4 VMware ESXi 8.0.x  < ESXi80U2e-24789317 VMware ESXi 7.0.x  < ESXi70U3w-24784741 
```

  
**解决方案**  
  
   
Solution  
   
  
  
  
**03**  
  
##   
## 升级修复方案  
  
VMware已发布安全公告 VMSA-2025-0013 ，建议管理员尽快将受影响系统更新至厂商指定的安全版本：  
VMware Fusion 13.6.4 版本  
  
VMware Workstation 17.6.4 版本  
  
VMware ESXi ESXi80U2e-24789317 版本  
  
VMware ESXi ESXi70U3w-24784741   
版本  
  
  
**时间线**  
  
   
Timeline  
   
  
  
  
**04**  
  
2025年7月 VMware官方发布  
VMSA-2025-0013  
  
2025年  
7月17日 长亭安全应急响应中心发布通告  
  
  
  
参考资料：  
  
[1].  
https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/35877  
  
  

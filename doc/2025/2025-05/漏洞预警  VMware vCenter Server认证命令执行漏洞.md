#  漏洞预警 | VMware vCenter Server认证命令执行漏洞   
浅安  浅安安全   2025-05-26 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-41225  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
vCenter是VMware提供的集中管理平台，用于管理VMware vSphere环境中的虚拟化资源。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUsIwGlCfN2dZicibqWiaNHKgXtZoficGruNicBicXQfnPOYAIFEvOX4wRXia41InkIOZ4ZlaWwqzhEMoK6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-41225**  
  
**漏洞类型：**  
认证命令执行****  
  
**影响：**  
执行任意代码  
  
**简述：**  
VMware vCenter存在认证命令执行漏洞，攻击者在具备创建或修改警报以及执行脚本操作权限时，可能利用该漏洞在vCenter Server上执行任意命令。  
  
**0x04 影响版本**  
- vCenter Server 8.0 < 8.0 U3e  
  
- vCenter Server 7.0 < 7.0 U3v  
  
- VMware Cloud Foundation (vCenter) = 5.x  
  
- VMware Cloud Foundation (vCenter) = 4. 5.x  
  
- VMware Telco Cloud Platform (vCenter) 5.x/4.x/3.x/2.x < 8.0 U3e  
  
- VMware Telco Cloud Infrastructure (vCenter) 3.x < 8.0 U3e  
  
- VMware Telco Cloud Infrastructure (vCenter) 2.x < 7.0 U3v  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.vmware.com/cn/products/vcenter.html  
  
  
  

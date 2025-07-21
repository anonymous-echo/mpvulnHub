> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTc0NDcyNQ==&mid=2247494310&idx=2&sn=4d9b5a33631dfe30cdde65271ea9a153

#  Broadcom修复Pwn2Own Berlin 2025中被利用的VMware高危漏洞  
鹏鹏同学  黑猫安全   2025-07-21 01:24  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce8ZFaCb0IyoVa5RIZrr1FNCRJjBsZlLwg6pNyZ0cVe68vvVm2TEUyR3TaNIsPe6ou7PtJWJ25mAsw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞总览**  
在Pwn2Own Berlin 2025黑客大赛中，白帽黑客通过VMware漏洞斩获超34万美元奖金，其中：  
• **STARLabs SG**  
 因利用整数溢出漏洞攻陷ESXi获15万美元  
• **Synacktiv**  
 通过堆溢出漏洞控制Workstation主机获8万美元  
• **REverse Tactics**  
 组合利用漏洞实现ESXi逃逸获11.25万美元  
  
**漏洞技术细节**  
1. **CVE-2025-41236**  
 (CVSS 9.3)  
  
1. 类型：VMXNET3虚拟网卡整数溢出  
  
1. 风险：虚拟机管理员可执行宿主机代码  
  
1. 发现者：STARLabs SG  
  
1. **CVE-2025-41237**  
 (CVSS 9.3)  
  
1. 类型：VMCI虚拟通信接口整数下溢  
  
1. 关联利用：与CVE-2025-41239形成攻击链  
  
1. 发现者：REverse Tactics  
  
1. **CVE-2025-41238**  
 (CVSS 9.3)  
  
1. 类型：PVSCSI控制器堆溢出  
  
1. 影响：Workstation本地提权至宿主机  
  
1. 发现者：Synacktiv  
  
1. **CVE-2025-41239**  
 (CVSS 7.1)  
  
1. 类型：信息泄露漏洞  
  
1. 特点：被Corentin BAYET和Theori团队独立发现  
  
**厂商声明**  
Broadcom确认："目前未发现这些漏洞在野利用的证据。"  
  
**修复建议**  
✓ 立即升级至最新安全版本  
✓ 重点关注虚拟设备（VMXNET3/PVSCSI）的访问控制  
✓ 企业用户应审计虚拟机管理员权限分配  
  
  

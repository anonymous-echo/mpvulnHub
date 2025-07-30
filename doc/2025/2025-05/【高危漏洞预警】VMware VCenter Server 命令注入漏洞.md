#  【高危漏洞预警】VMware VCenter Server 命令注入漏洞   
cexlife  飓风网络安全   2025-05-22 13:52  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01vL2Mgwk73I6bdosPmzibkY4ZWfHI3PJJicXra13zxMvdnhW3kfcfUhGU9gxyA0e02eGzLSb7alwmg/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
VMware vCenter Server存在一个需授权的命令执行漏洞,具有创建或修改警报和运行脚本操作权限的恶意行为者可能会利用此问题在vCenter Server上运行任意命令,官方已经在新版本中修复此漏洞,建议受影响用户及时升级到安全版本。  
  
影响版本:  
  
7.0<=VMware vCenter Server<7.0U3v  
  
8.0<=VMware vCenter Server<8.0U3e  
  
修复建议:  
  
官方已经发布了修复补丁,请立即更新以下补丁:  
  
VMware vCenter Server 7.0 U3v  
  
VMware vCenter Server 8.0 U3e  
  
下载链接:  
  
VMware vCenter Server 7.0 U3v：https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/release-notes/vcenter-server-update-and-patch-releases/vsphere-vcenter-server-70u3v-release-notes.html  
  
VMware vCenter Server 8.0 U3e：https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/release-notes/vcenter-server-update-and-patch-release-notes/vsphere-vcenter-server-80u3e-release-notes.html  
  
安装前,请确保备份所有关键数据,并按照官方指南进行操作安装后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。  
  
参考链接:  
  
https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25717  
  
  

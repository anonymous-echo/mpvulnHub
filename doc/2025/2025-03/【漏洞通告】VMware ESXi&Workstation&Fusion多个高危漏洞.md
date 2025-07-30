#  【漏洞通告】VMware ESXi&Workstation&Fusion多个高危漏洞   
原创 NS-CERT  绿盟科技CERT   2025-03-05 17:26  
  
**通告编号:NS-2025-0011**  
  
2025-03-05  
  
<table><tbody><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">TA</span></strong><strong><span style="font-size: 14px;">G：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><p style="vertical-align: inherit;line-height: 1.75em;font-size: 14px;color: rgb(0, 0, 0);font-family: 微软雅黑;"><strong style="font-size: 17px;caret-color: red;font-family: 微软雅黑, sans-serif;"><span style="font-size: 14px;caret-color: red;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">VMware ESXi、Workstation、Fusion、CVE-2025-22224、CVE-2025-22225、CVE-2025-22226</span></strong></p></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><span style="color: rgb(0, 0, 0);"><strong><span style="font-size: 14px;">漏洞危害：</span></strong></span><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 14px;"></span></strong></span></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><p style="vertical-align:inherit;"><span style="font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="caret-color: red;"><span style="font-size: 14px;">攻击者利用此次漏洞，可实现信息窃取、沙箱逃逸、代码执行。</span></strong></span></p></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">版本：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">1.0<br/></span></strong></td></tr></tbody></table>  
  
**1**  
  
  
**漏洞概述**  
  
  
近日，绿盟科技CERT监测到VMware发布安全公告，修复了VMware ESXi&Workstation&Fusion多个高危漏洞(CVE-2025-22224/CVE-2025-22225/CVE-2025-22226)，目前3个漏洞均已发现在野利用，请相关用户尽快采取措施进行防护。  
  
CVE-2025-22224：VMware ESXi和Workstation中存在TOCTOU（CheckTime-of-use）越界写入漏洞，具有虚拟机管理员权限的攻击者可通过主机上运行的虚拟机VMX进程执行任意代码。CVSS评分9.3。  
  
CVE-2025-22225：VMware ESXi中存在任意写入漏洞，具有VMX进程特权的攻击者可通过触发任意内核写入实现沙箱逃逸。CVSS评分8.2。  
  
CVE-2025-22226：HGFS中存在越界读取漏洞，具有虚拟机  
管理员权限的攻击者可通过VMX进程获取内存信息。CVSS评分7.1。VMware是一家提供虚拟化解决方案的软件公司，它提供了多个虚拟化产品，其中包括VMware ESXi虚拟化操作系统、VMware Workstation、VMware vSphere虚拟化平台，以及各种管理和监控工具等。  
  
  
参考链接：  
  
https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25390  
  
  
**SEE MORE →******  
  
**2****影响范围**  
  
**受影响版本**  
  
**CVE-2025-22224/CVE-2025-22225/CVE-2025-22226：**  
  
- VMware ESXi 8.0 U3d < ESXi80U3d-24585383  
  
- VMware ESXi 8.0 U2d < ESXi80U2d-24585300  
  
- VMware ESXi 7.0 < ESXi70U3s-24585291  
  
- VMware Cloud Foundation 5.x < ESXi80U3d-24585383  
  
- VMware Cloud Foundation 4.5.x < ESXi70U3s-24585291  
  
- VMware Telco Cloud Platform 5.x/4.x/3.x/2.x < KB389385  
  
- VMware Telco Cloud Infrastructure 3.x/2.x < KB389385  
  
  
  
**CVE-2025-22224/CVE-2025-22225/CVE-2025-22226：**  
  
- VMware Workstation 17.x < 17.6.3  
  
  
  
**CVE-2025-22226：**  
  
- VMware Fusion 13.x < 13.6.3  
  
  
  
  
**不受影响版本**  
  
**CVE-2025-22224/CVE-2025-22225/CVE-2025-22226：**  
  
- VMware ESXi 8.0 U3d >= ESXi80U3d-24585383  
  
- VMware ESXi 8.0 U2d >= ESXi80U2d-24585300  
  
- VMware ESXi 7.0 >= ESXi70U3s-24585291  
  
- VMware Cloud Foundation 5.x >= ESXi80U3d-24585383  
  
- VMware Cloud Foundation 4.5.x >= ESXi70U3s-24585291  
  
- VMware Telco Cloud Platform 5.x/4.x/3.x/2.x >= KB389385  
  
- VMware Telco Cloud Infrastructure 3.x/2.x >= KB389385  
  
  
  
**CVE-2025-22224/CVE-2025-22226：**  
  
- VMware Workstation 17.x >= 17.6.3  
  
  
  
**CVE-2025-22226：**  
  
- VMware Fusion 13.x >= 13.6.3  
  
  
  
  
**3****漏洞防护**  
  
**3.1 官方升级**  
  
目前官方已发布更新修复了上述漏洞，请受影响的用户尽快安装进行防护：  
<table><tbody><tr><td style="border-top-style: double;border-top-color: windowtext;border-left-style: double;border-left-color: windowtext;border-bottom: none;border-right-color: windowtext;background: rgb(217, 217, 217);" width="148.33333333333334"><p style="text-align:center;line-height: 125%;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">产品版本</span></p></td><td style="border-top-style: double;border-top-color: windowtext;border-left: none;border-bottom: none;border-right-color: windowtext;background: rgb(217, 217, 217);word-break: break-all;" width="229.33333333333334"><p style="text-align:center;line-height: 125%;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">下载链接</span></p></td><td style="border-style: double double none none;border-top-color: windowtext;border-left-width: initial;border-left-color: initial;border-bottom-width: initial;border-bottom-color: initial;border-right-color: windowtext;background: rgb(217, 217, 217);" width="141.33333333333331"><p style="text-align:center;line-height: 125%;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">操作文档</span></p></td></tr><tr><td style="border-left-style: double;border-color: windowtext;" width="84.00000000000001"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">VMware ESXi 8.0 ESXi80U3d-24585383</span></p></td><td style="border-top-color: windowtext;border-right-color: windowtext;border-bottom-color: windowtext;border-left: none;" width="229.33333333333334"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://support.broadcom.com/web/ecx/solutiondetails?patchId=5773</span></p></td><td style="border-top-color: windowtext;border-left: none;border-bottom-color: windowtext;border-right-style: double;border-right-color: windowtext;" width="121.3333333333333"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/release-notes/esxi-update-and-patch-release-notes/vsphere-esxi-80u3d-release-notes.html</span></p></td></tr><tr><td style="border-top: none;border-left-style: double;border-left-color: windowtext;border-bottom-color: windowtext;border-right-color: windowtext;" width="84.00000000000001"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">VMware ESXi 8.0 ESXi80U2d-24585300</span></p></td><td style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-color: windowtext;" width="229.33333333333334"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://support.broadcom.com/web/ecx/solutiondetails?patchId=5772</span></p></td><td style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-style: double;border-right-color: windowtext;" width="121.3333333333333"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/release-notes/esxi-update-and-patch-release-notes/vsphere-esxi-80u2d-release-notes.html</span></p></td></tr><tr><td style="border-top: none;border-left-style: double;border-left-color: windowtext;border-bottom-color: windowtext;border-right-color: windowtext;" width="84.00000000000001"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">VMware ESXi 7.0 ESXi70U3s-24585291</span></p></td><td style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-color: windowtext;" width="229.33333333333334"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://support.broadcom.com/web/ecx/solutiondetails?patchId=5771</span></p></td><td style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-style: double;border-right-color: windowtext;" width="121.3333333333333"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/release-notes/esxi-update-and-patch-release-notes/vsphere-esxi-70u3s-release-notes.html</span></p></td></tr><tr><td style="border-top: none;border-left-style: double;border-left-color: windowtext;border-bottom-color: windowtext;border-right-color: windowtext;" width="84.00000000000001"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">VMware Workstation 17.6.3</span></p></td><td style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-color: windowtext;" width="229.33333333333334"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">（Windows）：https://support.broadcom.com/group/ecx/productfiles?subFamily=VMware%20Workstation%20Pro&amp;displayGroup=VMware%20Workstation%20Pro%2017.0%20for%20Windows&amp;release=17.6.3&amp;os=&amp;servicePk=undefined&amp;language=EN&amp;freeDownloads=true</span></p><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">（Linux）：https://support.broadcom.com/group/ecx/productfiles?subFamily=VMware%20Workstation%20Pro&amp;displayGroup=VMware%20Workstation%20Pro%2017.0%20for%20Linux&amp;release=17.6.3&amp;os=&amp;servicePk=undefined&amp;language=EN&amp;freeDownloads=true</span></p></td><td style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-style: double;border-right-color: windowtext;" width="121.3333333333333"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://techdocs.broadcom.com/us/en/vmware-cis/desktop-hypervisors/workstation-pro/17-0/release-notes/vmware-workstation-1763-pro-release-notes.html</span></p></td></tr><tr><td style="border-top: none;border-left-style: double;border-left-color: windowtext;border-bottom-color: windowtext;border-right-color: windowtext;" width="84.00000000000001"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">VMw</span><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">are Fusion 13.6.3</span></p></td><td style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-color: windowtext;" width="229.33333333333334"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://support.broadcom.com/group/ecx/productfiles?subFamily=VMware%20Fusion&amp;displayGroup=VMware%20Fusion%2013&amp;release=13.6.3&amp;os=&amp;servicePk=undefined&amp;language=EN&amp;freeDownloads=true</span></p></td><td style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-style: double;border-right-color: windowtext;" width="121.3333333333333"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://techdocs.broadcom.com/us/en/vmware-cis/desktop-hypervisors/fusion-pro/13-0/release-notes/vmware-fusion-1363-release-notes.html</span></p></td></tr><tr><td style="border-top: none;border-left-style: double;border-left-color: windowtext;border-bottom-color: windowtext;border-right-color: windowtext;" width="84.00000000000001"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">VMware Cloud Foundation 5.x, 4.5.x</span></p></td><td colspan="2" style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-style: double;border-right-color: windowtext;" width="390.3333333333333"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://knowledge.broadcom.com/external/article?legacyId=88287</span></p></td></tr><tr><td style="border-top: none;border-left-style: double;border-left-color: windowtext;border-bottom-style: double;border-bottom-color: windowtext;border-right-color: windowtext;" width="84.00000000000001"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">Telco Cloud Platform 5.x, 4.x, 3.x</span></p></td><td colspan="2" style="border-top: none;border-left: none;border-bottom-style: double;border-bottom-color: windowtext;border-right-style: double;border-right-color: windowtext;" width="390.3333333333333"><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">https://techdocs.broadcom.com/us/en/vmware-sde/telco-cloud/vmware-telco-cloud-platform/5-0/Chunk77140612.html</span></p><p style="text-align:left;"><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"> https://techdocs.broadcom.com/us/en/vmware-sde/telco-clo</span><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">u</span><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">d/vmware-telco-cloud-platform/4-0/vmware-te</span><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">lco-cloud-platfor</span><span style="font-size: 14px;letter-spacing: normal;line-height: 2em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">m-401-release-notes.html<br/>https://techdocs.broadcom.com/us/en/vmware-sde/telco-cloud/vmware-telco-cloud-platform/3-1/Chunk1587463997.html#Chunk1587463997</span></p></td></tr></tbody></table>  
  
  
**END**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qR4ORTNELImFwJM2rh6GKbnrurdFA28jJ8chUPyC1U6aW3jhenqEiaXkmeGVmfOnvAJy8j3My901JQ7emHaicYzA/640?wx_fmt=png "")  
           
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qR4ORTNELImFwJM2rh6GKbnrurdFA28jib7icfic0lJJHh3eLRpIXiaia08KqOSEibBsz64vlOH9aqicu3lmjccEeAFWQ/640?wx_fmt=jpeg "")  
          
  
**声明**  
  
本安全公告仅用来描述可能存在的安全问题，绿盟科技不为此安全公告提供任何保证或承诺。由于传播、利用此安全公告所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，绿盟科技以及安全公告作者不为此承担任何责任。              
  
绿盟科技拥有对此安全公告的修改和解释权。如欲转载或传播此安全公告，必须保证此安全公告的完整性，包括版权声明等全部内容。未经绿盟科技允许，不得任意修改或者增减此安全公告内容，不得以任何方式将其用于商业目的。              
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qR4ORTNELImFwJM2rh6GKbnrurdFA28jib7icfic0lJJHh3eLRpIXiaia08KqOSEibBsz64vlOH9aqicu3lmjccEeAFWQ/640?wx_fmt=jpeg "")  
  
  
**绿盟科技CERT**  
****  
∣  
微信公众号  
  
![绿盟科技CERT公众号.jpg](https://mmbiz.qpic.cn/mmbiz_jpg/VvfsuOanecqbRYN2ibLpX6VMiaBicibl5zEuJ46cTTiaGk5LYx26NZyP34IsibogsxSbnnQKT90Q0S9GwJB2lLt6KUkg/640?wx_fmt=jpeg&from=appmsg "绿盟科技CERT公众号.jpg")  
  
![](https://mmbiz.qpic.cn/mmbiz/Hu8hctxHqSW0nSJn8p8OHVEQwHicSwTibFJMBE650AxdzfISoeY8woe2QsgCINIBrccBOOUft2HuU0GsNQWibSG7g/640?wx_fmt=png "")  
  
长按识别二维码，关注网络安全威胁信息  
  
  
  

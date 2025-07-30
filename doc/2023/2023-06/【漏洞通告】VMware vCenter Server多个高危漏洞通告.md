#  【漏洞通告】VMware vCenter Server多个高危漏洞通告   
原创 NS-CERT  绿盟科技CERT   2023-06-26 18:09  
  
**通告编号:NS-2023-0027**  
  
2023-06-26  
  
<table><tbody><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="95"><strong><span style="font-size: 14px;">TA</span></strong><strong><span style="font-size: 14px;">G：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="487"><p style="vertical-align: inherit;line-height: 1.75em;font-size: 14px;color: rgb(0, 0, 0);font-family: 微软雅黑;"><strong style="caret-color: red;line-height: 1.57em;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">vCenter Server、Cloud Foundation、CVE-2023-20892、CVE-2023-20893、CVE-2023-20894、CVE-2023-20895、CVE-2023-20896</span></strong></p></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><span style="color: rgb(0, 0, 0);"><strong><span style="font-size: 14px;">漏洞危害：</span></strong></span><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 14px;"></span></strong></span></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="467"><p><strong style="caret-color: red;font-size: 14px;line-height: 1.5em;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">攻击者利用本次安全更新中的漏洞，可造成远程代码执行、越界写入读取等</strong></p></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">版本：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="183"><strong><span style="font-size: 14px;">1.0<br/></span></strong></td></tr></tbody></table>  
  
**1**  
  
  
**漏洞概述**  
  
  
近日，绿盟科技  
CERT  
监测到  
VMware  
官方发布安全通告披露了  
VMware vCenter Server  
中的多个漏洞，  
攻击者可利用这些漏洞造成远程代码执行、越界写入读取等。目前官方已更新版本修复，请相关用户采取措施进行防护。  
  
vCenter Server是VMware公司的一种服务器管理解决方案，可帮助IT管理员通过单个控制台管理企业环境中的虚拟机和虚拟化主机。  
  
  
参考链接：  
  
https://www.vmware.com/security/advisories/VMSA-2023-0014.html  
  
  
**SEE MORE →******  
  
**2****重点漏洞简述**  
  
**vCenter Server****堆溢出漏洞（****CVE-2023-20892****）：**  
  
由于在DCERPC协议的实现中使用了未初始化的内存，对vCenter Server有网络访问权的恶意攻击者可利用该漏洞在使用了vCenter Server的底层操作系统上执行任意代码，CVSS评分8.1。  
  
  
**vCenter Server****释放后重用漏洞（****CVE-2023-20893****）：**  
  
vCenter Server在DCERPC协议的实现中存在一个释放重用漏洞，对vCenter Server有网络访问权的恶意攻击者可以利用该漏洞在使用了vCenter Server的底层操作系统上执行任意代码，CVSS评分8.1。  
  
  
**vCenter Server****越界写入漏洞（****CVE-2023-20894****）：**  
  
vCenter Server在DCERPC协议的实现中存在一个越界写入漏洞，对vCenter Server有网络访问权的恶意攻击者可通过发送特制的数据包来触发越界写入，导致内存损坏，CVSS评分8.1。  
  
  
**vCenter Server****越界读取漏洞（****CVE-2023-20895****）：**  
  
vCenter Server在DCERPC协议的实现中存在一个越界读取漏洞，对vCenter Server有网络访问权的恶意攻击者利用该漏洞可导致内存损坏，进而绕过身份验证，CVSS评分8.1。  
  
  
**vCenter Server****越界读取漏洞（****CVE-2023-20896****）：**  
  
vCenter Server在DCERPC协议的实现中存在一个越界读取漏洞，对vCenter Server具有网络访问权限的恶意攻击者可通过发送特制数据包来触发越界读取，从而导致某些服务（vmcad、vmdird和vmafdd）被拒绝服务，CVSS评分5.9。  
  
  
**3****影响范围**  
  
**受影响版本：**  
  
- VMware vCenter Server 8.0系列 < 8.0 U1b  
  
- VMware vCenter Server 7.0系列 < 7.0 U3m  
  
- VMware Cloud Foundation (vCenter Server) 5.x系列 < 8.0 U1b  
  
- VMware Cloud Foundation (vCenter Server) 4.x系列 < 7.0 U3m  
  
  
  
  
**不受影响版本：**  
  
- VMware vCenter Server 8.0系列 = 8.0 U1b  
  
- VMware vCenter Server 7.0系列 = 7.0 U3m  
  
- VMware Cloud Foundation (vCenter Server) 5.x系列 = 8.0 U1b  
  
- VMware Cloud Foundation (vCenter Server) 4.x系列 = 7.0 U3m  
  
  
  
  
**4****漏洞防护**  
  
**4.1 官方升级**  
  
目前官方已在最新版本中修复了该漏洞，请受影响的用户尽快升级版本进行防护，对应产品版本的下载链接如下：  
<table><tbody><tr><td valign="top" style="border-top-width: 2px;border-left-width: 2px;border-color: windowtext;background: rgb(217, 217, 217);" width="144"><p style="text-align:center;line-height: 1.75em;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>产品版本</strong></span></p></td><td valign="top" style="border-top-width: 2px;border-top-color: windowtext;border-left: none;border-bottom-color: windowtext;border-right-width: 2px;border-right-color: windowtext;background: rgb(217, 217, 217);" width="416"><p style="text-align:center;line-height: 1.75em;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>下载链接</strong></span></p></td></tr><tr><td valign="top" style="border-top: none;border-left-width: 2px;border-left-color: windowtext;border-bottom-color: windowtext;border-right-color: windowtext;" width="101"><p style="text-align:left;line-height: 1.75em;"><span style="line-height: 125%;color: black;background: white;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">VMware vCenter Server 8.0   U1b</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-width: 2px;border-right-color: windowtext;" width="436"><p style="text-align:left;line-height: 1.75em;"><span style="line-height: 125%;color: black;background: white;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">https://docs.vmware.com/en/VMware-vSphere/8.0/rn/vsphere-vcenter-server-80u1b-release-notes/index.html</span></p></td></tr><tr><td valign="top" style="border-top: none;border-left-width: 2px;border-left-color: windowtext;border-bottom-color: windowtext;border-right-color: windowtext;" width="101"><p style="text-align:left;line-height: 1.75em;"><span style="line-height: 125%;color: black;background: white;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">VMware vCenter Server 7.0   U3m</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-width: 2px;border-right-color: windowtext;" width="436"><p style="text-align:left;line-height: 1.75em;"><span style="line-height: 125%;color: black;background: white;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">https://docs.vmware.com/en/VMware-vSphere/7.0/rn/vsphere-vcenter-server-70u3m-release-notes/index.html</span></p></td></tr><tr><td valign="top" style="border-top: none;border-left-width: 2px;border-left-color: windowtext;border-bottom-color: windowtext;border-right-color: windowtext;" width="101"><p style="text-align:left;line-height: 1.75em;"><span style="line-height: 125%;color: black;background: white;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">VMware Cloud Foundation   (vCenter Server) 8.0 U1b</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: windowtext;border-right-width: 2px;border-right-color: windowtext;" width="436"><p style="text-align:left;line-height: 1.75em;"><span style="line-height: 125%;color: black;background: white;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">https://kb.vmware.com/s/article/88287</span></p></td></tr><tr><td valign="top" style="border-top: none;border-left-width: 2px;border-left-color: windowtext;border-bottom-width: 2px;border-bottom-color: windowtext;border-right-color: windowtext;" width="101"><p style="text-align:left;line-height: 1.75em;"><span style="line-height: 125%;color: black;background: white;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">VMware Cloud Foundation   (vCenter Server) 7.0 U3m</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-width: 2px;border-bottom-color: windowtext;border-right-width: 2px;border-right-color: windowtext;" width="436"><p style="text-align:left;line-height: 1.75em;"><span style="line-height: 125%;color: black;background: white;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">https://kb.vmware.com/s/article/88287</span></p></td></tr></tbody></table>  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/VvfsuOanecpHicbMS3dQSs6dOllWuxpBElrLjdVXLXWvZ6LIqiaN7RKqYCT1mSwXZsiaL8WemiaRTCAStVwCVic2CQw/640?wx_fmt=jpeg "绿盟科技CERT公众号.jpg")  
  
![](https://mmbiz.qpic.cn/mmbiz/Hu8hctxHqSW0nSJn8p8OHVEQwHicSwTibFJMBE650AxdzfISoeY8woe2QsgCINIBrccBOOUft2HuU0GsNQWibSG7g/640?wx_fmt=png "")  
  
长按识别二维码，关注网络安全威胁信息  
  
  

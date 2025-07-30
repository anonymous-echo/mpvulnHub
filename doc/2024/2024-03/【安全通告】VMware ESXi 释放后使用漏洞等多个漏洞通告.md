#  【安全通告】VMware ESXi 释放后使用漏洞等多个漏洞通告   
深瞳漏洞实验室  深信服千里目安全技术中心   2024-03-08 18:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xqu4e0pz18uW94jLFxHeCicmY6seurOYuYk57OUp84zE2SJjgn3icG61TKCyF9hYJX3xyOVicO8gSzw/640?wx_fmt=gif&from=appmsg "")  
****  
**漏洞名称：**  
  
VMware ESXi 释放后使用漏洞等多个漏洞  
  
**组件名称：**  
  
VMware ESXi  
  
**安全公告链接：**   
  
https://www.vmware.com/security/advisories/VMSA-2024-0006.html  
  
**官方解决方案：**  
  
已发布  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xqu4e0pz18uW94jLFxHeCicTpQU8qDhKyvwYhHJI8YqaYdONwCQwxfibFJYicXIsBSreDHFia2NrMdmA/640?wx_fmt=gif&from=appmsg "")  
  
**组件介绍**  
  
VMware ESXi 是一款由VMware公司开发的企业级服务器虚拟化产品，可以直接安装在物理服务器上，是轻量级，高效，易于管理，安全和可扩展的虚拟化基础设施，适用于各种规模的企业实现服务器资源的优化利用和管理。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xqu4e0pz18uW94jLFxHeCicTpQU8qDhKyvwYhHJI8YqaYdONwCQwxfibFJYicXIsBSreDHFia2NrMdmA/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞描述**  
  
  
近日，深瞳漏洞实验室监测到一则VMware官方发布安全补丁的通告，共修复了4个安全漏洞，其中包括4个高危漏洞的信息。  
  
<table><tbody><tr><td width="32" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">序号<strong><span style="font-family: &#34;Times New Roman&#34;;font-size: 14pt;"><o:p></o:p></span></strong></p></td><td width="156" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">漏洞名称<strong><span style="font-family: 仿宋_GB2312;font-size: 14pt;"><o:p></o:p></span></strong></p></td><td width="137" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">影响版本<strong><span style="font-family: &#34;Times New Roman&#34;;font-size: 14pt;"><o:p></o:p></span></strong></p></td><td width="54" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">严重等级<strong><span style="font-family: &#34;Times New Roman&#34;;font-size: 14pt;"><o:p></o:p></span></strong></p></td></tr><tr style="height:138.7500pt;"><td width="52" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">1<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="176" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">VMware ESXi 释放后使用漏洞(CVE-2024-22252<span style="font-family:仿宋_GB2312;mso-ascii-font-family:&#39;Times New Roman&#39;;mso-hansi-font-family:&#39;Times New Roman&#39;;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><span style="font-family:Times New Roman;">)</span></span><span style="font-family:仿宋_GB2312;mso-ascii-font-family:&#39;Times New Roman&#39;;mso-hansi-font-family:&#39;Times New Roman&#39;;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="157" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">ESXi 8.0,ESXi 7.0,Workstation 17.x,Fusion 13.x（MacOS平台）,Cloud Foundation (ESXi) 5.x/4.x<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="74" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">高危<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr><tr><td width="52" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">2<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="176" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">VMware ESXi 释放后使用漏洞(CVE-2024-22253)<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="157" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">ESXi 8.0,ESXi 7.0,Workstation 17.x,Fusion 13.x（MacOS平台）,Cloud Foundation (ESXi) 5.x/4.x<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="74" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">高危<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr><tr><td width="52" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">3<span style="font-family:仿宋_GB2312;mso-ascii-font-family:&#39;Times New Roman&#39;;mso-hansi-font-family:&#39;Times New Roman&#39;;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="176" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">VMware ESXi 越界写入漏洞(CVE-2024-22254)<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="157" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">ESXi 8.0,ESXi 7.0,Workstation 17.x,Fusion 13.x（MacOS平台）,Cloud Foundation (ESXi) 5.x/4.x<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="74" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">高危<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr><tr><td width="52" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">4<span style="font-family:仿宋_GB2312;mso-ascii-font-family:&#39;Times New Roman&#39;;mso-hansi-font-family:&#39;Times New Roman&#39;;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="176" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">VMware ESXi 信息泄露漏洞(CVE-2024-22255)<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="157" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">ESXi 8.0,ESXi 7.0,Workstation17.x,Fusion 13.x（MacOS平台）,Cloud Foundation (ESXi) 5.x/4.x<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td><td width="74" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">高危<span style="font-family:&#39;Times New Roman&#39;;mso-fareast-font-family:仿宋_GB2312;font-size:14.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xqu4e0pz18uW94jLFxHeCicTpQU8qDhKyvwYhHJI8YqaYdONwCQwxfibFJYicXIsBSreDHFia2NrMdmA/640?wx_fmt=gif&from=appmsg "")  
  
**高危漏洞描述**  
  
  
**VMware ESXi 释放后使用漏洞(CVE-2024-22252)**  
  
VMware ESXi, Workstation和 Fusion等产品存在释放后使用漏洞，攻击者可利用该漏洞在获得管理员权限的情况下，构造恶意数据执行释放后使用攻击，最终可在目标服务器执行任意代码。  
  
  
**VMware ESXi 释放后使用漏洞(CVE-2024-22253)**  
  
VMware ESXi, Workstation和 Fusion等产品存在释放后使用漏洞，攻击者可利用该漏洞在获得管理员权限的情况下，构造恶意数据执行释放后使用攻击，最终可在目标服务器执行任意代码。  
  
  
**VMware ESXi 越界写入漏洞(CVE-2024-22254)**  
  
VMware ESXi, Workstation和 Fusion等产品存在越界写入漏洞，攻击者可利用该漏洞在获得权限的情况下，构造恶意数据执行越界写入攻击，最终可造成虚拟机沙箱逃逸。  
  
  
**VMware ESXi 信息泄露漏洞(CVE-2024-22255)**  
  
VMware ESXi, Workstation和 Fusion等产品存在信息泄露漏洞，攻击者可利用该漏洞在获得管理员权限的情况下，构造恶意数据执行越界访问攻击，最终可造成服务器内存信息泄露。  
  
  
  
**影响范围**  
  
  
目前受影响的VMware ESXi及其关联组件版本：  
  
VMware ESXi 8.0,  
  
VMware ESXi 7.0,  
  
VMware Workstation 17.x,  
  
VMware Fusion 13.x（MacOS平台）,  
  
VMware Cloud Foundation (ESXi) 5.x/4.x  
  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xqu4e0pz18uW94jLFxHeCicTpQU8qDhKyvwYhHJI8YqaYdONwCQwxfibFJYicXIsBSreDHFia2NrMdmA/640?wx_fmt=gif&from=appmsg "")  
  
**官方修复建议**  
  
  
当前官方已发布受影响版本的对应补丁，建议受影响的用户及时更新官方的安全补丁。链接如下：  
  
https://www.vmware.com/security/advisories/VMSA-2024-0006.html  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xqu4e0pz18uW94jLFxHeCicTpQU8qDhKyvwYhHJI8YqaYdONwCQwxfibFJYicXIsBSreDHFia2NrMdmA/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
**1.风险资产发现**  
  
支持对VMware ESXi,VMware Workstation,VMware Fusion的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服云镜YJ】**已发布检测方案。  
  
**【深信服漏洞评估工具TSS】**已发布检测方案。  
  
  
  
**参考链接**  
  
  
https://www.vmware.com/security/advisories/VMSA-2024-0006.html  
  
  
**时间轴**  
  
  
  
**2024/3/8**  
  
深瞳漏洞实验室监测到VMware官方发布安全补丁。  
  
  
**2024/3/8**  
  
深瞳漏洞实验室发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xqu4e0pz18uW94jLFxHeCicK7Ys8RSRMh0pibaibjia0GiazenfGgYq9L49LJoUAGWQc8zqNt9hAcYjicw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5xqu4e0pz18uW94jLFxHeCicKZPdiaaPOwoOEJd9lIIPLaGsSeBmxQO4kqMTsVE8HcELLibZqBsTdticg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  

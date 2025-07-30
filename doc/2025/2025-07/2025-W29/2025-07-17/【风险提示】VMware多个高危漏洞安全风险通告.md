> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0ODM3NTU5MA==&mid=2247494290&idx=2&sn=a02c958b20179cf6beb420d4491d6a11

#  【风险提示】VMware多个高危漏洞安全风险通告  
原创 360漏洞研究院  360漏洞研究院   2025-07-16 11:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5nNKGRl7pFgbJxnOxcKdRicA5Vlgv8VdjNEa8tGFyzVgC6Q6dlYR7JSnqNf6hodTZqXAibl0ZqFHlNgZKH8hT2jQ/640?wx_fmt=gif&from=appmsg "")  
  
  
<table><tbody><tr style="box-sizing: border-box;"><td colspan="4" data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;background-color: rgb(100, 130, 228);box-sizing: border-box;padding: 0px;"><section style="text-align: center;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞概述</span></strong></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="24.0000%" width="24.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞名称</span></strong></p></section></td><td colspan="3" data-colwidth="76.0000%" width="76.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="word-break: break-all;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">VMware VMXNET3/PVSCSI/VMCI/Tools组件高危漏洞</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="24.0000%" width="24.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞编号</span></strong></p></section></td><td colspan="3" data-colwidth="76.0000%" width="76.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">CVE-2025-41236</span></p><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">CVE-2025-41237</span></p><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">CVE-2025-41238</span></p><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">CVE-2025-41239</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="24.0000%" width="24.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">公开时间</span></strong></p></section></td><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">2025-07-15</span></p></section></td><td data-colwidth="28.0000%" width="28.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span style="color: rgb(0, 0, 0);box-sizing: border-box;"><span leaf="">POC状态</span></span></strong></p></section></td><td data-colwidth="18.0000%" width="18.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">未公开</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="24.0000%" width="24.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">漏洞类型</span></strong></p></section></td><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="word-break: break-all;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">整数溢出/堆溢出</span></p></section></td><td data-colwidth="28.0000%" width="28.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">EXP状态</span></strong></p></section></td><td data-colwidth="18.0000%" width="18.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">未公开</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="24.0000%" width="24.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span style="color: rgb(0, 0, 0);box-sizing: border-box;"><span leaf="">利用可能性</span></span></strong></p></section></td><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">高</span></p></section></td><td data-colwidth="28.0000%" width="28.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;color: rgb(0, 0, 0);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">技术细节状态</span></strong></p></section></td><td data-colwidth="18.0000%" width="18.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">未公开</span></p></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="24.0000%" width="24.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">CVSS 3.1</span></strong></p></section></td><td data-colwidth="30.0000%" width="30.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">9.3</span></p></section></td><td data-colwidth="28.0000%" width="28.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;color: rgb(0, 0, 0);padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">在野利用状态</span></strong></p></section></td><td data-colwidth="18.0000%" width="18.0000%" style="border-width: 1px;border-color: rgb(100, 130, 228);border-style: solid;box-sizing: border-box;padding: 0px;"><section style="font-size: 12px;padding: 0px 8px;box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">未发现</span></p></section></td></tr></tbody></table>  
  
  
**01**  
  
影响组件  
  
  
  
VMware ESXi  
  
VMware Workstation Pro  
  
VMware Fusion  
  
VMware Tools  
  
VMware Cloud Foundation  
  
VMware vSphere Foundation  
  
VMware Telco Cloud Platform  
  
VMware Telco Cloud Infrastructure  
  
  
**02**  
  
**漏洞描述**  
  
  
  
2025年7月15日，VMware发布安全公告VMSA-2025-0013，公告中披露了3个由Pwn2Own参赛者发现并报告的高危漏洞：  
  
  
CVE-2025-41236（VMXNET3整数溢出漏洞）  
  
虚拟机本地管理员可通过构造恶意数据触发主机代码执行（仅影响使用VMXNET3适配器的VM）  
  
  
CVE-2025-41237（VMCI整数下溢漏洞）  
  
越界写入可导致ESXi沙箱逃逸（Workstation/Fusion可能实现宿主机RCE）  
  
  
CVE-2025-41238（PVSCSI堆溢出漏洞）  
  
特殊配置下可能绕过ESXi沙箱限制（Workstation/Fusion风险同41237）  
  
  
经360漏洞研究院团队对上述漏洞进行进一步分析，发现相关漏洞均属于内存安全问题，最终都可能导致越界写入（Out-of-bounds Write）。具有虚拟机本地管理员权限的攻击者成功利用可能实现从虚拟机到主机的权限提升，突破虚拟化隔离。  
  
  
本次公告同时披露了CVE-2025-41239（VMware Tools权限提升漏洞）  
  
VMware Tools中存在权限提升漏洞，该漏洞允许具有虚拟机内有限权限的攻击者执行特权操作。此漏洞主要影响Windows和Linux平台上的VMware Tools，攻击者可以通过利用VMware Tools中的不安全文件处理机制，在虚拟机环境内修改关键文件或执行未授权操作。  
  
  
**03**  
  
**漏洞影响范围******  
  
  
  
VMware ESXi：  
  
8.0版本 < ESXi80U3f-24784735或ESXi80U2e-24789317  
  
7.0版本 < ESXi70U3w-24784741  
  
  
VMware Workstation Pro：  
  
17.x版本 < 17.6.4版本  
  
  
VMware Fusion：  
  
13.x版本 < 13.6.4版本  
  
  
VMware Cloud Foundation：  
  
5.x（需应用ESXi80U3f-24784735异步补丁）  
  
4.5.x（需应用ESXi70U3w-24784741异步补丁）  
  
  
**04**  
  
**修复建议******  
  
  
  
**正式防护方案**  
  
Broadcom已发布补丁修复相关漏洞  
  
VMware ESXi：  
  
8.0版本（需更新至ESXi80U3f-24784735或ESXi80U2e-24789317）  
  
https://support.broadcom.com/web/ecx/solutiondetails?patchId=15938  
  
https://support.broadcom.com/web/ecx/solutiondetails?patchId=15939  
  
  
7.0版本（需更新至ESXi70U3w-24784741）  
  
https://support.broadcom.com/web/ecx/solutiondetails?patchId=15940  
  
  
VMware Workstation Pro：  
  
17.x版本（需更新至17.6.4）  
  
https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Workstation%20Pro&freeDownloads=true  
  
  
VMware Fusion：  
  
13.x版本（需更新至13.6.4）  
  
https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Fusion&freeDownloads=true  
  
  
VMware Cloud Foundation：  
  
5.x（需应用ESXi80U3f-24784735异步补丁）  
  
4.5.x（需应用ESXi70U3w-24784741异步补丁）  
  
  
**临时缓解措施**  
  
1. 配置防火墙规则，限制对VMware相关服务的访问。只允许受信任的IP地址和端口进行连接，减少攻击面。  
  
2. 部署IDS/IPS设备，实时监测网络流量，及时发现并阻止针对VMware漏洞的攻击行为。  
  
3. 对于Workstation和Fusion用户，避免从不受信任的来源运行虚拟机。  
  
  
**05**  
  
**时间线**  
  
  
  
2025年7月15日，VMware发布公告。  
  
2025年7月16日，360漏洞研究院发布本安全风险通告。  
  
  
**06**  
  
参考链接  
  
  
  
https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/35877  
  
https://secalerts.co/vulnerability/CVE-2025-41236  
  
https://cve.akaoma.com/cve-2025-41236  
  
  
**07**  
  
更多漏洞情报  
  
  
  
建议您订阅360数字安全-漏洞情报服务，获取更多漏洞情报详情以及处置建议，让您的企业远离漏洞威胁。  
  
  
邮箱：360VRI@360.cn  
  
网址：https://vi.loudongyun.360.net  
  
  
  
“洞”悉网络威胁，守护数字安全  
  
  
**关于我们**  
  
  
360 漏洞研究院，隶属于360数字安全集团。其成员常年入选谷歌、微软、华为等厂商的安全精英排行榜, 并获得谷歌、微软、苹果史上最高漏洞奖励。研究院是中国首个荣膺Pwnie Awards“史诗级成就奖”，并获得多个Pwnie Awards提名的组织。累计发现并协助修复谷歌、苹果、微软、华为、高通等全球顶级厂商CVE漏洞3000多个，收获诸多官方公开致谢。研究院也屡次受邀在BlackHat，Usenix Security，Defcon等极具影响力的工业安全峰会和顶级学术会议上分享研究成果，并多次斩获信创挑战赛、天府杯等顶级黑客大赛总冠军和单项冠军。研究院将凭借其在漏洞挖掘和安全攻防方面的强大技术实力，帮助各大企业厂商不断完善系统安全，为数字安全保驾护航，筑造数字时代的安全堡垒。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5nNKGRl7pFjg8qMb2BUlECEwwBJIpZCcBTOdeCNVicqZuIqHmqRJgcRpD7ia9eTcQIbdNYWo3vnTHCiaXNvpPxF9Q/640?wx_fmt=gif&from=appmsg "")  
  
  
  
“扫描上方二维码，进入公众号粉丝交流群。更多一手网安咨询、漏洞预警、技术干货和技术交流等您参与！”  
  
  
  

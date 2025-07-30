#  或致防火墙崩溃！SonicWall SonicOS 管理访问和 SSLVPN 中存在访问控制不当漏洞   
 安全客   2024-09-09 15:07  
  
SonicWall 透露，最近修补的一个影响 SonicOS 的关键安全漏洞可能已被利用，敦促用户尽快应用补丁。  
  
  
该漏洞被跟踪为 CVE-2024-40766，CVSS 评分为9.3分。  
  
  
SonicWall 在更新的公告中表示：“在 SonicWall SonicOS 管理访问和 SSLVPN 中发现了一个不当的访问控制漏洞，可能导致未经授权的资源访问，并在特定条件下，导致防火墙崩溃。”  
  
  
最新发展显示，CVE-2024-40766 还影响了防火墙的 SSLVPN 功能。该问题已在以下版本中得到解决：  
  
  
  
SOHO（第五代防火墙） - 5.9.2.14-13o  
  
  
第六代防火墙 - 6.5.2.8-2n（适用于 SM9800、NSsp 12400 和 NSsp 12800）以及 6.5.4.15.116n（适用于其他第六代防火墙设备）  
  
  
网络安全供应商更新了公告，反映出该漏洞可能已被积极利用。  
  
  
“该漏洞可能正在被利用”，公告中补充道，“请尽快为受影响的产品应用补丁。”  
  
  
作为临时解决方案，建议将防火墙管理限制为可信源，或禁用防火墙的 WAN 互联网管理功能。对于 SSLVPN，建议将访问限制为可信源，或完全禁用互联网访问。  
  
  
其他缓解措施包括为所有 SSLVPN 用户启用多因素认证（MFA），使用一次性密码（OTP），并建议使用 GEN5 和 GEN6 防火墙的客户立即更新具有本地管理帐户的 SSLVPN 用户密码，以防止未经授权的访问。  
  
  
文章来源：  
  
https://thehackernews.com/2024/09/sonicwall-urges-users-to-patch-critical.html  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb40iadOocMbiaicpoyTribgia0m6uuNibZ9uFvy6hPCPHz9ct62T8E5QInBTVOywhSYQKRWsja5iaPk4S7mg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb40iadOocMbiaicpoyTribgia0m6lF6VkiavRlk98GLnp8qFbfjXuLrjiboQxzu5P5WicWH7c4GmxpKlHFPXg/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  

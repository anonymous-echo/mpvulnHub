#  Rockwell PowerMonitor 漏洞允许远程黑客攻击工业系统   
会杀毒的单反狗  军哥网络安全读报   2024-12-21 01:01  
  
**导****读**  
  
  
  
罗克韦尔自动化公司修补的 Allen-Bradley PowerMonitor 1000 产品中的严重漏洞可能允许远程黑客侵入工业系统并造成破坏或获得进一步的访问权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaE8jgaibPKYUDalMTcm8Y2jgOR4nRmR27wdEWfVq51HQNmFPuyyL95GQxl8gdiaLHT9XeNOOUOZSicyg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
本周，罗克韦尔自动化和网络安全机构CISA发布安全公告，这些漏洞的存在被曝光。  
  
  
PowerMonitor 1000 是一款紧凑型电力监测器，用于负载分析、成本分配和能源控制。该设备可与其他能源监测系统集成，并可轻松与其他 Rockwell 工业控制系统 (ICS) 通信。  
  
  
电源监视器中发现了三个漏洞，每个漏洞的严重程度评级均为“严重”。其中之一 CVE-2024-12371 被描述为设备接管问题。  
  
  
Rockwell 在其公告中解释道：“此漏洞允许配置新的保单持有人用户，而无需通过 API 进行任何身份验证。保单持有人用户是最高权限用户，可以执行编辑操作、创建管理员用户和执行恢复出厂设置。”  
  
  
第二个漏洞 CVE-2024-12372 可用于发起 DoS 攻击，甚至可用于远程代码执行；第三个漏洞 CVE-2024-12373 可用于发起 DoS 攻击。  
  
  
这些安全漏洞影响运行包含补丁的 4.020 之前版本固件的 PowerMonitor 1000 设备。  
  
  
工业和物联网网络安全公司 Claroty 的 Team82 安全研究员 Vera Mens 向罗克韦尔披露这些漏洞，研究人员使用网络扫描服务发现了数十个暴露在互联网上的易受攻击的 PowerMonitor 设备。  
  
  
“我们强烈建议资产所有者及时更新固件，以确保全面保护。”Mens 说。  
  
  
研究人员指出，利用这些漏洞不需要任何身份验证——攻击者可以在获得目标组织内部网络的访问权限后攻击设备，或者在设备暴露于互联网的情况下直接从网络攻击设备。  
  
  
“利用这些漏洞可能会造成多种影响，包括拒绝服务、绕过身份验证和远程代码执行。例如，用于监控制造环境中用电量的设备（如 PowerMonitor 1000）上的拒绝服务可能会通过阻止对能耗的准确跟踪来破坏供应链，最终导致生产停止。”Mens 解释道。  
  
  
研究人员补充道：“此外，远程代码执行可能让攻击者完全控制设备，从而可能危及整个网络。”  
  
  
Rockwell  
官方漏洞公告：  
  
https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1714.html  
  
  
新闻链接：  
  
https://www.securityweek.com/rockwell-powermonitor-vulnerabilities-allow-remote-hacking-of-industrial-systems/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  

#  CISA 确认勒索软件攻击利用了关键的 Cleo 漏洞   
会杀毒的单反狗  军哥网络安全读报   2024-12-14 01:00  
  
**导****读**  
  
  
  
  
CISA 证实，Cleo Harmony、VLTrader 和 LexiCom 文件传输软件中的一个严重安全漏洞正被勒索软件攻击所利用。  
  
  
该漏洞编号为 CVE-2024-50623，影响 5.8.0.21 之前的所有版本。漏洞可使未经身份验证的攻击者在网上暴露的易受攻击的服务器上进行远程代码执行。  
  
  
Cleo 于 10 月份发布了安全更新来修复该问题，并警告所有客户“立即升级实例”以防范更多潜在攻击。  
  
  
该公司尚未披露 CVE-2024-50623 是否在野遭到攻击；然而，周五，CISA将该安全漏洞添加到其已知被利用漏洞目录中，并将其标记为用于勒索软件活动。  
  
  
虽然该网络安全机构没有提供关于针对易受 CVE-2024-50623 漏洞攻击的 Cleo 服务器的勒索软件活动的任何其他信息，但这些攻击与近年来利用MOVEit Transfer、GoAnywhere MFT和Accellion FTA  
0day  
漏洞进行的Clop 数据盗窃攻击极为相似。  
  
  
一些人还认为该漏洞被 Termite 勒索软件行动所利用。然而，人们认为这种联系只是因为 Blue Yonder 有一个暴露的 Cleo 软件服务器，并且它们在勒索软件团伙声称发动的网络攻击中被攻破。  
  
### Cleo零日漏洞也被积极利用  
###   
  
正如 Huntress 安全研究人员十天前首次发现的那样，已全面修补的 Cleo 服务器仍然受到攻击，可能使用了 CVE-2024-50623 绕过（尚未收到 CVE ID），攻击者可以通过利用默认的 Autorun 文件夹设置来导入和执行任意 PowerShell 或 bash 命令。  
  
  
Cleo 现已发布补丁来修复此被积极利用的  
0day  
漏洞，并敦促客户尽快升级到 5.8.0.24 版本，以保护互联网暴露的服务器免遭攻击。  
  
  
该公司补充道：“应用补丁后，启动时发现的任何与此漏洞相关的文件都会被记录为错误，并且这些文件会被删除。”  
  
  
建议无法立即升级的管理员通过从系统选项中清除自动运行目录来禁用自动运行功能，以减少攻击面。  
  
  
Rapid7在调查  
0day  
攻击时发现，威胁组织利用  
0day  
漏洞释放了 Java 存档 (JAR) 负载，而该负载是一个基于 Java 的大型后利用框架的一部分。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFTEcTKicyLYxAzkewKP0nZYEg5q8kEtTWCmsMVR6KHbyZBvftLQDjuPU5GAA524xOM6NQXxnEUEkA/640?wx_fmt=png&from=appmsg "")  
  
Cleo 攻击流程（Rapid7）  
  
  
Huntress 也对该恶意软件进行了分析，并将其命名为 Malichus，他表示只发现该恶意软件部署在 Windows 设备上，尽管它也支持 Linux。  
  
  
据另一家调查正在进行的攻击的网络安全公司Binary Defense ARC Labs称，恶意软件操作员可以使用 Malichus 进行文件传输、命令执行和网络通信。  
  
  
到目前为止，Huntress 已发现至少有 20 多家公司的 Cleo 服务器遭到入侵，并表示可能还有其他潜在受害者。Sophos 的 MDR 和实验室团队还发现超过 50 台 Cleo 主机存在入侵迹象。  
  
  
技术报告：  
  
https://www.rapid7.com/blog/post/2024/12/11/etr-modular-java-backdoor-dropped-in-cleo-exploitation-campaign/  
  
https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis  
  
https://www.binarydefense.com/resources/blog/cleo-mft-mass-exploitation-payload-analysis/  
  
  
新闻链接：  
  
https://www.bleepingcomputer.com/news/security/cisa-confirms-critical-cleo-bug-exploitation-in-ransomware-attacks/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  

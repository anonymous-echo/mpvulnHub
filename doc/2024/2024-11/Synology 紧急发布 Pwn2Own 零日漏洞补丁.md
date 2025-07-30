#  Synology 紧急发布 Pwn2Own 零日漏洞补丁   
胡金鱼  嘶吼专业版   2024-11-12 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
网络附加存储 (NAS) 设备制造商 Synology 已修复了 Pwn2Own 黑客竞赛中被利用的两个关键零日漏洞。   
  
Midnight Blue 安全研究员在该公司的 Synology Photos 和 BeePhotos for BeeStation 软件中发现了关键的零点击漏洞（一起追踪为 CVE-2024-10443，并称为 RISK:STATION）。  
  
正如 Synology 在 Pwn2Own Ireland 2024 上演示这些漏洞劫持 Synology BeeStation BST150-4T 设备，两天后发布的安全公告中所解释的那样，这些安全漏洞使远程攻击者能够以 root 身份在在线暴露的易受攻击的 NAS 设备上获得远程代码执行。  
  
Midnight Blue 表示：“该漏洞最初是在几个小时内被发现的，作为另一个 Pwn2Own 提交的替代品。演示后立即向 Synology 披露了该问题，并在 48 小时内提供了解决该漏洞的补丁。”   
  
Synology 表示，它解决了以下软件版本中的漏洞；但是，它们不会自动应用于易受攻击的系统，建议客户尽快更新以阻止潜在的传入攻击：  
  
**·**BeePhotos for BeeStation OS 1.1：升级到1.1.0-10053或更高版本。  
  
**·**BeePhotos for BeeStation OS 1.0：升级到1.0.2-10026或更高版本。  
  
**·**Synology Photos 1.7 for DSM 7.2：升级到 1.7.0-0795 或更高版本。  
  
**·**Synology Photos 1.6 for DSM 7.2：升级到 1.6.2-0720 或更高版本。  
  
另一家 NAS 设备制造商 QNAP 在一周内修复了在黑客竞赛中被利用的两个更关键的零日漏洞（在该公司的 SMB 服务和混合备份同步灾难恢复和数据备份解决方案中）。  
  
虽然 Synology 和 QNAP 匆忙推出安全更新，但供应商有 90 天的时间可以更新。  
  
NAS 设备通常被家庭和企业客户用来存储敏感数据，并且它们也经常暴露在互联网上以进行远程访问。然而，这使得它们成为网络犯罪分子的目标，他们利用弱密码或漏洞来破坏系统、窃取数据、加密文件，并通过索要赎金来勒索所有者以提供对丢失文件的访问权限。  
  
Midnight Blue 安全研究人员在 Pwn2Own Ireland 2024 期间演示了 Synology 零日漏洞，他们在美国和欧洲的警察部门网络上发现了暴露于互联网的 Synology NAS 设备，以及来自韩国、意大利和加拿大的关键基础设施承包商。  
  
QNAP 和 Synology 多年来一直提醒客户，在线暴露的设备正在成为勒索软件攻击的目标。例如，eCh0raix 勒索软件（也称为 QNAPCrypt）于 2016 年 6 月首次出现，一直定期针对此类系统，其中 2019 年 6 月（针对 QNAP 和 Synology 设备）和 2020 年 6 月报告的两起大规模勒索软件尤为突出。  
  
在最近的攻击浪潮中，威胁者还使用其他恶意软件菌株，包括 DeadBolt 和 Checkmate 勒索软件，以及各种安全漏洞来加密暴露于互联网的 NAS 设备。  
  
参考及来源：https://www.bleepingcomputer.com/news/security/synology-fixed-two-critical-zero-days-exploited-at-pwn2own-within-days/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ictZicmnibYy2Ppib7oBydgWPBy7S8tTD3VpdvsECh1sZw3ibCCAD1po0tGic8pQ9QZ0CGkXiaMt18oicPiag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ictZicmnibYy2Ppib7oBydgWPB6g3AJuic9hAyoh1BQj3TOSmv7pck8hCt6FnKWODfHrayl6l8loiaV9uQ/640?wx_fmt=png&from=appmsg "")  
  
  

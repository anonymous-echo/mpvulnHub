> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493513&idx=1&sn=1ccc756f815c32f18e26fef511666ec0

#  漏洞预警 | Linux本地提权漏洞  
浅安  浅安安全   2025-06-26 00:00  
  
**0x00 漏洞编号**  
- CVE-2025-6019  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
udisks服务在多数Linux系统默认运行，提供存储管理的D-Bus接口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVAoKbq6tfnbjOfiatsfCEmOyPDQS02j738cKn0spGywiaRvplicbFfPd9ePpvialJicfWSLOcoLIGcwXw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-6019**  
  
**漏洞类型：**  
本地提权  
  
**影响：**  
提升权限  
  
**简述：**  
Linux存在本地权限提升漏洞，由于udisks守护进程挂载文件系统中会调用libblockdev库，而libblockdev挂载时没有使用nosuid和nodev标志，致使拥有“allow_active”权限的用户可利用此漏洞获取root权限。  
  
**0x04 影响版本**  
- Ubuntu、Debian、Fedora、openSUSE等主流发行版  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://github.com/storaged-project/libblockdev  
  
  
  

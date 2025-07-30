#  【漏洞通告】Arm Mali GPU Kernel Driver释放后使用漏洞安全风险通告   
 嘉诚安全   2024-06-12 16:48  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Arm发布Mali GPU驱动程序安全公告，披露了Bifrost和Valhall GPU内核驱动程序中的一个释放后使用漏洞，漏洞编号为：CVE-2024-4610，目前该漏洞已发现被  
**在野利用**。  
  
  
Arm是一家全球知名的芯片架构设计公司，Arm Mali GPU是ARM公司推出的高性能图形处理器（GPU）系列，具有卓越的性能、高效能电源管理和广泛的应用场景。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**漏洞。本地非特权用户可以执行不正确的GPU内存处理操作来访问已释放的内存，成功利用该漏洞可能导致信息泄露或任意代码执行。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响范围  
  
Arm Bifrost GPU Kernel Driver 34p0 - r40p0  
  
Arm Valhall GPU Kernel Driver r34p0 - r40p0  
  
注：基于 Bifrost 的 Mali GPU 用于智能手机/平板电脑（G31、G51、G52、G71 和 G76）、单板计算机、Chromebook和各种嵌入式系统；Valhall GPU 应用于采用 Mali G57 和 G77 等芯片的高端智能手机/平板电脑、汽车信息娱乐系统和高性能智能电视。  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可升级到Bifrost 和 Valhall GPU 内核驱动程序 r41p0或更高版本。  
  
下载链接：  
  
https://developer.arm.com/downloads/-/mali-drivers/  
  
参考链接：  
  
https://developer.arm.com/Arm%20Security%20Center/Mali%20GPU%20Driver%20Vulnerabilities  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-4610  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  

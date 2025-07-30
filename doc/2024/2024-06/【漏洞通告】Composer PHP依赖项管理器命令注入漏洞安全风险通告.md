#  【漏洞通告】Composer PHP依赖项管理器命令注入漏洞安全风险通告   
 嘉诚安全   2024-06-14 13:17  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Composer中存在一个PHP依赖项管理器命令注入漏洞，漏洞编号为：CVE-2024-35242。  
  
  
Composer是PHP开发领域中最受欢迎的依赖项管理工具之一，使PHP开发者能够轻松地管理项目中的依赖关系，并确保这些依赖项在不同环境中的一致性和可用性。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**漏洞。在版本2.2.24和2.7.7之前的2.x分支上，在具有特制分支名称的git/hg存储库中运行的“composer install”命令可能会导致命令注入。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响范围  
  
2.0 <= Composer < 2.2.24  
  
2.3 <= Composer < 2.7.7  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
官方已发布修复方案，受影响的用户建议更新至安全版本。  
  
参考链接：  
  
https://github.com/composer/composer/security/advisories/GHSA-v9qv-c7wm-wgmf  
  
https://github.com/composer/composer/commit/6bd43dff859c597c09bd03a7e7d6443822d0a396  
  
https://github.com/composer/composer/commit/fc57b93603d7d90b71ca8ec77b1c8a9171fdb467  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  

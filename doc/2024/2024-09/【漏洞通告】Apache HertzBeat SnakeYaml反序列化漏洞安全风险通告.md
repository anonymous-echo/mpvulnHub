#  【漏洞通告】Apache HertzBeat SnakeYaml反序列化漏洞安全风险通告   
 嘉诚安全   2024-09-26 10:47  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Apache HertzBeat中修复SnakeYaml反序列化漏洞，漏洞编号为：CVE-2024-42323。  
  
  
Apache HertzBeat (incubating)是一个易于使用的开源实时监控系统，具有无代理（Agentless）、高性能集群、兼容prometheus、提供强大的自定义监控和状态页面构建功能。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞。在受影响版本中，由于使用了存在漏洞的SnakeYaml解析库，可能导致经过身份验证的攻击者通过恶意YAML配置文件（被HertzBeat用于定义监控类型或其他关键配置）触发反序列化漏洞，从而导致远程代码执行。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Apache HertzBeat < 1.6.0  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可升级到Apache HertzBeat 1.6.0或更高版本。  
  
下载链接：  
  
https://github.com/apache/hertzbeat/releases  
  
参考链接：  
  
https://lists.apache.org/thread/dwpwm572sbwon1mknlwhkpbom2y7skbx  
  
https://github.com/apache/hertzbeat/pull/1239  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  

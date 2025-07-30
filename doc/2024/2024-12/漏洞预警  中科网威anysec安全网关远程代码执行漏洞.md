#  漏洞预警 | 中科网威anysec安全网关远程代码执行漏洞   
浅安  浅安安全   2024-12-24 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
中科网威ANYSEC安全网关基于Linux平台自主研发生产，集上网行为管理、流量监控、防火墙、VPN、路由交换、多线路负载均衡等多功能于一体，是一种在线部署于局域网与广域网之间的All in One式的多功能高性能流量监控、管理与优化的设备。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXnntOIXgZRibKgBXy9W9U6P9hohEbN3WicITCypwMFjJw6EOy7QXEeUaFzWTyyvnyfZCIVXuyIejicg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
远程代码执行  
  
  
**影响：**  
  
执行任意代码  
  
**简述：**  
中科网威ANYSEC安全网关的/cgi-bin/system/arping.cgi接口存在远程代码执行漏洞，经过授权的攻击者可以通过该漏洞执行任意代码，从而控制目标服务器。  
  
**0x04 影响版本**  
- 中科网威ANYSEC安全网关  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://netpower.com.cn/  
  
  
  

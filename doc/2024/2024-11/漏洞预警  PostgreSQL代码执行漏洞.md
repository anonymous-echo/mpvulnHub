#  漏洞预警 | PostgreSQL代码执行漏洞   
浅安  浅安安全   2024-11-22 23:50  
  
**0x00 漏洞编号**  
- # CVE-2024-10979  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
PostgreSQL是一个免费的对象-关系数据库服务器，它的Slogan是“世界上最先进的开源关系型数据库”。它具有强大的功能、稳定的性能、高度的可扩展性和丰富的数据类型。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWicwkicszFczgBVUWTG428aXDjzMCqFFvKictwG9n2VSjo9Nq0uYibkxMNt7haIygbSfOQsPx2oRxLZA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-10979**  
  
**漏洞类型：**  
代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
PostgreSQL中存在代码执行漏洞，当PL/Perl扩展被安装并启用时，由于PL/Perl扩展未能正确控制环境变量，导致非特权数据库用户可以修改敏感的进程环境变量，并可能利用该漏洞执行任意代码、获得对数据库服务器的未授权访问权限，或者执行数据窃取、数据篡改或破坏等恶意操作。  
###   
  
**0x04 影响版本**  
- PostgreSQL 17 < 17.1  
  
- PostgreSQL 16 < 16.5  
  
- PostgreSQL 15 < 15.9  
  
- PostgreSQL 14 < 14.14  
  
- PostgreSQL 13 < 13.17  
  
- PostgreSQL 12 < 12.21  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.postgresql.org/  
  
  
  

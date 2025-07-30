#  【情报】CVE出现罕见的10.0评分漏洞，SAP NetWeaver存在RCE漏洞   
原创 visionsec  安全视安   2025-05-01 05:21  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF7ib5zib7TvpCSWM83gMQaZL5Shia0IXV5VicXPJBibC8fk78hmjUZXQkh2ZFmamym85ZPeobk5j3fZJXw/640?wx_fmt=png&from=appmsg "")  
##   
## 漏洞概述  
  
SAP NetWeaver Visual Composer的Metadata Uploader模块缺失必要的授权校验，攻击者可通过未经身份验证的POST请求向/developmentserver/metadatauploader  
端点上传任意可执行文件，进而实现远程代码执行  
国家漏洞数据库  
。该漏洞于2025年4月24日由SAP官方公开，并获得CVSS v3.1最高分10.0（Critical）  
国家漏洞数据库  
。  
## 背景  
### 产品简介  
  
Visual Composer是SAP NetWeaver Application Server Java（AS Java）中的一个可视化开发组件，帮助非程序员用户快速构建业务界面和应用逻辑  
。  
### 漏洞来源  
  
该漏洞由ReliaQuest率先发现，其在Metadata Uploader服务中未对上传请求做任何授权检查，导致任何网络可达的攻击者都可绕过认证机制进行文件上传  
。  
## 漏洞细节  
- **受影响版本**  
：Visual Composer 7.50及之前版本（默认安装即启用该组件）  
。  
  
- **攻击向量**  
：网络可达，无需用户交互或先验凭据，直接发送精心构造的HTTP POST请求即可   
。  
  
- **利用过程**  
：攻击者向/developmentserver/metadatauploader  
上传JSP、WAR或其他可执行二进制文件，服务器在未做权限校验的情况下接收并存放于Web可访问目录，随后可直接访问以触发代码执行  
。  
  
- **CVE评分**  
：10.0/10.0（AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H）国家漏洞数据库  
。  
  
## 在野利用  
  
自漏洞公开以来，多个初始访问经纪（Initial Access Broker）和勒索软件团伙已将其纳入攻击工具箱，短短五天内便出现大规模利用趋势  
。安全厂商Rapid7和Red Canary均报告了真实攻击案例，受影响范围涵盖全球主要SAP部署环境，尤其是在中国与美国使用量较大的地区  
。  
## 检测与常见利用手法  
### 常见检测指标  
1. **异常HTTP请求日志**  
：检测指向/developmentserver/metadatauploader  
的未经授权的POST上传请求  
。  
  
1. **新增可执行文件**  
：监控Web目录下突增的.jsp  
、.war  
等可执行文件或不常见的脚本文件  
。  
  
1. **命令执行痕迹**  
：结合WAF/IDS规则，拦截Payload中包含典型反弹Shell或命令注入特征的流量  
。  
  
### 利用技巧提示  
- **路径Fuzzing**  
：部分实例可能对上传路径做了二次封装，建议使用路径Fuzz工具（如ffuf、dirbuster）枚举隐藏的上传目录Rapid7  
。  
  
- **WebShell爆破**  
：在知道他人已利用该漏洞上传WebShell时，可尝试对常见目录与文件名进行爆破，快速获取已存在的后门文件  
。  
  
CVE-2025-31324作为高危漏洞，其“无认证文件上传→RCE”链路十分直接，且已在全球范围内被黑产组织大规模利用。各组织务必以最快速度完成补丁部署与访问控制加固，同时结合日志监控与威胁情报分享，降低潜在风险。  
  

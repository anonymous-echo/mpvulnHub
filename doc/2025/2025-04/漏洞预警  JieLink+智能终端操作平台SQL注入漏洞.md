#  漏洞预警 | JieLink+智能终端操作平台SQL注入漏洞   
浅安  浅安安全   2025-04-19 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
捷顺JeLink+智能终端操作平台是捷顺历经多年行业经验积累，集智能硬件技术视频分析技术、互联网技术等多种技术融合，基于B/S架构，实现核心业务处理模型的搭建;基于C/S架构实现岗亭收费、收费、自助服务，满足车场收费车辆特征分析处理、当班管理、业务托管、信息上报等现场业务处理。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUG0yRG5TYGsV97zmdJJT4Bzk3aUz7ww8rwxVx9PdgeuOV77LVicfFUV6sLZUBkewrQKXTUcNzN72g/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
### 漏洞类型：SQL注入  
  
**影响：**  
获取  
敏感信息  
  
  
  
**简述：**  
捷顺JeLink+的  
/project/IPPool/DeleteIpPool接口存在SQL注入漏洞，未授权的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 捷顺JeLink+  
  
**0x05****POC状态**  
- **已公开**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.jieshun.cn/  
  
  
  

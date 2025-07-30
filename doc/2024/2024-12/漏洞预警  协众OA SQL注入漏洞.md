#  漏洞预警 | 协众OA SQL注入漏洞   
浅安  浅安安全   2024-12-25 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
协众OA是广州协众软件科技有限公司推出的一款基于PHP技术开发，具有高度定制化、灵活性强、安全性能高的特点，涵盖协同办公、工作流程管理、人事管理等多种功能，兼容多终端的协同办公管理软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXd5rQAPl8GzXqo3qnqlr1EJng9E7wbVQJZQLfMTnsNZFgajG1Z6qyuewwkS3aYltlHTPkrPp9yBw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
协众OA的checkLoginQrCode接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用SQL注入漏洞获取数据库中的信息之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
**0x04 影响版本**  
- 协众OA < 6.0.2  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.cnoa.cn/  
  
  
  

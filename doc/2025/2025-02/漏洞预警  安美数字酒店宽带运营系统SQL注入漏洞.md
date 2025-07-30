#  漏洞预警 | 安美数字酒店宽带运营系统SQL注入漏洞   
原创 安全笔记  安全笔记   2025-02-21 06:13  
  
### 0x00 漏洞编号  
  
•  
暂无  
### 0x01 危险等级  
  
•  
高危  
### 0x02 漏洞概述  
  
安美数字酒店宽带运营系统是通过提供系统数据分析报表和带宽动态管理功能来确保在有限的资源内优化上网体验并改善服务质量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdye1iaJPF7eicIFtWzDlHvPy1L6bic1DwldHFyPiaKsgickUvfc8Oib9FFUIpW5sMubhleqYfORKicjsw7JQ/640?wx_fmt=png&from=appmsg "null")  
### 0x03 漏洞详情  
  
**漏洞类型：**SQL注入  
  
**影响：**获取敏感信息  
  
**简述：**安美数字酒店宽带运营系统的list_qry.php接口处存在SQL注入漏洞，未经身份验证的恶意攻击者利用SQL注入漏洞获取数据库中的信息之外，甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
### 0x04 影响版本      
  
•安美数字酒店宽带运营系统  
### 0x05 POC  
  
•  
暂未公开  
### 0x06 修复建议  
  
目前官方暂未发布漏洞修复版本，建议用户后续升级到安全版本。  
  

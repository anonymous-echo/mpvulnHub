#  漏洞预警 | JeecgBoot任意文件上传漏洞   
浅安  浅安安全   2024-05-01 08:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
JeecgBoot是一款基于代码生成器的低代码开发平台。前后端分离架构 SpringBoot2.x，SpringCloud，Ant Design&Vue，Mybatis-plus，Shiro，JWT，支持微服务。强大的代码生成器让前后端代码一键生成，实现低代码开发。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SW25cvic5s59KsEGyS6fTiaaogPXrsntzHQO87dEEoxdTnicwvibHLUm8wvIaRo5oQWGzJqicZPr2Q7G9w/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
文件上传  
  
**影响：**  
控制服务器  
  
**简述：**  
Jeecg-Boot存在任意文件上传漏洞，未授权的攻击者可以通过该漏洞上传恶意脚本文件到服务器，从而控制服务器。  
###   
  
**0x04 影响版本**  
- Jeecg-Boot  
  
**0x05****POC**  
  
https://github.com/zan8in/afrog/blob/3f4a033a359cad6385d3e33d01049349e49bcdbf/pocs/afrog-pocs/vulnerability/jeecgboot-commoncontroller-parserxml-fileupload.yaml  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.jeecg.com/  
  
  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493785&idx=2&sn=b6d7880ae3a645643d60d6269ee37cb3

#  漏洞预警 | 汉王e脸通智慧园区管理平台任意文件上传漏洞  
浅安  浅安安全   2025-07-19 00:02  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
汉王e脸通综合管理平台是一个集生物识别、大数据、NFC射频、计算机网络、自动控制等技术于一体，通过“人脸卡”及关联信息实现多种功能智能管理，打造从云端到终端一体化应用，广泛应用于智慧园区、社区、工地等领域的综合管理平台。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXBWzKcPxKTbCAudbicoRhD4DILaNMD6D6qnttU3p7KPq7VzXMGBA3uxvhiaM8SQo0jqEEWicZX6JqQA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
任意文件上传  
  
**影响：**  
上传恶意脚本  
  
**简述：**  
汉王e脸通综合管理平台的  
/manage/visitorMapConfig/updateVisitorMapConfig.do  
接口存在任意文件上传漏洞，未经身份验证的攻击者可以通过该漏洞上传恶意脚本文件，从而控制目标服务器。  
  
**0x04 影响版本**  
- 汉王e脸通综合管理平台  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://hwzy99.com/  
  
  
  

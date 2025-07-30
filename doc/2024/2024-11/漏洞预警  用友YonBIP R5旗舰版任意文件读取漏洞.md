#  漏洞预警 | 用友YonBIP R5旗舰版任意文件读取漏洞   
浅安  浅安安全   2024-11-21 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
用友YonBIP R5旗舰版是用友网络科技股份有限公司推出的一款企业级管理软件，广泛应用于大中型企业的资源管理、数据分析和业务流程自动化等领域。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUTGsZpt8BLQXKl46W7WYicRHeDxNS4IiaiaVbAG4TqvZrjMGeYHicxPsuZuNOeCKxc2AQeajFIHtic4Cg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息  
  
**简述：**  
用友YonBIP R5旗舰版的/iuap-apcom-workbench/ucf-wh/yonbiplogin/接口处存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取大量敏感信息。  
###   
  
**0x04 影响版本**  
- YonBIP V3.0(R5_2312)  
  
- YonBIP V3.0(R5_2312_SP240517)  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.yonyou.com/  
  
  
  

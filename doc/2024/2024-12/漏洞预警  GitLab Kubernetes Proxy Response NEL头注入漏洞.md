#  漏洞预警 | GitLab Kubernetes Proxy Response NEL头注入漏洞   
浅安  浅安安全   2024-12-20 00:02  
  
**0x00 漏洞编号**  
- CVE-2024-11274  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
GitLab是一个用于仓库管理系统的开源项目，其使用Git作为代码管理工具，可通过Web界面访问公开或私人项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWurkicwgzOT4LeOPBpry1N5ugc3t7jF2S3qXGNeicXtdSxC1YB5a1Gnrniar8VV7TVtDoH5D9TYSw2g/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-11274**  
  
**漏洞类型：**  
NEL头注入  
  
**影响：**  
未授权访问  
  
**简述：**  
GitLab存在Kubernetes Proxy Response NEL头注入漏洞，由于GitLab CE/EE中的Kubernetes代理功能未正确处理或验证注入的Network Error Logging头，攻击者可通过在Kubernetes代理响应中注入恶意NEL标头， 成功利用该漏洞可能导致会话相关数据泄露，这些数据可能被滥用来进行账户接管，从而实现未授权访问和控制用户账户。  
  
**0x04 影响版本**  
- 16.1 <= GitLab CE/EE < 17.4.6  
  
- 17.5 <= GitLab CE/EE < 17.5.4  
  
- 17.6 <= GitLab CE/EE < 17.6.2  
  
**0x05****POC状态**  
  
**未公开**  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://about.gitlab.com/  
  
  
  

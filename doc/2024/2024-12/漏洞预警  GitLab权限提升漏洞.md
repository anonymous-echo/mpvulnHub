#  漏洞预警 | GitLab权限提升漏洞   
浅安  浅安安全   2024-12-05 00:03  
  
**0x00 漏洞编号**  
- CVE-2024-8114  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
GitLab是一个用于仓库管理系统的开源项目，其使用Git作为代码管理工具，可通过Web界面访问公开或私人项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWurkicwgzOT4LeOPBpry1N5ugc3t7jF2S3qXGNeicXtdSxC1YB5a1Gnrniar8VV7TVtDoH5D9TYSw2g/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-8114**  
  
**漏洞类型：**  
权限提升  
  
**影响：**  
泄露敏感信息  
  
**简述：**  
GitLab存在权限提升漏洞，由于GitLab中对LFS令牌的权限管理不当，当攻击者获取目标用户的个人访问令牌后，可以进一步滥用该PAT生成的LFS令牌，利用该漏洞实现权限提升，从而可能导致敏感信息泄露或执行未授权操作。  
  
**0x04 影响版本**  
- 8.12 <= GitLab CE/EE < 17.4.5  
  
- 17.5 <= GitLab CE/EE < 17.5.3  
  
- 17.6 <= GitLab CE/EE < 17.6.1  
  
**0x05****POC状态**  
  
****- **未公开**  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://about.gitlab.com/  
  
  
  

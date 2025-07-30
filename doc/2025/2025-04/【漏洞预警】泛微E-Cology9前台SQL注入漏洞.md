#  【漏洞预警】泛微E-Cology9前台SQL注入漏洞   
cexlife  飓风网络安全   2025-04-14 13:43  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu03S6odjmSibEiadyjTX8JImwCvH4vUAW1kBB22jsCXQ61jtYID052KVNSf1hrkZ864WyYU1Vk4XWzzg/640?wx_fmt=png&from=appmsg "")  
  
产品介绍:  
  
泛微e-cology是一款由泛微网络科技开发的协同管理平台，支持人力资源、财务、行政等多功能管理和移动办公。  
  
漏洞描述:  
  
该漏洞是由于泛微e-cology未对用户的输入进行有效的过滤,直接将其拼接进了SQL查询语句中,导致系统出现 SQL 注入漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu03S6odjmSibEiadyjTX8JImwClFaf8rYxZf5YtqVibibZrrmbMpB16kFvkjt1RaqUOckc3uiaWP5Z3uB6w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu03S6odjmSibEiadyjTX8JImwCZXeCMSPibw8ViaQBM5aC4xb1ia5oPTe9RzMcOgLbRWtibY8e6H6C6S5HXA/640?wx_fmt=png&from=appmsg "")  
  
漏洞影响:  
  
攻击者可利用此漏洞获取敏感信息，进一步利用可能获取目标系统权限。  
  
影响版本:  
  
e-cology 9 < v10.74  
  
漏洞修复建议:  
  
官方已发布升级补丁包，支持在线升级和离线补丁安装。  
  
https://www.weaver.com.cn/cs/securityDownload.html?src=cn  
  
  

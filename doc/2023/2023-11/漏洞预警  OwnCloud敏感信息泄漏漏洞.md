#  漏洞预警 | OwnCloud敏感信息泄漏漏洞   
浅安  浅安安全   2023-11-25 09:03  
  
**0x00 漏洞编号**  
- # CVE-2023-49103  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
OwnCloud是一款开源软件，它简化了创建和使用文件管理服务的过程，适用于希望自己管理云存储的用户。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUkgWHnZO6mDZiaWyGJ899SS1X88ahWzvic11RpYZkib6V7YvLn7oAE9mH8ziaTnXgarwhtZ9POZbOy3A/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2023-49103**  
  
**漏洞类型：**  
信息泄漏  
  
**影响：**  
接管服务  
  
  
**简述：**  
ownCloud owncloud/graphapi 0.2.x在0.2.1之前和0.3.x在0.3.1之前存在信息泄漏漏洞，graphapi应用程序依赖于提供URL的第三方GetPhpInfo.php库。当访问此URL时，会显示PHP环境的配置详细信息。此信息包括Web服务器的所有环境变量，包括敏感数据，如ownCloud管理员密码、邮件服务器凭据和许可证密钥。  
###   
  
**0x04 影响版本**  
- owncloud/graphapi 0.2.x < 0.2.1  
  
- owncloud/graphapi 0.3.x < 0.3.1  
  
**0x05 漏洞分析**  
  
https://github.com/creacitysec/CVE-2023-49103  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://owncloud.com/  
  
  
  

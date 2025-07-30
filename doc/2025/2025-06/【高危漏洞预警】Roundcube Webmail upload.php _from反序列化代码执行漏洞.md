#  【高危漏洞预警】Roundcube Webmail upload.php _from反序列化代码执行漏洞   
cexlife  飓风网络安全   2025-06-04 14:24  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00rLzZMq8kVwHTiankpiaZGw1TX13y6akibN4BuMNgAytAgfAbIWHUIZDTl0xVo9sUAIExP8QEfMpQ3w/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
Roundcube Webmail是一个邮件服务器,CVE-2025-49113中,在1.5.10之前和低于1.6.11的1.6.x版本中,由于在program/actions/settings/upload.php文件中没有对_from参数进行验证,导致允许经过身份验证的用户触发反序列化执行远程代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00rLzZMq8kVwHTiankpiaZGw1bGgARCgvqx8kIvPibDDdPibA5EBfgDZb7euicS9ibNno8TIvbUexuYuSqg/640?wx_fmt=png&from=appmsg "")  
  
安全版本:  
  
Roundcube Webmail 1.5.10  
  
Roundcube Webmail 1.6.11  
  
修复建议:  
  
升级Roundcube Webmail至安全版本以上  
  
参考链接  
  
http://www.openwall.com/lists/oss-security/2025/06/02/3  
  
  

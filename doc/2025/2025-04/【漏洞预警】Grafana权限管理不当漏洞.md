#  【漏洞预警】Grafana权限管理不当漏洞   
cexlife  飓风网络安全   2025-04-27 03:57  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01I2Opzk4YFL2IAbx36iaxzWBgvu7S3t0xg9n2WhcIPjZScSkUibR6LF75HyY8V24QfVHezFYqG4k3Q/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
Grafana官方发布安全公告,修复了Grafana中的多个安全漏洞,其中包括一个权限管理不当漏洞,该漏洞于Grafana 11.6.x引入,查看者无论被分配何种访问权限,都能访问所有仪表板,编辑者则可以查看、编辑和删除同一组织内的任何仪表板,使用匿名身份验证的实例特别容易受到攻击,官方已经发布新版本修复此漏洞,建议受影响用户及时升级到安全版本。  
  
修复建议:  
  
正式防护方案:  
  
针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本:  
  
Grafana >= 11.6.0+security-01  
  
Grafana >= 11.5.3+security-01  
  
Grafana >= 11.4.3+security-01  
  
Grafana >= 11.3.5+security-01  
  
Grafana >= 11.2.8+security-01  
  
Grafana >= 10.4.17+security-01  
  
下载链接:  
  
https://grafana.com/grafana/download/11.6.0+security-01  
  
https://grafana.com/grafana/download/11.5.3+security-01  
  
https://grafana.com/grafana/download/11.4.3+security-01  
  
https://grafana.com/grafana/download/11.3.5+security-01  
  
https://grafana.com/grafana/download/11.2.8+security-01  
  
https://grafana.com/grafana/download/10.4.17+security-01  
  
安装前,请确保备份所有关键数据,并按照官方指南进行操作。安装后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。  
  
  

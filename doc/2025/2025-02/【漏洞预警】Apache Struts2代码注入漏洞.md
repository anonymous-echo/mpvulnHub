#  【漏洞预警】Apache Struts2代码注入漏洞   
cexlife  飓风网络安全   2025-02-07 11:39  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00avvdhDOpfhzWYPYCL7HxCoiaZ57tRXmRzicYcPx6rBicZlNapCA1ZWxKnyibKKnY0StM3GIiaR8KPKTA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞详情:**  
  
Nginx官方发布安全公告,披露了Nginx Plus和Nginx Open Source中存在的一处凭证管理不当漏洞,该漏洞是由于当基于名称的虚拟主机配置为使用TLS 1.3和OpenSSL共享相同的IP地址和端口组合时,先前经过身份验证的攻击者可以使用会话恢复来绕过这些服务器上的客户端证书身份验证要求,此漏洞可能导致资源或功能暴露给意外行为者,从而可能为攻击者提供对敏感信息的有限访问权限,Nginx官方已经发布新版本修复此漏洞,建议受影响用户及时升级到安全版本。**修复方案:**针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本:NGINX Plus >= R33 P2NGINX Plus >= R32 P2NGINX Open Source >= 1.27.4NGINX Open Source >= 1.26.3**下载链接:**https://nginx.org/en/download.html安装前,请确保备份所有关键数据,并按照官方指南进行操作。安装后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。   **参考链接:**https://my.f5.com/manage/s/article/K000149173  
  

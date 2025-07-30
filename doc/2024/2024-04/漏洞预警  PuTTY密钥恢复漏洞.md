#  漏洞预警 | PuTTY密钥恢复漏洞   
 网络威胁数据联盟   2024-04-24 15:00  
  
**0x00 漏洞编号**  
- # CVE-2024-31497  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
PuTTY  
是一种流行的开源终端仿真器、串行控制台和网络文件传输应用程序，支持SSH、Telnet、SCP和SFTP等协议，可使用该软件通过SSH远程访问和管理服务器和其他网络设备。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXOeE9Liak8AxAKuHH8wHFzUvurAqCzZ5hQwEic3azRNcKQDGlJ6peI8qFQbvwJloPYBjyrOKiclV9KA/640?wx_fmt=png&from=appmsg&wxfrom=13 "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2024-31497**  
  
**漏洞类型：**  
密钥恢复  
  
**影响：**  
  
  
未授权访问  
  
  
  
**简述：**  
PuTTY版本0.68-0.80中使用NIST P521曲线的ECDSA私钥生成签名的代码中存在密钥恢复漏洞（当使用PuTTY或Pageant对SSH服务器进行身份验证时，它会根据密钥生成签名），获得约60条签名消息和公钥的威胁者可能恢复用户的NIST P-521私钥，然后伪造签名，登录使用该密钥的任何服务器，导致信息泄露和未授权访问SSH服务器等。  
###   
  
**0x04 影响版本**  
- 0.68 <= PuTTY <= 0.80  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwndFyOpUG1b2QKn62AOda3xZmjXNENL194swjwqJt7OkcUSaQlkibbGTeyE7X1uefpaInG3luR5ACrAspFWx9Q/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

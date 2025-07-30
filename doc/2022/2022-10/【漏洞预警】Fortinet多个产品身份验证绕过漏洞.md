#  【漏洞预警】Fortinet多个产品身份验证绕过漏洞   
安识科技  SecPulse安全脉搏   2022-10-12 12:02  
  
##   
  
1. **通告信息**  
  
  
  
近日，安识科技  
A-Team团队监测到Fortinet官方发布安全公告，修复了其多个产品中的一个身份验证绕过漏洞（CVE-2022-40684），其CVSSv3评分为9.6，目前已发现被利用。  
  
对此，安识科技建议广大用户及时升级到安全版本，并做好资产自查以及预防工作，以免遭受黑客攻击。  
##   
  
2. **漏洞概述**  
  
  
  
漏洞名称：  
Fortinet多个产品身份验证绕过漏洞  
  
CVE编号：CVE-2022-40684  
  
简述：  
Fortinet（飞塔）是一家全球知名的网络安全产品和安全解决方案提供商，其产品包括防火墙、防病毒软件、入侵防御系统和终端安全组件等。  
  
在受影响的  
FortiOS、FortiProxy 和 FortiSwitchManager产品的管理界面中，可以通过使用备用路径或通道绕过身份验证，并在未经认证的情况下通过特制的HTTP或HTTPS请求对管理界面进行操作。  
##   
  
3. **漏洞危害**  
  
  
  
在受影响的FortiOS、FortiProxy 和 FortiSwitchManager产品的管理界面中，可以通过使用备用路径或通道绕过身份验证，并在未经认证的情况下通过特制的HTTP或HTTPS请求对管理界面进行操作。  
##   
  
4. **影响版本**  
  
  
  
目前受影响的  
   
Fortinet版本  
：  
  
FortiOS 版本 7.2.0 - 7.2.1  
  
FortiOS 版本 7.0.0 - 7.0.6  
  
FortiProxy 版本 7.2.0  
  
FortiProxy 版本 7.0.0 - 7.0.6  
  
FortiSwitchManager 版本 7.2.0  
  
FortiSwitchManager 版本 7.0.0  
##   
  
5. **解决方案**  
  
  
  
目前该漏洞已经修复。据调查，  
Internet 上可能存在超过 140,000 台可远程访问的 FortiGate防火墙（使用FortiOS系统），如果这些产品的管理界面也暴露于Internet，则很容易受到攻击。建议受影响用户尽快升级到以下版本：  
  
FortiOS 版本 >= 7.2.2  
  
FortiOS 版本 >= 7.0.7  
  
FortiProxy 版本 >= 7.2.1  
  
FortiProxy 版本 >= 7.0.7  
  
FortiSwitchManager 版本 >= 7.2.1  
  
下载链接：  
  
https://fortiguard.fortinet.com/  
  
缓解措施：  
  
无法立即升级的用户可以通过禁用  
HTTP/HTTPS管理界面，或使用本地策略限制可以访问管理界面的IP地址来缓解此漏洞，详见参考链接中的Fortinet安全公告。  
##   
  
6. **时间轴**  
  
  
  
【  
-  
】  
202  
2  
年  
10  
月  
10  
日   
安识科技  
A  
-T  
eam团队监测到漏洞公布信息  
  
【  
-  
】  
2  
02  
2  
年  
10  
月  
11  
日   
安识科技  
A-Team团队根据漏洞信息分析  
  
【  
-  
】  
2  
02  
2  
年  
10  
月  
12  
日   
安识科技  
A-Team团队发布安全通告  
  
  

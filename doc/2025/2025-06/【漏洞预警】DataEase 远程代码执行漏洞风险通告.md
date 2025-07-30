#  【漏洞预警】DataEase 远程代码执行漏洞风险通告  
原创 masterC  企业安全实践   2025-06-09 01:12  
  
## 一、漏洞描述  
  
DataEase是一款数据库管理软件，旨在帮助用户轻松地创建和管理数据库应用程序。该软件提供了直观的界面和强大的功能，使用户能够快速设计数据库结构、建立关系、定义数据输入和输出格式，并生成相应的应用程序代码。  
  
近日，互联网上披露了关于DataEase中存在三个远程代码执行漏洞。在受影响版本中，CVE-2025-49001是由于JWT校验机制错误导致攻击者可伪造JWT令牌绕过身份验证流程；CVE-2025-48999是由于DataEase后台在配置Redshift数据源时，未对JDBC连接参数进行严格校验，攻击者在拥有后台权限的情况下，可以通过构造恶意的JDBC连接字符串注入恶意代码；CVE-2025-49002是由于DataEase后台配置H2数据源的功能中，由于系统未对H2 JDBC连接参数进行严格校验，攻击者可通过恶意构造的JDBC URL注入恶意代码；成功利用漏洞后，攻击者可获取目标服务器权限。该漏洞对应的CVE编号为CVE-2025-49001、CVE-2025-48999、CVE-2025-49002，该漏洞影响较高，请受影响的用户做好安全加固措施。  
## 二、漏洞等级  
  
高  
## 三、影响范围  
  
DataEase <= 2.10.8  
## 四、安全版本  
  
DataEase >= 2.10.10  
## 五、修复建议  
  
目前官方已修复该漏洞，建议受影响用户尽快前往官网升级至安全版本。  
## 六、缓解方案  
  
目前暂无缓解方案。  
## 七、参考链接  
  
https://github.com/dataease/dataease/releases/tag/v2.10.10  
  
https://github.com/dataease/dataease/security/advisories/GHSA-xx2m-gmwg-mf3r  
  
https://github.com/dataease/dataease/security/advisories/GHSA-999m-jv2p-5h34  
  
https://github.com/dataease/dataease/security/advisories/GHSA-6pq2-6q8x-mp2r  
  
  

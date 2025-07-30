#  【漏洞预警】VMware Aria Operations for Logs反序列化漏洞漏洞威胁通告   
安识科技  SecPulse安全脉搏   2023-07-13 10:46  
  
##   
  
1. **通告信息**  
  
  
  
近日，  
安识科技A-Team团队  
监测到一则VMware Aria Operations for Logs存在反序列化漏洞的信息，漏洞编号：  
CVE-2023-20864  
，漏洞威胁等级：高危。  
  
该漏洞源于  
InternalClusterController类中的多个方法中对用户数据的验证不当，未经身份验证的远程威胁者可以通过向目标服务器发送恶意设计的请求来利用该漏洞，成功利用可能导致以 root 身份运行任意代码。  
  
对此，安识科技建议广大用户及时升级到安全版本，并做好资产自查以及预防工作，以免遭受黑客攻击。  
##   
  
2. **漏洞概述**  
  
  
  
CVE  
：  
CVE-2023-20864  
  
简述：  
VMware Aria Operations for Logs（以前称为 vRealize Log Insight）是一款日志分析工具，可提供高度可扩展的异构日志管理功能，具备直观且可操作的仪表板、精细的分析功能和广泛的第三方扩展功能。  
  
VMware Aria Operations for Logs中存在不安全的反序列化漏洞，该漏洞源于InternalClusterController类中的多个方法中对用户数据的验证不当，未经身份验证的远程威胁者可以通过向目标服务器发送恶意设计的请求来利用该漏洞，成功利用可能导致以 root 身份运行任意代码。  
##   
  
3. **漏洞危害**  
  
  
  
未经身份验证的远程威胁者可以通过向目标服务器发送恶意设计的请求来利用该漏洞，成功利用可能导致以  
   
root 身份运行任意代码。  
##   
  
4. **影响版本**  
  
  
  
VMware Aria Operations for Logs (Operations for Logs) 8.10.2 < 8.12  
  
VMware Cloud Foundation（VMware Aria Operations for Logs）4.x  
##   
  
5. **解决方案**  
  
  
  
目前该漏洞已经修复，受影响用户可升级到  
VMware Aria Operations for Logs (Operations for Logs) 8.12或更高版本，VMware Cloud Foundation (VMware Aria Operations for Logs) 4.x可参考KB91865。  
  
下载链接：  
  
https://www.vmware.com/security/advisories/VMSA-2023-0007.html  
##   
  
6. **时间轴**  
  
  
  
【  
-  
】2023年  
0  
7月11日 安识科技A  
-T  
eam团队监测到VMware Aria Operations for Logs漏洞的信息  
  
【  
-  
】  
2  
02  
3年  
0  
7月12日 安识科技A-Team团队根据漏洞信息分析  
  
【  
-  
】  
2  
02  
3年  
0  
7月13日 安识科技A-Team团队发布安全通告  
  
  
  
  

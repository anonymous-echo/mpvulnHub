#  【漏洞预警】Splunk Enterprise远程代码执行漏洞威胁通告   
安识科技  SecPulse安全脉搏   2023-11-24 21:45  
  
## 1. 通告信息  
  
近日，安识科技  
A-Team团队监测到Splunk Enterprise中修复了一个XML解析远程代码执行漏洞（CVE-2023-46214），其CVSSv3评分为8.0。  
  
对此，安识科技建议广大用户及时升级到安全版本，并做好资产自查以及预防工作，以免遭受黑客攻击。  
## 2. 漏洞概述  
  
简述：  
Splunk Enterprise是一款专业的数据分析软件，能够对采样的数据以及统计图做出专业分析，支持跨平台使用，常用于金融、IT、财务等多个领域。  
  
漏洞名称：  
Splunk Enterprise远程代码执行漏洞  
  
CVE编号：  
CVE-2023-46214  
  
Splunk Enterprise 版本9.0.7 和 9.1.2之前，由于未能安全清理用户提供的可扩展样式表语言转换 (XSLT，其中包含将 XML文档转换为HTML、纯文本或 PDF等其他格式的规则)，威胁者可以上传恶意 XSLT文件，从而导致在Splunk Enterprise实例上远程执行代码。  
## 3. 漏洞危害   
  
威胁者可以上传恶意   
XSLT文件，从而导致在Splunk Enterprise实例上远程执行代码。  
## 4. 影响版本  
  
受影响的  
Splunk  
版本：  
  
Splunk Enterprise 9.0版本：9.0.0 - 9.0.6  
  
Splunk Enterprise 9.1版本：9.1.0 - 9.1.1  
  
Splunk Cloud 版本< 9.1.2308  
## 5. 解决方案  
  
目前该漏洞已经修复，受影响用户可升级到以下版本：  
  
Splunk Enterprise 9.0版本：升级到9.0.7  
  
Splunk Enterprise 9.1版本：升级到9.1.2  
  
Splunk Cloud 版本：升级到9.1.2308  
  
下载链接：  
  
https://www.splunk.com/  
## 6. 时间轴   
  
【  
-】2023年  
11  
月  
19  
日   
安识科技  
A-Team团队监测到漏洞公布信息  
  
【  
-】2023年  
11  
月  
20  
日   
安识科技  
A-Team团队根据漏洞信息分析  
  
【  
-】2023年  
11  
月  
21  
日   
安识科技  
A-Team团队发布安全通告  
  
  
  
  
  

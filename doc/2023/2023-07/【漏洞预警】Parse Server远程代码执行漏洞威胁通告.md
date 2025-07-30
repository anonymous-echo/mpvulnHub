#  【漏洞预警】Parse Server远程代码执行漏洞威胁通告   
安识科技  SecPulse安全脉搏   2023-07-04 12:13  
  
##   
  
1. **通告信息**  
  
  
##   
  
近日，安识科技  
A-Team团队监测到Parse Server中修复了一个远程代码执行漏洞（CVE-2023-36475），其CVSSv3评分为9.8。  
  
对此，安识科技建议广大用户及时升级到安全版本，并做好资产自查以及预防工作，以免遭受黑客攻击。  
##   
  
2. **漏洞概述**  
  
  
##   
  
漏洞名称：  
Parse Server远程代码执行漏洞  
  
CVE编号：  
CVE-2023-36475  
  
简述：  
Parse Server 是一款开源的、基于nodejs的后端框架，默认情况下使用MongoDB数据库进行数据存储，通过MongoDB BSON解析器来解析和处理BSON数据。  
  
Parse Server版本5.5.2和6.2.1之前，由于对用户控制的参数缺乏过滤，当MongoDB BSON解析器解析恶意构造的BSON数据时易受原型污染的影响，可利用该漏洞远程执行任意代码。  
##   
  
3. **漏洞危害**  
  
  
##    
  
当  
MongoDB BSON解析器解析恶意构造的BSON数据时易受原型污染的影响，可利用该漏洞远程执行任意代码。  
##   
  
4. **影响版本**  
  
  
##   
  
目前受影响的  
Parse-server版本：  
  
Parse-server版本：< 5.5.2  
  
6.0.0<= Parse-server版本 < 6.2.1  
##   
  
5. **解决方案**  
  
  
##   
  
目前该漏洞已经修复，受影响用户可升级到以下版本：  
  
5.5.2<=Parse-server版本< 6.0.0  
  
Parse-server版本：>=6.2.1  
  
下载链接：  
  
https://github.com/parse-community/parse-server/releases  
##   
  
6. **时间轴**  
  
  
##    
  
【  
-】2023年0  
7  
月  
02  
日   
安识科技  
A-Team团队监测到漏洞公布信息  
  
【  
-】2023年0  
7  
月  
0  
3  
日   
安识科技  
A-Team团队根据漏洞信息分析  
  
【  
-】2023年0  
7  
月  
04  
日   
安识科技  
A-Team团队发布安全通告  
  
  
  

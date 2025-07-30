#  【漏洞预警】Apache Kafka Connect任意文件读取漏洞风险通告  
原创 masterC  企业安全实践   2025-06-10 07:13  
  
## 一、漏洞描述  
  
Kafka是由Apache软件基金会开发的一个开源流处理平台，由Scala和Java编写。Apache Kafka Connect是Apache Kafka生态系统中的一个组件，它提供了一种可靠且可扩展的方式来连接Kafka与其他系统。  
  
近日，互联网上披露了关于Apache Kafka中存在一个任意文件读取漏洞。在受影响版本中，攻击者可利用该漏洞读取服务器上的敏感文件（如配置文件、环境变量等），或者发起SSRF攻击，访问内部网络或其他受限资源，从而获取敏感信息或进一步扩大攻击范围。另外，若Apache Druid使用了受影响的Kafka版本，也受该漏洞影响。该漏洞对应的CVE编号为CVE-2025-27817，该漏洞影响较高，请受影响的用户做好安全加固措施。  
## 二、漏洞等级  
  
高  
## 三、影响范围  
  
3.1.0 <= Apache Kafka ＜= 3.9.0  
## 四、安全版本  
  
Apache Kafka >= 3.9.1  
## 五、修复建议  
  
目前官方已修复该漏洞，建议受影响用户尽快前往官网升级至安全版本。  
## 六、缓解方案  
  
对于使用受影响版本的用户，建议通过系统属性-Dorg.apache.kafka.disallowed.login.modules禁用LdapLoginModule，JndiLoginModule 和其他危险的登录模块。  
## 七、参考链接  
  
https://github.com/apache/kafka/tags  
  
https://seclists.org/oss-sec/2025/q2/235  
  
https://lists.apache.org/thread/6cm2d0q5126lp7w591wt19211s5xxcsm  
  

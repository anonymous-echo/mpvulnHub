#  长亭观点｜先别急！Apache Solr漏洞情报补充   
长亭应急响应  黑伞安全   2023-10-24 18:33  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicTmdiat8BnQ3vwJicUiacqriaeYkKJibsMmQ1CjSaqPnmib4E7YmXicBrhS6UpDibBZib8icH49HDumTdHvibIVg/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png "")  
  
  
近期，长亭应急响应实验室接收到一份关于Apache Solr远程代码执行漏洞的报告。  
安全研究团队已迅速完成了对这个漏洞的详细分析和评估。在此补充一些关于这个漏洞的关键信息。  
**漏洞描述**  
  
   
Description   
  
  
  
**0****1**  
  
当Apache Solr配置为集群模式（cloud mode）启动时，攻击者可以利用Schema Designer功能上传恶意配置文件，最终通过加载恶意的 jar 包实现远程代码执行。  
**前置条件**  
  
 Preconditions   
  
  
  
**0****2**  
#   
只有在Solr配置为集群模式（cloud mode）时，攻击者才能利用Schema Designer功能。如果没有开启集群模式，这个漏洞就无法被利用。攻防视角 Perspective 03经过深入分析和综合评估，长亭认为这个漏洞的实际利用价值相对较低，原因如下：1. 该漏洞通过写入文件来获得服务器权限，然而，文件写入的tmp目录并不固定，且在不同操作系统下有所不同。（例如 Linux下为/tmp/jar_cache*.tmp，而在Mac下为/private/var/folders/**/**/**/jar_cache* .tmp）2. 从SOLR-13984版本开始，Solr默认启用了Security Manager。在Windows和Mac操作系统上，这会默认限制对文件写入目录的访问，导致无法落地jar_cache。虽然有消息称在Windows下可以使用UNC路径来绕过这个限制，但暂时还未得到确认。影响范围 Affects 04Linux环境：8.10-9.2.1Windows环境：8.10–9.3.0  
**解决方案**  
  
   
Solution   
  
  
  
**05**  
入侵检测方案1. 对流量进行监控，关注指向Solr服务的流量。在流量防护设备上设置告警，针对Solr服的/api/schema-designer/*相关路径进行特别关注。2. 检查Schema Designer中的Schema列表，以确认是否存在预期之外的或异常的Schema创建记录。对于任何未经授权或可疑的Schema创建行为，确定其来源和目的。如果确认存在恶意活动，立即删除未授权的Schema，并采取必要的应对措施，如修改访问控制策略，加强身份验证和授权机制等。配置和版本检查方案验证是否使用集群模式启动，可以采用以下方法：1. 通过Solr Admin界面访问Solr的管理界面 http://<Solr服务器地址>:<端口号>/solr/，在界面的左侧菜单栏中，找到并点击“Cloud”选项。如果Solr是以集群模式运行的，将在这里看到集群的相关信息，包括节点、集合等详情。2. 通过Solr API访问http://<Solr服务器地址>:<端口号>/solr/admin/collections?action=CLUSTERSTATUS，如果Solr以集群模式启动，这个请求将返回集群的状态和配置信息。验证Solr的版本，可以采用以下方法：1. 通过Solr Admin界面访问Solr的管理界面http://<Solr服务器地址>:<端口号>/solr/，在界面的右上角或者底部，会显示Solr的版本信息。2. 通过Solr API访问 http://<Solr服务器地址>:<端口号>/solr/admin/info/system?wt=json，返回的JSON数据中会包含Solr的版本信息，通常在lucene字段下的solr-spec-version。  
**升级修复方案**  
  
  
强烈建议所有受影响的Apache Solr用户尽快访问官方下载页面（https://solr.apache.org/downloads.html），并将系统升级至最新版本，以消除潜在的安全风险，确保系统的安全性。  
  
  
  
**临时缓解方案**  
  
  
通过实施网络访问控制列表（ACL）策略来限制访问源，只有来自特定IP地址或地址段的请求才被允许访问Solr服务。  
  
  
需要特别注意的是，Solr在默认配置下允许未经授权访问，因此强烈建议启用身份认证机制，以增强系统的安全性。  
  
  
  
**时间线**  
  
   
Tinmeline  
   
  
  
  
**06**  
10月15日 官方修复漏洞10月23日 长亭应急响应实验室漏洞分析与复现10月24日 长亭安全应急响应中心发布通告  
  
  
参考资料：  
  
✦https://solr.apache.org/guide/6_6/documents-fields-and-schema-design.html  
  
  
✦https://solr.apache.org/guide/6_6/overview-of-documents-fields-and-schema-design.html  
  
  
**长亭应急响应服务**  
  
  
  
  
全力进行产品升级  
  
及时将风险提示预案发送给客户  
  
检测业务是否收到此次漏洞影响  
  
请联系长亭应急团队  
  
7*24小时，守护您的安全  
  
  
第一时间找到我们：  
  
邮箱：support@chaitin.com  
  
应急响应热线：4000-327-707  
  
  
  

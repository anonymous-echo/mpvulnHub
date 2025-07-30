#  霄壤实验室获Apache社区致谢，永信至诚「数字风洞」测评中心提醒：Apache Tomcat 存在远程执行漏洞请尽快修复   
 永信至诚   2024-12-18 12:42  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/D5XCicp6wr0Tku3IbZ5ELs5UtSZ4AMykh9XmV9SJBib0JAIpygVbAnQfEpbAGOLogibsCyJsWaC1quZQKlNanaiaEw/640?wx_fmt=png "")  
  
  
  
2024年12月17日，Apache Tomcat 官方发布安全通告，修复了一个存在于Apache Tomcat 开源组件中的远程代码执行漏洞(CVE-2024-50379)。作为该开源社区参与者，**永信至诚春秋GAME团队霄壤实验室研究员因在Apache Tomcat 多个版本的漏洞验证、测试及修复方案工作中做出重要贡献****，获得官方致谢**。  
  
  
目前该漏洞POC已在互联网上公开，且漏洞影响范围较大，Apache 官方已停止对风险版本的维护，建议用户尽快做好自查及防护，更新至安全版本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/D5XCicp6wr0RQSiauOoNPrpzEuibQzKg5llbLjVQcicFfKXxhx46OlerefE0qPib3KkkuVpVoiaQO7PSFEOnTcum3w1w/640?wx_fmt=png "")  
  
  
Apache Tomcat 是一个开源的Java Servlet容器和 Web 服务器，由 Apache 软件基金会维护。它实现了Java EE（现为 Jakarta EE）规范中的几个核心组件，特别是 Servlet 和 JSP（JavaServer Pages）规范，因此它常被用作运行和管理 Java Web 应用程序的服务器。  
  
  
霄壤实验室安全研究员介绍，该漏洞成因在于Windows文件系统与Tomcat在处理路径大小写敏感性方面存在差异，攻击者能够**利用Tomcat路径校验机制中的一个缺陷，通过绕过路径一致性检查，使得原本无法解析的文件（例如大小写不同的 JSP 文件）变为可解析状态。**  
  
  
当默认 Servlet 的 readonly 参数被设置为 false（即非默认配置）且允许使用 PUT 方法上传文件时，攻击者便能够**上传包含恶意 JSP 代码的文件，并通过条件竞争，触发 Tomcat 对该文件的解析和执行，最终实现远程代码执行****。**  
  
  
01  
  
**风险描述**  
  
  
  
成功利用该漏洞的攻击者能够远程执行代码，获取对受影响服务器的控制权，可能导致数据泄露、系统崩溃，甚至被用作传播勒索病毒等恶意软件。  
  
  
02  
  
**影响范围**  
  
  
  
Tomcat 8 全版本 (官方于2024年3月31日后停止更新)  
  
**·**11.0.0-M1 <= Apache Tomcat < 11.0.2  
  
**·**10.1.0-M1 <= Apache Tomcat < 10.1.34  
  
**·**9.0.0.M1 <= Apache Tomcat < 9.0.98  
  
  
03  
  
**解决方案**  
  
  
  
根据业务需求，注释掉 conf/web.xml中的readOnly参数或将其改为true  
  
  
04  
  
**参考资料**  
  
  
https://lists.apache.org/thread/y6lj6q1xnp822g6ro70tn19sgtjmr80r  
  
  
05  
  
**时间线**  
  
  
**·**2024年10月18日 发现薄弱点  
  
**·**2024年12月17日 官方修复并发布公告  
  
**·**2024年12月17日 获得官方致谢  
  
**·**2024年12月18日 互联网公开  
  
  
霄壤实验室安全研究员介绍，**加强对开源组件的漏洞关注并及时进行版本升级是确保软件系统安全性的关键措施**，在软件开发过程中应当建立供应链的安全管理机制，选择已知安全且经过验证的开源组件版本，并定期检查依赖的开源组件状态，利用自动化工具进行深度测试和代码审计，确保所有依赖组件的安全性和合规性。  
  
  
**永信至诚****「****数字风洞」测试评估平台**围绕企业数字资产进行全生命周期的健康管理，其**代码审计与软件成分分析系统可从软件供应链方面围绕代码、中间件等进行安全风险检测，提高软件系统的整体安全性，保障数字健康**，相关用户可向永信至诚安全专家寻求支持。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/D5XCicp6wr0Tku3IbZ5ELs5UtSZ4AMykhRwOQkcRviaGSHCgcSdZkK3FglXjDN5VcWCRkiaUuiaIbUXFKTEZ2tzW3g/640?wx_fmt=png "")  
  
**往期精选**  
  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454828008&idx=1&sn=1eb7245b8cd58334fe68e3700cb7b931&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454828006&idx=1&sn=efb848c20b614b8c71605710251df9cb&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454827130&idx=1&sn=25f89af6acf8516aa4e5821f96f98ae0&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454827020&idx=1&sn=51edc74f86206d5b238730ce0d84f6de&chksm=8c8f8686bbf80f901645ee25489e6d454475dc21efe565de0f3dafcb1638d5c000eac6605fd1&token=447322482&lang=zh_CN&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454826718&idx=1&sn=8a56766ebca68967ff2f152b5eb465fc&chksm=8c8f9854bbf81142d9fd72527f26911d87b70e731ab6e4b0bece7b49c1c1aab11517638dc249&token=930694209&lang=zh_CN&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454826500&idx=1&sn=7adcdf7dfef4cdb8de005d50565244b1&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454825729&idx=1&sn=c5243db53f9f48cb2246261ddc892b26&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454824458&idx=1&sn=66049fa3ea0b3c11524c8a6dc9901497&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454823925&idx=1&sn=e6cf768dd6fbebf814514de812862c16&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAwNDUyMjk4MQ==&mid=2454823704&idx=1&sn=5901da0eb9f54178a04cef536204a679&scene=21#wechat_redirect)  
  
  
**赛事演练**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/D5XCicp6wr0Tku3IbZ5ELs5UtSZ4AMykhiaRBZu3ykLdFQ537siaty4sxSxB5Q1zAYlHibZna5UOibAlxB2Ae66CAWg/640?wx_fmt=jpeg "")  
  
  
**核心产品**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/D5XCicp6wr0Tku3IbZ5ELs5UtSZ4AMykhicTyQqIghicp0Iibk2YFreEQSsh77VpozDGI6VdNXb4qI3j5ghibvofdrQ/640?wx_fmt=png "")  
  
  
**完**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/D5XCicp6wr0Tku3IbZ5ELs5UtSZ4AMykhtQX5pibtpciaz0icwjYMMwZuwXhnkCLE1Cq4IcsOf8lNFIcGPkn6aO5Sg/640?wx_fmt=jpeg "")  
  
  

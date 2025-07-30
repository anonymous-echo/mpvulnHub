#  CNNVD | 关于Apache Dubbo 代码问题漏洞的通报   
 中国信息安全   2023-12-20 18:48  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5zlXThOicZKAOm4xofkjJ31avItZCM9SXDoNrg0JQ4kMia3nNz7INM8MCEvmnRI4EVibX0g9JSEzcdpA/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5zlXThOicZKAOm4xofkjJ31avItZCM9SXDoNrg0JQ4kMia3nNz7INM8MCEvmnRI4EVibX0g9JSEzcdpA/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1brjUjbpg5zlXThOicZKAOm4xofkjJ31agw3U3rz67sQ2V0u0O1LInEbJQYFF8mvanQmic0nQN4taBhalraziaSDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5zlXThOicZKAOm4xofkjJ31avItZCM9SXDoNrg0JQ4kMia3nNz7INM8MCEvmnRI4EVibX0g9JSEzcdpA/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5zlXThOicZKAOm4xofkjJ31avItZCM9SXDoNrg0JQ4kMia3nNz7INM8MCEvmnRI4EVibX0g9JSEzcdpA/640?wx_fmt=gif&from=appmsg "")  
  
**扫码订阅《中国信息安全》**  
  
邮发代号 2-786  
  
征订热线：010-82341063  
##   
## 近日，国家信息安全漏洞库（CNNVD）收到关于Apache Dubbo代码问题漏洞（CNNVD-202312-1524、CVE-2023-29234）情况的报送。成功利用漏洞的攻击者，可在目标系统上执行任意代码。Apache Dubbo 3.1.0至3.1.10版本，3.2.0至3.2.4版本均受此漏洞影响。目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
**一、漏洞介绍**  
  
Apache Dubbo是美国阿帕奇（Apache）基金会的一款基于Java的轻量级RPC（远程过程调用）框架。该产品提供了基于接口的远程呼叫、容错和负载平衡以及自动服务注册和发现等功能。漏洞源于程序在处理异常时对反序列化后的对象进行了字符串拼接，恶意攻击者可利用该漏洞在目标系统上执行任意代码。  
  
**二、危害影响**  
  
成功利用漏洞的攻击者，可在目标系统上执行任意代码。Apache Dubbo 3.1.0至3.1.10版本，3.2.0至3.2.4版本均受此漏洞影响。  
  
**三、修复建议**  
  
目前，Apache官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方参考链接：  
  
https://lists.apache.org/thread/wb2df2whkdnbgp54nnqn0m94rllx8f77  
  
本通报由CNNVD技术支撑单位——奇安信网神信息技术（北京）股份有限公司、新华三技术有限公司、上海斗象信息科技有限公司、深圳市深信服信息安全有限公司、深圳昂楷科技有限公司、上海矢安科技有限公司、南京禾盾信息科技有限公司、杭州迪普科技股份有限公司、西安交大捷普网络科技有限公司、中孚安全技术有限公司、网宿科技股份有限公司、江苏百达智慧网络科技有限公司等技术支撑单位提供支持。  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。联系方式: cnnvdvul@itsec.gov.cn  
  
（来源：CNNVD）  
  
  
  
  
**《中国信息安全》杂志倾力推荐**  
  
**“企业成长计划”**  
  
  
**点击下图 了解详情**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzE5MDAzOA==&mid=2664162643&idx=1&sn=fcc4f3a6047a0c2f4e4cc0181243ee18&chksm=8b5ee7aabc296ebc7c8c9b145f16e6a5cf8316143db3edce69f2a312214d50a00f65d775198d&scene=21#wechat_redirect)  
  
  

#  OpenCVE：一款自动收集NVD、MITRE等多源知名漏洞库的开源工具，累计收录CVE 27万+   
原创 筑梦网安  全栈安全   2024-12-15 13:34  
  
>   
> 漏洞库在企业中扮演着至关重要的角色，不仅提升了企业的安全防护能力，还支持了安全决策、合规性要求的满足以及智能化管理的发展。前期博文《[业界十大知名权威安全漏洞库介绍](https://mp.weixin.qq.com/s?__biz=MzkyMTYyOTQ5NA==&mid=2247484808&idx=1&sn=54775c3d874d0f42eae901f62394c105&token=803826220&lang=zh_CN&scene=21#wechat_redirect)  
  
》介绍了主流漏洞库，今天给大家介绍一款集成了多款知名漏洞库的开源漏洞预警平台。  
  
  
# 1. 什么是OpenCVE  
  
OpenCVE是一个开源项目，旨在帮助用户跟踪和管理其软件和系统中的安全漏洞。它的核心原理是通过集成多个漏洞数据库，自动化地收集和更新漏洞信息，并允许我们根据各种条件搜索、过滤和组织他们，从而为用户提供实时的安全态势感知。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicqYOXkiaL4IiaqeGKpL3KmyqVBVVBUqeGicGLAjpUfW7GVt6ylrq41gUJxxjMg0OkJJe7IXbNPTQ7aw/640?wx_fmt=png&from=appmsg "")  
  
OpenCVE漏洞界面  
  
  
我在写这篇文章时，OpenCVE刚好完成了v2版本的发布，这个新版本是对v1的完全重构，具有新的技术栈、增强的功能和改进的可扩展性。相比v1版本，主要变化点如下：  
- **升级的技术栈**  
：从Flask过渡到Django，从Celery过渡到Airflow，实现了强大的可扩展性和工作流编排。  
  
- **组织和项目**  
：引入了对组织和项目的支持，以帮助隔离订阅（供应商和产品）并更有效地组织通知。  
  
- **Webhook集成**  
：添加了Webhook支持，将OpenCVE通知集成到外部系统和工作流中。  
  
- **增强的漏洞源**  
：将CVE更新与MITRE、NVD、RedHat和VulnEnrichment的丰富数据进行交叉引用，提供全面和最新的漏洞见解。  
  
>   
> 截至2024.12.15，OpenCVE已经收录了27.3W+个CVE漏洞。  
  
  
项目地址：  
https://github.com/opencve/opencve  
  
项目网站：  
https://www.opencve.io/  
# 2. OpenCVE主要功能介绍  
  
通过多源漏洞库集成、漏洞监控及API支持，OpenCVE可帮助组织提高对安全漏洞的响应速度，降低其潜在的安全风险。  
## 2.1. 漏洞监控  
  
用户可以通过OpenCVE按供应商或产品来监控特定软件或库的漏洞，系统会自动通知用户相关的安全更新和漏洞信息，这些通知可以通过电子邮件或Webhook发送。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicqYOXkiaL4IiaqeGKpL3Kmyq7yWTd6KtInPOYfrGhuSVTvwFib0qdbcvTbLUwwzjEVteS9lwPRVE2bQ/640?wx_fmt=png&from=appmsg "")  
  
邮件订阅  
## 2.2. 集成多源数据  
  
OpenCVE交叉引用来自多个可靠来源的信息，如MITRE、Vulnrichment、NVD和RedHat。这确保了漏洞数据保持准确和最新，即使其中一个源暂时不可用，也不影响整个流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicqYOXkiaL4IiaqeGKpL3KmyqFkav2z1kyiaWmyWN8I0TJK8nwu1Jb0oPaeXC7icfF7LDe10HR9Z14I2A/640?wx_fmt=png&from=appmsg "")  
  
漏洞元数据界面  
## 2.3. 自定义配置  
  
用户可以根据自己的需求自定义监控的项目和接收通知的方式，灵活适应不同的安全管理策略。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicqYOXkiaL4IiaqeGKpL3KmyqMCwWKXibSiazicj7y2LUW1jfuWsdQFRzV5AiaxibttHtjqNVTftAs9BD1tg/640?wx_fmt=png&from=appmsg "")  
  
自定义配置  
## 2.4. API支持  
  
OpenCVE提供API接口，方便开发者将其集成到其他安全管理工具中，提升整体的安全防护能力。  
  
比如，如下为获取CVE列表的接口  
```
$ curl -u username:password https://app.opencve.io/api/cve?page=10{  "count": 262939,  "next": "https://app.opencve.io/api/cve?page=11",  "previous": "https://app.opencve.io/api/cve?page=9",  "results": [    ...  ]}
```  
  
要想了解更多接口的调用方式，可能参阅官网https://docs.opencve.io/api/。  
# 3. 如何使用OpenCVE  
  
大家可以根据自身情况选择如下两种使用方式：  
- **自托管**  
：可以使用Docker在自己的服务器上安装和配置OpenCVE，这种方式提供了对实例的完全控制；  
  
- **SaaS版本**  
：或者可以使用OpenCVE的免费SaaS版本，网址为https://www.opencve.io。此选项不需要设置，可以开箱即用，需要在平台注册账户方可使用更多功能。  
  
# 4. 如何搭建私有化OpenCVE  
  
克隆OpenCVE存储库并进入docker  
目录，然后运行 install.sh 脚本：  
```
git clone https://github.com/opencve/opencve.gitcd docker./install.sh
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicqYOXkiaL4IiaqeGKpL3KmyqMHnia7ZzzSXXOicFtazS6LvI1JXQ2QJrt77SErEnnzN3icpibssyhDNe4Q/640?wx_fmt=png&from=appmsg "")  
  
启动OpenCVE  
  
它将准备环境并运行OpenCVE所需的所有服务。由于依赖的组件较多，需求实时联网下载依赖文件，整个安装启动过程耗时约30min。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicqYOXkiaL4IiaqeGKpL3KmyqCIFlJyDdAxLV9sWGL1guFibtkovUxYcPslTz5DjG5mccWtQ6THlhjow/640?wx_fmt=png&from=appmsg "")  
  
安装完成  
  
安装完成后可以用默认的密码登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicqYOXkiaL4IiaqeGKpL3Kmyq5sk2sgTFVbyhNpURUib5z9IgjIOFrAJtKZ8yP1SGsPNPPYYIGnXlhpA/640?wx_fmt=png&from=appmsg "")  
  
默认密码信息  
  
比如，我们可以登录到Airflow（OpenCVE利用其进行漏洞源采集）的后台查看漏洞采集的任务信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicqYOXkiaL4IiaqeGKpL3Kmyqa5Q5y05Reh22FzhEXLRDdh0a2xBZUMjXX7hX0OnUiaXr4cyR2D49TpA/640?wx_fmt=png&from=appmsg "")  
  
Airflow后台  
>   
> Airflow是一个可编程，调度和监控的开源工作流平台，基于有向无环图(DAG)，Airflow可以定义一组有依赖的任务，按照依赖依次执行。  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicqYOXkiaL4IiaqeGKpL3KmyqibPFD2LGegJkoJkLicGCp7LFwErv9UBc36FBpRAvzvltcG1d1XyoU2Ew/640?wx_fmt=png&from=appmsg "")  
  

#  同程黑盒漏洞扫描系统 - 飞刃(nextscan)正式发布   
原创 lysrc  同程旅行安全应急响应中心   2023-04-24 18:22  
  
**1**  
  
Part.1  
  
**简介**  
  
    黑盒漏洞扫描器作为企业安全建设中重要的一环，同程在此过程中也试用过业界很多扫描器，但是都无法很好满足我们扫描需求，比如无法支持分布式部署、扫描目标来源单一、没有限速容易扫挂业务、想自己添加漏洞插件，不支持，不方便？  
  
    基于上述原因，同程安全推出了企业级黑盒漏洞扫描平台：飞刃（NextScan），它是我们自研一款适合企业需求的漏洞扫描平台，基于go语言编写，采用分布式架构，由Server，Agent，Web三个部分组成。拥有信息采集、漏洞扫描、漏洞管理、POC管理、资产管理等功能，支持主动、被动多种扫描模式，支持多种数据来源，支持扫描Web漏洞、主机类漏洞；我们的愿景是希望打造成一个可以开箱即用的企业级黑盒漏洞扫描平台  
  
  
“她”可能满足了一个甲方安全从业者对一款企业级漏洞扫描器的所有幻想  
  
  
功能架构：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKq8BSYekDZiaIsKLdTMrV6M53U60AUQJopnGf3KegMVysBPUHNXAmlwFibDPiarhxeP17yRpYiaOjRWRg/640?wx_fmt=png "")  
  
**2**  
  
Part.2  
  
**系统特色******  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKoqK0nu7MEWAsAe6bpOHINbZQOP7AqlKq2ZSjEVS6OVKh7s3Bnfia9tMiaA6dWn4OHibmSIVqxQ7gqHg/640?wx_fmt=png "")  
  
  
  
**3**  
  
Part.3  
  
**系统截图**  
  
  
**系统首页**  
  
展示系统内各个模块统计数据，指标大盘  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKqrOW8f5SbKzavydSokdhDf2pcLOUggrqS5lOL2RkMQIVHomgogeuslgG9a45gS79s39gqMgncn3w/640?wx_fmt=png "")  
  
  
**项目管理**  
  
创建项目-->选择来源  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKoqK0nu7MEWAsAe6bpOHINbNuECiaStNoLyuv6z1ap1I1GCCC3GqMXx16hI4I2kJichSRSXqru6N1dg/640?wx_fmt=png "")  
  
  
创建项目-->自由配置插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKqrOW8f5SbKzavydSokdhDficIWQraE6ZP3DZkFo6tpdsrgFDW9cwEBiahzIK1XUFNs9x0eZ9OibUEibQ/640?wx_fmt=png "")  
  
项目启动，暂停，取消  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKqrOW8f5SbKzavydSokdhDfvJnIEo3FkTibHniaVOu8SeoUpUkr9SaqzeUehRfXjibZUe0dX5psGQGuA/640?wx_fmt=png "")  
  
****  
**漏洞管理**  
  
展示，管理，查看已扫描出漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKqrOW8f5SbKzavydSokdhDfRBW9vzZB1nMBDd5faibibtqzJyvhDQlibYtsu5GVVtrVrYTKTZ08gcKcg/640?wx_fmt=png "")  
  
****  
**插件管理**  
  
管理系统所带插件，包括内置插件，nuclei的开源插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKqtrhbB3L7MSTPeqeDYp54JcMvB5plmOv9vyPCwmLkdkHy65oJHOc6BebSBTwehQhCD50WefjB4xw/640?wx_fmt=png "")  
  
  
更多功能介绍，使用以及系统部署的请参照官方文档  
  
**文档**：[https://next-scan.ly.com](https://next-scan.ly.com)  
  
  
**GitHub**:  
 [https://github.com/tongcheng-security-team/NextScan](https://github.com/tongcheng-security-team/NextScan)  
  
  
[](https://github.com/ysrc/nexscan)  
  
  
4  
  
Part.4  
  
**结语**  
  
   飞刃是一个公益性项目，主要是分享同程在建设企业黑盒漏洞扫描系统的一些实践和研究成果，赋能给社区，欢迎广大企业用户和个人使用。飞刃还很年轻，我们也希望吸取社区经验和指导，能帮助飞刃一起成长，希望大家多多支持。  
  
  
公众号回复“nextscan”扫码进群；也可添加管理微信进入 nextscan官方群共同交流  
  
  
nextscan 交流群  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKq8BSYekDZiaIsKLdTMrV6M5xUWgv9wc1Rvp9QnI7ia6yJsHz4nUgI5okgRlvTudPlzejZd3HKGaQ5w/640?wx_fmt=png "")  
  
  
同程旅行安全应急响应中心  
  
  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PAV8ewtdsKoqK0nu7MEWAsAe6bpOHINbUUauQdRLYx3tKeFd3Yib4qtupF3NVHXUOagQcpOw6BicIFQN8JtMsGkQ/640?wx_fmt=png "")  
  
  
  

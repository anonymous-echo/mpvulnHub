#  绿盟科技星云实验室获微软MSRC致谢|Azure数据库服务存在RCE漏洞   
创新研究院  绿盟科技研究通讯   2024-02-27 15:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/hiayDdhDbxUaFiaxT3ZfuHhY0kClichXR6aNpCY0eBZ9NsRID2An2SgLhhrKgvROKoicqEJ2PYV1uibMMAMuNfuvZRQ/640?wx_fmt=gif&from=appmsg "")  
  
  
  
一.  概述  
  
  
  
  
  
  
  
  
  
  
Azure Database for PostgreSQL - Flexible Server [1]是基于开源 PostgreSQL数据库[2]引擎的关系数据库服务。它是完全托管的数据库即服务，能够处理任务关键型工作负荷，具有可预测的性能、安全性、高可用性和动态可伸缩性。   
  
经星云实验室研究发现，该数据库服务存在RCE漏洞，恶意用户可借由该漏洞在数据库的宿主机上执行命令。  
  
该漏洞根因在于某个数据库插件，用户可借由该插件安装过程中调用的函数实现数据库提权，尽管数据库禁止了Program特性，后续仍可利用PostgreSQL UDF实现宿主机命令执行。致谢如图1所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hiayDdhDbxUaFiaxT3ZfuHhY0kClichXR6aevYMPTg2xa2F9R1vU5Fw9oQqQdnYU469QY98X1voys4W8HcaXCWZdQ/640?wx_fmt=png&from=appmsg "")  
  
图1 MSRC致谢  
  
注：本文涉及到的技术仅供教学、研究使用，禁止用于非法用途  
  
  
  
二.  漏洞跟踪  
   
  
  
  
  
  
  
  
  
  
  
2.1  
  
漏洞影响  
  
Azure Database for PostgreSQL Flexible Server所有允许该特定插件安装的数据库服务。该特定插件安装过程中调用的函数可以被用户劫持，恶意用户可借此提升权限至超级用户，随后利用PostgreSQL UDF执行宿主机系统命令。  
  
2.2  
  
修复时间线  
  
2023年8月11日 报告了该漏洞  
  
2023年8月12日 MSRC受理该漏洞  
  
2023年8月23日 MSRC确认了该漏洞  
  
2023年8月28日 问题开始修复  
  
2023年9月22日 确认修复  
  
参考文献  
   
  
[1] https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/overview  
  
[2] https://www.postgresql.org/  
  
  
**相关阅读**  
  
  
  
[阿里云数据库漏洞分析与思考](http://mp.weixin.qq.com/s?__biz=MzIyODYzNTU2OA==&mid=2247495223&idx=1&sn=80003f4b3712285c9a6074b76eeab0ba&chksm=e84c48e8df3bc1fed19bccd9b164b0a431d4029dd0dc844639dc26ac2422192900c3499d2a37&scene=21#wechat_redirect)  
   
  
  
内容编辑：创新研究院 马胜  
     
   
责任编辑：创新研究院 陈佛忠  
  
  
本公众号原创文章仅代表作者观点，不代表绿盟科技立场。所有原创内容版权均属绿盟科技研究通讯。未经授权，严禁任何媒体以及微信公众号复制、转载、摘编或以其他方式使用，转载须注明来自绿盟科技研究通讯并附上本文链接。  
  
  
**关于我们**  
  
  
绿盟科技研究通讯由绿盟科技创新研究院负责运营，绿盟科技创新研究院是绿盟科技的前沿技术研究部门，包括星云实验室、天枢实验室和孵化中心。团队成员由来自清华、北大、哈工大、中科院、北邮等多所重点院校的博士和硕士组成。  
  
绿盟科技创新研究院作为“中关村科技园区海淀园博士后工作站分站”的重要培养单位之一，与清华大学进行博士后联合培养，科研成果已涵盖各类国家课题项目、国家专利、国家标准、高水平学术论文、出版专业书籍等。  
  
我们持续探索信息安全领域的前沿学术方向，从实践出发，结合公司资源和先进技术，实现概念级的原型系统，进而交付产品线孵化产品并创造巨大的经济价值。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/hiayDdhDbxUbicz5Thqd08pCaEYu4icsFDsaWia7KdXbwuxu0wTnhKoI1RGNS2iaLWZr0NpwZobich5rob6g6KAI8h9Q/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**长按上方二维码，即可关注我**  
  

#  (0day)月子会所ERP某接口存在文件读取漏洞   
原创 websec  WebSec   2024-12-16 06:41  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvCicxSYRNH1W482VBCDEG3W5wmK4sDEcWhDtNSC4usPacqBHfCvhvHyog/640?wx_fmt=png&from=appmsg "")  
  
  
  
**阅读须知**  
  
亲爱的读者，我们诚挚地提醒您，WebSec实验室的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。WebSec实验室及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
  
  
  
  
  
  
  
**01**  
  
  
**漏洞描述**  
  
  
      
月子会所ERP管理云平台是为月子中心量身定制的企业资源规划系统，旨在提升管理效率和服务质量。平台集成了预约管理、客户档案、员工排班、财务核算、库存管理等功能，支持实时数据分析与报告生成。通过云平台，月子会所可以实现线上预约、会员管理、自动化调度等操作，简化流程、提高运营效率，并提供更加个性化的服务，提升客户满意度。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvC3OPXu3bqkttHOfMVKyAU6HVAqdvG2VmxbyTiaAy23niaG7kpsvrCJ7Bw/640?wx_fmt=png&from=appmsg "")  
  
  
**02**  
  
  
**资产测绘**  
  
  
  
  
```
Fofa语法：app="妈妈宝盒-ERP"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvCtg9CSpu0v3sTMZu02pUHoYTox7FzkticxPVYefc1l6ypuGk3FNPoLbA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**03**  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvC0NhxQ6OtWFmPk1GbvJ0bwzGRBzq0flxPwfQBHY7VOUJ6DXDL92zKxw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvCj91qCosvZSYoSIrppwk4vsn4H7WIJ5B0uOTcib3QibnodHF7xfdWibQqQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**04**  
  
  
**修复建议**  
  
****  
  
  
临时缓解方案：  
- **严格限制文件路径**  
：确保用户输入的文件路径只允许访问预定的目录。可以使用白名单方式，限制只允许访问特定的文件或目录。  
  
- **去除特殊字符**  
：在用户输入中去除或转义特殊字符，如 ../  
、..  
、/  
、\  
 等，这些字符常用于进行路径穿越攻击。  
  
- **路径规范化**  
：在处理用户输入的路径时，使用标准化函数将路径规范化，以消除 ../  
 和其他路径穿越符号。例如，使用 realpath()  
 或相似的函数来获取真实路径，确保不允许访问敏感目录。  
  
升级修复方案：  
  
官方已发布补丁  
  
  
  
**05**  
  
  
**星球介绍**  
  
  
1. 我们郑重承诺，不定时推送高质量的  
1day  
，有时也会分享未公开的  
0day  
。  
  
1. 星球目前价格降至  
99元  
，公众号设置星标，私聊星主只需  
89元.  
  
1. 欢迎投稿  
最新漏洞poc  
或  
复现分析文章  
，符合条件的投稿者将获得一年免费会员资格。  
  
                                      
**速来刷分**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ssAcvVwPLCUhA5hAcDMBQgTaJsXE1uluQH0hEFd4XV9myj2SadMnV9SFS792os2A5JbDFuNZU78acgD83yqjaw/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ssAcvVwPLCUhA5hAcDMBQgTaJsXE1uluC3wh0ve4RxJFPgwrkzsicJOdVpKd0k7CvVQ3kAlHofGX75EZNefic7KQ/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCVDaBanNRWoiaHrEsXv4ol8bFewWtfRPRPCiaJ3fibDy0rlYSnYMJED3eWFOjZzkj6QKpVWNqQbtNozQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**▌▌▌星球服务**  
  
**1、WebSec专属Fofa查询工具（**  
**Fofa****永久高级会员）******  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCUTrJuXibRP1Yu0O3w6L8hOy5sZJfHBugLxoITVTBlLZoSiaKEdIhL7tRY78ndQgznK00PzU0vU9Qlw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**2、Hunter积分充值八折优惠**  
  
**3、**  
**MD5付费****版查询**  
  
**4、Xray高级版**  
  
**更多漏洞poc发布在知识星球**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvC8mEiaSibAl17e6zhusRCngOeh3lK12fCicLW52sXu3boEQAticyD8hg3ibg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
****  
- END -  
  
  
  
  

#  (0day)安科瑞环保用电监管云平台存在SQL注入漏洞   
原创 WebSec  WebSec   2024-12-19 04:19  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvCicxSYRNH1W482VBCDEG3W5wmK4sDEcWhDtNSC4usPacqBHfCvhvHyog/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**阅读须知**  
  
亲爱的读者，我们诚挚地提醒您，WebSec实验室的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。WebSec实验室及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
  
  
  
  
  
  
  
**01**  
  
  
**漏洞描述**  
  
  
      
安科瑞环保用电监管云平台是一款基于云计算和大数据技术的智能能源管理系统，旨在帮助企业和公共机构实现电力监控、数据分析和用电优化。通过实时监测电力消耗、设备状态和能效数据，平台可以生成详细报告和预警，帮助用户提高能源使用效率、降低成本，并符合环保和能源管理的相关法规要求。系统支持远程控制、智能调度，提升能源管理的精细化与智能化水平。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCUxL6Yc4wnCybjrbfpCCD3kMdWjPxANwibNGFZMOUvXnWDOiazjwa57wop4icfEqSbWbibBbR5qmIGLpA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**02**  
  
  
**资产测绘**  
  
  
  
  
```
Fofa语法：body="myCss/phone.css"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCUxL6Yc4wnCybjrbfpCCD3kcSsXcGDkBab89c5e29ecVGVmXjQV1FvO7vBXSx6jbIkghpoGMqQ1hQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**03**  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCUxL6Yc4wnCybjrbfpCCD3k92RIibTblpOVklEAwMpkcd0QzR1hEwZ8c3bws7VgEkhYl0icpsSjb6Mg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCUxL6Yc4wnCybjrbfpCCD3kkMvgHTCbErHbCqwNvPXGABxME3mdFyAwOMFpbEsNWuvzFrC1HnZ61A/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**04**  
  
  
**修复建议**  
  
****  
  
  
临时缓解方案：  
- **限制输入类型**  
：对用户输入进行严格的类型检查，确保输入数据符合预期的格式。例如，如果某个字段应该是数字，确保用户输入的值仅为数字。  
  
- **过滤特殊字符**  
：对用户输入中的特殊字符（如 '  
、"  
、;  
、--  
 等）进行转义或替换，以防止恶意SQL语句注入。  
  
- **使用白名单验证**  
：只允许特定的、已知的输入值，避免使用黑名单过滤，因为黑名单无法覆盖所有攻击方式。  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvC8mEiaSibAl17e6zhusRCngOeh3lK12fCicLW52sXu3boEQAticyD8hg3ibg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
- END -  
  
  
  
  

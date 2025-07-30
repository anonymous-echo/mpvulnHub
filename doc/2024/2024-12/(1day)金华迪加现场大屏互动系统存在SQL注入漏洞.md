#  (1day)金华迪加现场大屏互动系统存在SQL注入漏洞   
原创 WebSec  WebSec   2024-12-23 02:03  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvCicxSYRNH1W482VBCDEG3W5wmK4sDEcWhDtNSC4usPacqBHfCvhvHyog/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**阅读须知**  
  
亲爱的读者，我们诚挚地提醒您，WebSec实验室的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。WebSec实验室及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
  
  
  
  
  
  
  
**01**  
  
  
**漏洞描述**  
  
  
      
金华迪加现场大屏互动系统是一种集成化的互动技术平台，旨在提升现场活动的观众参与感和互动体验。通过大屏幕与观众进行实时互动，支持触摸、扫码、投票、抽奖等多种互动方式，增强活动的趣味性和互动性。系统广泛应用于企业年会、展览展示、商业活动等场合，帮助品牌提升现场影响力，同时提供数据分析和实时反馈，优化活动效果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCW2NuHjCekedThb6BvwiaGIXkqy5Xq40ETIXibgd6kBhuGRWU3iak6RHJiaho2x2tic2BlAd5ziaSqtibdfA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**02**  
  
  
**资产测绘**  
  
  
  
  
```
Fofa语法：body="/wall/themes/meepo/assets/images/defaultbg.jpg" || title="现场活动大屏幕系统"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCW2NuHjCekedThb6BvwiaGIXGme1ib9VmSAjAlDjIBtQbIsSa6hWobEIzz5JrbO5vZ9J80HYdqdYyKA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**03**  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCW2NuHjCekedThb6BvwiaGIXZfo39Inkv58thqAHZichMX5WL5tmOKiavWk5Up9uCuWicmgsQ5aTeI2tw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCW2NuHjCekedThb6BvwiaGIXxvkmlMSxfGjI6Bq1007SlEZELsuA2biauasYsyteEkfxffUtXq9TegA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
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
  
  
  
  

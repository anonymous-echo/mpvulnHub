#  (1day)全媒体采编平台存在未授权访问漏洞   
原创 WebSec  WebSec   2024-12-24 00:22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvCicxSYRNH1W482VBCDEG3W5wmK4sDEcWhDtNSC4usPacqBHfCvhvHyog/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**阅读须知**  
  
亲爱的读者，我们诚挚地提醒您，WebSec实验室的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。WebSec实验室及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
  
  
  
  
  
  
  
**01**  
  
  
**漏洞描述**  
  
  
      
全媒体采编V3.0工作平台登录界面为用户提供便捷的身份验证和权限管理功能。用户通过输入用户名和密码，安全登录系统后，可以访问平台内的各类新闻采编、编辑、发布等模块。平台支持多种认证方式，确保信息安全。登录成功后，用户可以根据权限进行操作，提高工作效率，满足全媒体内容的创作、发布与管理需求。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCW2NuHjCekedThb6BvwiaGIXgmlLNZ8b7zWXZcvFYY9JIqNkWz3L1byzYfjCuE6Z12A2mnPldpDJyg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**02**  
  
  
**资产测绘**  
  
  
  
  
```
Hunter语法：web.title=="全媒体采编V3.0-工作平台登录"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCW2NuHjCekedThb6BvwiaGIXPpQEYHNCHCBn1PD6vrYeS4wal9ichAB0ZMpeI4icCjDWBFKSW2bxkhaA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**03**  
  
  
**漏洞复现**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCW2NuHjCekedThb6BvwiaGIXeTQHicA9bxvJfZnahMoicic4kNbBwLXhlTodEJpJNVmoj7bZcfHUN0kVg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
  
**修复建议**  
  
****  
  
  
临时缓解方案：  
- 暂时禁用可能导致未授权访问的功能或模块，防止攻击者利用漏洞进行非法访问。  
  
- 增强登录流程，如启用双因素认证（2FA）或临时提高密码复杂度要求。  
  
- 限制某些敏感操作必须通过管理员权限进行。  
  
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
  
  
  
  

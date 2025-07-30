#  (0day)当虹科技-Arcvideo-Live存在文件上传漏洞   
原创 WebSec  WebSec   2024-12-25 01:28  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU0ntNfgic0wmqIFYOL0SzvCicxSYRNH1W482VBCDEG3W5wmK4sDEcWhDtNSC4usPacqBHfCvhvHyog/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**阅读须知**  
  
亲爱的读者，我们诚挚地提醒您，WebSec实验室的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。WebSec实验室及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
  
  
  
  
  
  
  
**01**  
  
  
**漏洞描述**  
  
  
      
当虹科技的Arcvideo-Live系统是一款高性能的视频直播解决方案，旨在提供高清、低延迟的视频传输和实时互动功能。该系统支持多平台、多通道的直播管理，能够满足大规模直播需求。通过云计算、CDN加速等技术，Arcvideo-Live确保了视频内容的稳定传输和极佳的观看体验，广泛应用于体育赛事、演唱会、企业活动等领域，助力各类行业实现高效、流畅的直播运营。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCVWakbQKxXNsXOMJdYxX1tEq0SrWhfttm8gBFJcx5zlXRd1UxpkIsTL5VmCcibMTjmeIWjEb89laXg/640?wx_fmt=png&from=appmsg "")  
  
  
**02**  
  
  
**资产测绘**  
  
  
  
  
```
Fofa语法：app="当虹科技-Arcvideo-Live"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCVWakbQKxXNsXOMJdYxX1tEcRZGNPEwjMZNUDmr1YkFSSbRaNeCBluZs3ko2JLictlax5XdkHA7o1g/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**03**  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCVWakbQKxXNsXOMJdYxX1tEyFV0vhKwZ74ME0vLypQOp2nMHAvqDpOv0xQ149b39mWyxJGkhiaV2kQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCVWakbQKxXNsXOMJdYxX1tExkwKpH1JcXgTicd58WIdHcXonI4rbyYZ7D5Zd2tEdhSghStkxSf0Q0g/640?wx_fmt=png&from=appmsg "")  
  
  
  
**04**  
  
  
**修复建议**  
  
****  
  
  
临时缓解方案：  
- 仅允许特定类型的文件上传（如 .jpg  
, .png  
, .pdf  
 等），通过文件扩展名、MIME 类型以及文件内容的魔数进行检查。  
  
- 设置上传文件的最大大小限制，防止攻击者上传过大的文件（如大于服务器容量的文件）进行拒绝服务攻击（DoS）。  
  
- 上传的文件可以重命名为随机字符串或 UUID，避免文件名中包含恶意代码（例如 .php  
, .exe  
 等），减少文件被直接执行的风险。  
  
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
  
  
  
  

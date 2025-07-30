#  (0day)杜特网上订单管理系统getUserImage存在SQL注入漏洞   
原创 websec  WebSec   2024-12-12 06:43  
  
**阅读须知**  
  
亲爱的读者，我们诚挚地提醒您，WebSec实验室的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。WebSec实验室及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
  
  
  
  
  
  
  
**01**  
  
  
**漏洞描述**  
  
  
      
  
杜特网上订单管理系统 getUserImage.ashx 接口未对用户传入的参数进行合理的校验和过滤，导致传入的参数直接携带到数据库执行，导致SQL注入漏洞，未经身份验证的攻击者可通过此漏洞获取数据库权限，深入利用可获取服务器权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCUTRicNXhbwOQx1douVmicwWTpvuLhGtg50CEnOwMycYB3EB4ZcHibNQexqeiaav2kgXaYeeiaqQNJ1dxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**02**  
  
  
**资产测绘**  
  
  
  
  
```
Fofa语法：app="TUTORSOFT-ERP"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCUTRicNXhbwOQx1douVmicwWTHWrDOHCKqKKPNhCzLG4lgS8xktUyIvibTZrktg25361z2APDJjSzUDA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**03**  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCUTRicNXhbwOQx1douVmicwWTC1qibib7HCYhicu5xrwJ5iaxXtDpica8Y8mNaFOdwSNCPI18KTiawNVoTJtA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCUTRicNXhbwOQx1douVmicwWTzadkrsBianjuQbbsc1CqZeBwmFbQkFiasibbB9zkQumrdRChElURGEoHw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**04**  
  
  
**修复建议**  
  
****  
  
  
临时缓解方案：  
1. **使用参数化查询**  
（Prepared Statements）: 通过预编译 SQL 语句，避免直接拼接用户输入。  
  
1. **输入验证和过滤**  
: 严格验证用户输入，过滤掉危险字符，如 '  
, "  
, ;  
 等。  
  
1. **最小权限原则**  
: 确保数据库用户仅具有执行必要操作的权限。  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ssAcvVwPLCUTRicNXhbwOQx1douVmicwWTeKiaiakR84ehbvDM53A153TB7f5WwDA87tLWiaSBvpib3Ygmpn6pu6dNrA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
****  
- END -  
  
  
  
  

#  (未公开)灵当CRM某接口存在文件读取漏洞   
原创 WebSec  WebSec   2024-12-10 12:21  
  
**阅读须知**  
  
亲爱的读者，我们诚挚地提醒您，WebSec实验室的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。WebSec实验室及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
  
  
  
  
  
  
  
**01**  
  
  
**漏洞描述**  
  
  
      
  
灵当CRM某接口存在文件读取漏洞，泄漏敏感信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXP9wksACaZXHPAaPWhlxITGvTIpuudmKAFaEqlhaTMjbbIvAwLe60KrVBdkicEXb5cVicichicYe64fw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**02**  
  
  
**资产测绘**  
  
  
  
  
```
Fofa语法：app="灵当CRM企业版-客户关系管理专家"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXP9wksACaZXHPAaPWhlxITiadDH5VGiaVDPnXuzPFY5mrANTpjjzvicpqWsfc3z7NPcjbOT4tH2rBFQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**03**  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXP9wksACaZXHPAaPWhlxITFyRlKSkDnkkNw3xCsQ6ibiauxUYic2vvRmLUUpVib80tCpeGEvhiaT9nhNw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCXP9wksACaZXHPAaPWhlxITIx2YxS7odzwnq0Awqeiag0xx1BCnq1LiaQC8Vgd6YCMH4h0EEWQnBZaA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**04**  
  
  
**修复建议**  
  
****  
  
  
临时缓解方案：  
- **限制文件路径**  
：始终将文件路径限制在应用程序的特定目录内，避免用户能直接访问系统根目录或敏感目录。  
  
- **验证文件路径**  
：对用户输入的文件路径进行严格的验证，确保路径不包含“..  
”等跳出目录的字符。可以使用正则表达式或路径清理函数过滤用户输入。  
  
- **使用绝对路径**  
：尽量使用绝对路径，避免用户能通过相对路径改变访问的文件位置。  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ssAcvVwPLCXP9wksACaZXHPAaPWhlxITrYYgLW0yoG6NAIteEfXRyZnHZgmSIqqu5uE58KLs8YZy1tH526BZGg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
****  
- END -  
  
  
  
  

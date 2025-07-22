> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNzM2MjM0OQ==&mid=2247498076&idx=1&sn=acc7a4823d45f270ce926bf990ddb032

#  【SRC实战】验证码漏洞  
原创 小恰  隐雾安全   2025-07-22 01:01  
  
**No.0**  
  
**前言**  
  
  
在挖一家大型src时，在一个微信小程序处发现用一个手机号发送短信验证码之后，填任意的手机号都可以绑定成功，造成任意用户相关漏洞。  
  
大家以后挖验证码相关漏洞的时候可以尝试一下  
  
  
**No.1**  
  
**正文**  
  
  
在一个小程序的个人中心有一处收货手机号管理的功能点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkBNABhplmHSn04KbCFYLziaiavSmQmMoUQ0m9FIGYwZkQLicn6zTd7DsSN07eHYuQMSfnw5KAibX2tA/640?wx_fmt=png&from=appmsg "")  
  
  
点进去发现可以添加手机号  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkBNABhplmHSn04KbCFYLz7AHH0iaibTgVSXB7zCAy9EtxXDMnlp1DVSjOC65UFOgrFzNgXDcyjUbw/640?wx_fmt=png&from=appmsg "")  
  
  
但需要手机验证码才可以添加成功  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkBNABhplmHSn04KbCFYLzVluWHmm2O1argVC0IyL1wXRfzNFLVPWmsL1WMveE1q9DuzjgFBnujw/640?wx_fmt=png&from=appmsg "")  
  
  
于是我尝试写上自己的手机号，收到了短信  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkBNABhplmHSn04KbCFYLzOicNkvyfHM6XS074pphcjgT1ewux7h32heEorjFyJejWpKhpUic6KZNA/640?wx_fmt=png&from=appmsg "")  
  
  
在点击提交时，把自己的手机号改成随便一个手机号（18888888888）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkBNABhplmHSn04KbCFYLzSGibqJiazKF3RtNtiatLicrU8lxOGiaW709LTgv4x7tEzeGicicRicIrLrYjbA/640?wx_fmt=png&from=appmsg "")  
  
  
结果添加成功了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkBNABhplmHSn04KbCFYLzW2yTMSVFEl9HmfuicX6zgiaB0Xl4wrEvPArZLHuqYu8GxT6ibYG7mdq9g/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞产生的原因大概是后端没有校验该验证码所对应的手机号，从而导致任意手机号都可以绑定。  
  
  
**No.3**  
  
**网安沟通交流群**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ELQKhUzr34zkBNABhplmHSn04KbCFYLzaicBnckVb673WWl4EdQ3nysmMuiapQ7NaOYo8zbicpLsVqGuZAqdAcE6w/640?wx_fmt=jpeg&from=appmsg "")  
  
**扫码加客服小姐姐拉群**  
  
  
  

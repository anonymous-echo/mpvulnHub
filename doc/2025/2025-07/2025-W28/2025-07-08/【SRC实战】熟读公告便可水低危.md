> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNzM2MjM0OQ==&mid=2247497998&idx=1&sn=be6b9bd71aafa0cdf4bac35bae76082e

#  【SRC实战】熟读公告便可水低危  
原创 小恰  隐雾安全   2025-07-08 01:01  
  
**No.0**  
  
**前言**  
  
  
是这样的，本人在挖一家src某个微信小程序时，在短信发送的功能点发现了有点短信轰炸的影子，在读了src的公告之后，有了挖掘思路，成功挖到了这样一个有趣的短信轰炸漏洞。  
  
**No.1**  
  
**正文**  
  
  
废话少说，直接来到下面的微信小程序  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqibG8dDvzB0Qblnl2Hk5DPjj0tIFgxaLVWiciahnr22CFUB1FiaHhJicE0eA/640?wx_fmt=png&from=appmsg "")  
  
  
在“我的”中有一个“注销账号”的功能点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibq1WFy7w6M2V2aFzqY7XVREQyAjyrwicWZhtfbInJIufX6jh8F9gZtQNA/640?wx_fmt=png&from=appmsg "")  
  
  
点击之后，会有一个发送验证码的功能点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqnGpgrO2aNyq8Be3jMwc3glCVmSnc6zSplv53VYj9MPthttLibN2j3Jw/640?wx_fmt=png&from=appmsg "")  
  
  
直接bp抓数据包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqIUnAoLqXur2bibFgibJFJZ66nicNQ8HmpWZLQ4PGQ0I4yEbn0dc1gLTAg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到“phone”字段为空，我直接就是作死写上自己的手机号，返回如下数据包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqfnsZHQyRAWSMrlhPgPal9vpRE3chXQowlslA3Qx5UiaKPFqDPicZdSDQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以发送，我直接狂点发送键，结果在第五次的时候出现了以下提示  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqm5uGW1vXUd35V3rjhPQkabrATO5d0V8tHg327hxQNiceOibbAEcWdZDQ/640?wx_fmt=png&from=appmsg "")  
  
  
咋办？于是我就去看src的公告，看看短信轰炸的收录标准是什么，如下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibq2b0Cibp7hPfNFZmaic6GuKHa2kND6S2OSrNGmRn3bkC5FZNRIos6m6gg/640?wx_fmt=png&from=appmsg "")  
  
  
每分钟超20条就算？我就想看看能不能绕过，于是我把手机号改为+8613111111111（假设我的手机号是13111111111哈^_^）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibq2CG7ejyCTX363ss117iaGqDmGpzj3Yiahb4aCzcNUcGG2Y4tDf5SBtqA/640?wx_fmt=png&from=appmsg "")  
  
  
发送成功  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqNCIoUk19WR46SzIMC79oCTnIFbOMY0zoNFVUlYRCnkyl8XygIFufHQ/640?wx_fmt=png&from=appmsg "")  
  
  
但还是发了5条就限制了，于是我尝试以下写法  
  
8613111111111  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqwDE3hCjOjoOH4Umr3iceBae4LJdrqeVWawS1ic862RjMvEnkCVmG6AUg/640?wx_fmt=png&from=appmsg "")  
  
  
+86-13111111111  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqVv2gC5whKGZq3ZpLw7qrhiaD4rha3w7D7U8mADh4asCjXFbCVZJsE7A/640?wx_fmt=png&from=appmsg "")  
  
  
86-13111111111  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqADGtzqpPNDianROZxucHonT3Y3VfcDIljs9LnxxCnGdkeGEs8Smichow/640?wx_fmt=png&from=appmsg "")  
  
  
以上均成功发送，这样一来有五种绕过写法，一种可以发送5条短信，5x5就是25条，正好符合收录标准，字典就这样写  
  
13111111111  
  
13111111111  
  
13111111111  
  
13111111111  
  
13111111111  
  
+8613111111111  
  
+8613111111111  
  
+8613111111111  
  
+8613111111111  
  
+8613111111111  
  
8613111111111  
  
8613111111111  
  
8613111111111  
  
8613111111111  
  
8613111111111  
  
+86-13111111111  
  
+86-13111111111  
  
+86-13111111111  
  
+86-13111111111  
  
+86-13111111111  
  
86-13111111111  
  
86-13111111111  
  
86-13111111111  
  
86-13111111111  
  
86-13111111111  
  
  
也是成功发送  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqT06Zt5MS8zaJ5hjvJRHwLl0P0k2YDegoicP1qdVbicWibxiaBsph8Nq3iaw/640?wx_fmt=png&from=appmsg "")  
  
  
美滋滋，又混个低危......  
  
  
**No.2**  
  
**网安沟通交流群**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ELQKhUzr34yhFSKEdeaLia7e7fNJnjyibqCMfGuXhgVicEYjCsFzNDf2w4zZoPsBtHA7T60o9NJiaQV6QJERVmLibhg/640?wx_fmt=jpeg&from=appmsg "")  
  
**扫码加客服小姐姐拉群**  
  
  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247493126&idx=1&sn=0c477858639004e35491ba258a01cc25

#  【红队APT】钓鱼邮件的制作与SPF绕过  
zero1234  神农Sec   2025-07-13 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：zero1234  
  
文章来源：https://www.freebuf.com/articles/system/427451.html  
  
  
**钓鱼邮件的制作与SPF绕过**  
  
  
## 引言  
  
还在愁外网挖洞挖不到嘛？还在愁没有0day打不进内网吗？还在愁没有账号密码测试系统吗？从现在开始，不用在忧愁了，我们直接gogogo，快速的学习一下钓鱼邮件的制作，让我们不废吹灰之力，拳打老弱病残~  
## 你能收获什么？  
  
1.利用kali自带工具去伪造发件人  
  
2.明白SPF是一个什么东西，如何去绕过SPF，从而伪造发件人。  
  
3.利用gohish工具制作钓鱼邮件模板、钓鱼网页、伪造发件人、捕获账号密码。  
## 正式开始  
  
废话不多说，冲冲冲  
### 知识点一：手动制作钓鱼邮件  
  
钓鱼邮件的制作的要点：  
  
取得受害者信任邮件：发信人地址，邮件内容(话术)，兴趣话题  
  
然后就可以在受害者的信任邮件中嵌入：嵌入网页配合钓鱼 (模拟真实网站)、嵌入文件配合钓鱼 (压缩包，文档类等）  
  
那么如何制作一个钓鱼邮件呢：  
  
首先我们可以随意的找到一个临时邮箱地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa735CWPian7UibaSKbfrXrAY9zPQt2ibwiaibhcLtRDFTpDGRzRia9DFbuNZA/640?wx_fmt=png&from=appmsg "")  
  
直接搜索即可，网络上有许多免费的临时邮箱，而使用这些临时邮箱也可以作为反溯源的一部分。  
  
https://temp-mail.io/zh  
临时邮箱地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa4XlRx1m862sttyHDfqfXpUXDD75ShjsW4NVOg3JkTGnG3S9KsXtGGw/640?wx_fmt=png&from=appmsg "")  
  
那么我们首先用一个  
QQ  
邮箱给他发信息看是否能正常的接收：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaquUIhkqlCydn4iaAUWJAUadRrjFBDkbDoHXS7hLibiaWnJS9B06ib26SYQ/640?wx_fmt=png&from=appmsg "")  
  
收件人就使用刚刚自己申请的临时邮箱即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaUCyDK8JwSs6EHibzuib8T6maTl7e4Ov17GFbteNCWpJecJUyd60uicDHw/640?wx_fmt=png&from=appmsg "")  
  
这里收件人报错了，那么我们就换一个可以显示发件人的就好  
~  
  
链接：一次性临时电子邮件 - TempMail.Plus  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaShzshP7YYu8eibc9U452ptjCNo1HlO6HkKPmv3dtKPuZArlB77BHQCQ/640?wx_fmt=png&from=appmsg "")  
  
这里就显示了发件人，你的  
QQ  
号加上  
qq.com  
对吧  
  
那么我们最想做的一个件事情，就是伪造发件人对吗？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaeB5atiaLVpKlILeBnfKsaicvcPfaAdIEEyzbamydtH0DhHYGO5CFjoXA/640?wx_fmt=png&from=appmsg "")  
  
比如说伪造为拼多多的发件人。对吧，这样钓鱼才有真实性。  
  
那么提到伪造发件人，我们就绕不开一个知识点：  
SPF  
  
这个决定了我们是否能绕过发件人。  
  
那么什么是  
SPF  
呢？  
  
发件人策略框架（SenderPolicyFramework）电子邮件认证机制，主要作用是防止（伪造邮件地址）、伪造发件人  
  
如何查询某个域名的  
SPF  
策略？  
<table><tbody><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">dig </span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">-t </span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">txt </span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">qq.com</span></span></p></td><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">//linuxn</span></p></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span lang="en-us" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">ns</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">lookup -type=txt </span></span><span lang="en-us" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">q</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">q.com</span></span></p></td><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">//windows</span></p></td></tr></tbody></table>  
查询过后的返回含义是什么呢？  
<table><tbody><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;height: 35px;"><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">&#34;v=spf1 -all&#34;</span></p></td><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">(拒绝所有，表示这个域名不会发出邮件）</span></p></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;height: 35px;"><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">&#34;v=spf1 +all&#34;</span></p></td><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">(接受所有)</span></p></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;height: 35px;"><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">&#34;v=spf1</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">ip4:192.168.0.1/16</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">-a</span></span><span lang="en-us" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">ll</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">&#34;</span></span></p></td><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">(只允许192.168.0.1/16范围内的IP发送邮件)</span></p></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;height: 35px;"><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">&#34;v=spf1</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">mx</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">-all&#34;</span></span></p></td><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">(允许当前域名的mx记录对应的IP地址发送邮件)</span></p></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;height: 35px;"><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">&#34;v=spf1 mx mx:test.example.com -all&#34;</span></p></td><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">(允许当前域名和test.example.com的mx记录对应的IP地址发送邮件)</span></p></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;height: 35px;"><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">&#34;v=spf1</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">a</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">mx</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">ip4:173.194.72.103</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">-all&#34;</span></span></p></td><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span leaf="">(允许当前域名的a记录和mx记录和一个给定的IP地址发送邮件)</span></p></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;height: 35px;"><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">&#34;v=spf1 include:example.com</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">-all&#34;</span></span></p></td><td style="box-sizing: border-box;margin: 0px;padding: 4pt;border: 1pt solid rgb(163, 163, 163);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: top;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;height: 35px;"><p style="box-sizing: border-box;margin: 0px 0px 10px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: 15px;line-height: 26px;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;max-width: 100%;color: rgb(51, 51, 51);word-break: break-word;white-space: normal;"><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">(采用和 example.com一样的 </span></span><span lang="en-us" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">SPF</span></span><span lang="zh-cn" style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;word-break: break-word;"><span leaf="">记录)</span></span></p></td></tr></tbody></table>  
例如：我们查询QQ的SPF策略  
  
![1744619320_67fcc73845a9de32dfe02.png!small?1744619229024](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaU6FDCCer5UmiajkrhhHkBECqaCiaqd7PQviaeIxYtcIWKiceWxh9tDZTlA/640?wx_fmt=jpeg&from=appmsg "")  
  
这里就是采用和spf.mail.qq.com一样的策略，那么继续查查spf.mail.qq.com  
  
![1744619349_67fcc755088807c202119.png!small?1744619257825](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa80SuB9rEzoJIricDReWYNSNlLKOTsakWxQKyrByWCRBb9gUHWM2LvzQ/640?wx_fmt=jpeg&from=appmsg "")  
  
那么这里就表示严格拒绝（  
-  
all  
）所有未在 SPF 记录中明确授权的 IP 地址发送邮件，保所有合法发信服务器均已包含在 include 列表中  
  
什么意思呢？  
  
例如，若攻击者试图伪造 @qq.com 域名发送邮件，但 IP 不在腾讯的授权列表中，邮件将被直接标记为伪造并拒绝投递。  
  
嘿嘿，真的嘛，我们一会试试看。  
  
但现在，我们先试试看一个成功的案例吧，首先需要用到  
kali  
的一款自带工具，或者去其他地方下载也是可以的  
  
工具名字：  
S  
waks  
  
http://jetmore.org/john/code/swaks/  
  
首先我们使用命令：nslookup -type=txt mailto.plus  
  
![1744619575_67fcc837e421bd8bf954b.png!small?1744619485433](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaL7W6yrEtN4xo0iazibf1C6qqs4rnOx3N8dF54St3nLXicGR2R4PztX8oQ/640?wx_fmt=jpeg&from=appmsg "")  
  
若某封邮件声称来自 mailto.plus，但实际发送 IP 不在 mx.fex.plus 的 A 记录中，收件方会判定为伪造邮件。就是这个SPF的策略了，但这不影响我们伪造qq.com的邮箱~  
  
打开  
kali  
，打开终端，直接输入命令：  
  
swaks  
--header-X-Mailerr "" --header-Message-  
Id ""   
--header-"Content-Type"="text/html"  
--from "admin@qq.com"  
--ehlo  
shabimeiguo  
-header  
"Subject：测试"  
--body 我们做了一个测试  
--to  
yeqiu@mailto.plus  
  
我们暂时只用知道这两个参数就好了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaCVHRuoicNBaV9pA82I6pWtvUEEQSibWlmaFTvJdlu3LDHPcG6NXHibFtQ/640?wx_fmt=png&from=appmsg "")  
  
  
![1744619382_67fcc776167ddcade3999.png!small?1744619292396](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaGSE3oTWDSxpUAyiclyQLibm2BSw4RF8AvpHnqPMnZZFuRkXD4dI4KSxA/640?wx_fmt=jpeg&from=appmsg "")  
  
这样就发送成功了，去看看临时邮箱里有没有这个东西：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaacYB3KMs79wC9DRiaIExtA27L8lPtX6p0ibkkCDNO4iaticyrziaib7rb5AQ/640?wx_fmt=png&from=appmsg "")  
可以看到发件人成功伪造为了admin@qq.com![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaAwibYFFcU0JOUaxtmVUhceeq56SUnkqWiakF7yeg2CcJnOLIxLkZPibyw/640?wx_fmt=png&from=appmsg "")  
  
  
我们伪造一下拼多多的域名看看invoice@pinduoduo.com  
  
![1744619823_67fcc92ff37a89aa3dc04.png!small?1744619733050](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaYvQJSr7QjcfIJ6mXKn66njdXIicbgxWvXIPdTXicBRYK0Lz9Io06VRXg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaCMOtstr5Pvrn7vXgEzsiaDKQO6Zibmic1iaiaiaoVMTw0hNdibMF5V5ZIzydg/640?wx_fmt=png&from=appmsg "")  
  
![1744619831_67fcc9375df33e4d44744.png!small?1744619740072](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaakecxq89myCIjLANIloJDtjkRF62JWlONvBjKsN9P3mIt2gRg1sOnbA/640?wx_fmt=jpeg&from=appmsg "")  
  
是不是和拼多多的电子发票一模一样  
~  
  
那么我们说的  
SPF  
的作用呢？当我们将收件人伪造为  
admin@qq.com  
发送到  
QQ  
的邮箱试试  
  
![1744619846_67fcc9462b9ad54a035ed.png!small?1744619756160](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaSlkwXTcFYFw9Xs4zaMa4B8skHn3MibUcF93p1gX07Z9kgqpmJQnChBg/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到提示：服务器返回55  
0  
错误（永久性失败），明确拒绝并指出问题：SPF验证失败。  
  
这就是  
SPF  
的作用了。它会验证你发邮箱的服务器（或者是你的电脑，是否在它的白名单中，如果不在）那么你用admin  
@qq.com域名  
，它检测admin@qq.com用户的ip和你的ip是否一致，如果不一样  
就会进行拦截不给你发。所以我们有什么办法可以绕过呢？  
  
首先是视觉绕过法：将  
o  
改为  
0  
  
![1744619926_67fcc99635502fa73fb8d.png!small?1744619835363](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaVnoNnhibsU9jExeWGMIpVwPIKA8RrlQibXZr03ic2F22CYy96Rpe8DtHw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaibpxFciakGTm13NCYdOfia9ezibIZzhZBFeRd2N2OMicFCdr6zicq8Ekxnjw/640?wx_fmt=png&from=appmsg "")  
  
很可惜，虽然成功发送了，但在QQ的垃圾箱中，这和邮件服务器的策略有关~  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaAc05RV2PsrkmQQsLdEQ2ledU1dgr0nDsicLzWLibgqVuH5icB9HoI17Vg/640?wx_fmt=png&from=appmsg "")  
  
但伪造却成功的伪造了  
  
那么我们其实可以多打几个，尽量规避  
~  
  
![1744620011_67fcc9eb70a1de790aed0.png!small?1744619921845](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaapqzaOJ1sdt46FOAzicaGDwL3ToeGv6Pe27DDRpPffxhSW5qeOiaoUZSQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620021_67fcc9f5063e93d3c059d.png!small?1744619929766](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaarUAC6XicvbqfaqBo07NKLyhoiaGZLFibFQ6Szsj9GI3x7XvcLRSKA1ubg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaSQaaqRnMoQG3obLrSncF9eQicOwvc0vpvvX5cls8kqadTKNXyMVdRdQ/640?wx_fmt=png&from=appmsg "")  
  
这样就成功规避了  
~  
  
总而言之，言而总之，有  
SPF  
验证，我们绕过的方式有两种，一种是：  
  
修改后缀，也就是修改我们  
@  
后面的域名。将  
0  
改为  
o  
，将  
i  
改为  
1  
，等等这种后缀的绕过  
~  
  
第二种是：  
  
通过自建服务器，当然，这个门槛比较高，下一章再讲  
### 知识点二：gohish钓鱼平台搭建  
  
说到钓鱼呢，就不得不介绍一款成熟的工具：gophish  
  
这款工具我觉得最大的好处就在于：低门槛，上手快  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaRqEZxicGNPJbNb4yYVfvfITCNDGbUoF2m55euhJDuHiafnRCzc3nXb6w/640?wx_fmt=png&from=appmsg "")  
  
链接：https://github.com/gophish/gophish/releases/tag/v0.12.1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa2tCxKFLCXHVxXQk3RR8nX7OyBp0SdHLTJzCZR7S1tEGLy9Aer6B4zw/640?wx_fmt=png&from=appmsg "")  
  
![1744620071_67fcca271bfae820def31.png!small?1744619980968](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaZnYkWgDgfL4iaVW5Kcof9GLk1P7JgWqmaksqUTtYM9gibl9Qu6h2eq5w/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620074_67fcca2ad93e80598163c.png!small?1744619984089](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa7dyJewT8ewsmAQEA3wg7BGTRGvNsv9Wn5yDFR2Qiaps6MlPNAXetLpg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620078_67fcca2e3a8e74a071e3e.png!small?1744619987609](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaapKDj6ppiacqYcFeIRnicTr4ZRA5r6uia65ialAccJ0ria23MvhGrdlPhwdw/640?wx_fmt=jpeg&from=appmsg "")  
  
简单吧，然后我们访问  
https://127.0.0.1:3333  
  
![1744620098_67fcca42319c61ad72b02.png!small?1744620007022](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaugl7XAd4xK3R3HuKHib40NMf0DqpOgBookeUbOT7QtnzANV3TQmAJDA/640?wx_fmt=jpeg&from=appmsg "")  
  
如果不想在虚拟机中操作，可以查询虚拟机的地址：  
  
![1744620107_67fcca4b789dff2d0f4f1.png!small?1744620016570](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaiczRAdVmtRqxibLib2kftH1icEYrU5vvlndrXibBWWs5PhH7EkE7QiaZWnXA/640?wx_fmt=jpeg&from=appmsg "")  
  
https://192.168.249.222:3333/  
  
![1744620116_67fcca54cd4eeb03acb0e.png!small?1744620025620](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaahVxibOWSJxbNRiclCtWDDM9W7nKpIibRcQu357Nl8kDt1pJa6846C0s2Q/640?wx_fmt=jpeg&from=appmsg "")  
  
也是可以成功访问的，访问以后呢，就简单了，输入账号密码。  
  
![1744620133_67fcca6532a4a1064e9cd.png!small?1744620041948](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaoaic94SyicMsicQVy8lHW0aDHGDSzVWR38PiaYb536fvEOcbd4hdsED1ww/640?wx_fmt=jpeg&from=appmsg "")  
  
  
设置一个新密码，后就可以登录进来的，首先要进行邮件配置  
  
![1744620148_67fcca74a3817059e0786.png!small?1744620058043](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaPG5G4Oc8CmUPItNgWQo2bXRoo6NZz5TWNQp2c6WdZGibCfDiaicwJZfzw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620152_67fcca780d8bbf4657b30.png!small?1744620061066](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa7p8Q3rnib6qrv84LY1icHl2M2UR2SNpKDqusMr0hW3I7N7cicz7o65HBg/640?wx_fmt=jpeg&from=appmsg "")  
  
照这样格式填完就好了，这里  
QQ  
邮箱是我瞎编的，不要瞎搞噢  
~  
嘿嘿，比如拿我作为钓鱼邮件测试  
~  
  
那么  
P  
assword  
是  
QQ  
号吗？显然不是，这个是要通过  
QQ  
邮箱开启的  
  
![1744620166_67fcca8649457c27cecf6.png!small?1744620075373](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaawE6VdZBr9cM3icFU3GCUCwFBDhMfGAw61AQNCRnnz0VgoyRqYfM3aGw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620200_67fccaa89ff07a1e98014.png!small?1744620109605](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaatuS7Q8dXYv0FicdibEF6BSODH6GSevib9bK4FJnPrnh1chuMXibQicbIb5A/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620207_67fccaafc977b9bfa1094.png!small?1744620116734](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaadYYJMC6Q3FQ3HkRvB2xicVlLJNibgQxXbUJArNFPobrdABHxTlyM7DibQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620211_67fccab3a65590efe1fce.png!small?1744620120587](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaibeiauGibfHvuxNBmQrurUeJlsF7PB2WkNj3auxDj43LxuBBCuu94ibSgA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620215_67fccab754d0f76fd443e.png!small?1744620124101](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaQsnqO0RgOdiaWbH1Lk4K9jMfic8vMRhLaL2LFa7n9csLKwbJdAbNozQg/640?wx_fmt=jpeg&from=appmsg "")  
  
去根据验证发送，然后开启，复制一下授权码：hqvvub  
xxxxxxxxxx  
  
![1744620222_67fccabe90c6146cb96d7.png!small?1744620131618](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaxwd0MVpcQYicl6qABaNj5Brjzs9XoO0vQ73rvt584bq6tWcgVKcK4bQ/640?wx_fmt=jpeg&from=appmsg "")  
  
就可以发送测试邮件了  
  
![1744620232_67fccac8a1cfda55dc349.png!small?1744620141613](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaCRMFsjn3kxUia87qnm2SBULTuCNa4Sr2CdnOxsTq6ug6W9MesDXoERA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620236_67fccacc985d059a64c74.png!small?1744620145855](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa4Y9rHdtdzDqKrdIPdeaulsGKuJeDBRO1FFMeibK9SIrfDDaOtuEQ7Rw/640?wx_fmt=jpeg&from=appmsg "")  
  
这样去  
QQ  
邮箱查看，能查看到就代表设置成功了  
~  
  
![1744620246_67fccad60910e6c6391ff.png!small?1744620154896](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaFia8bQA3ez17VBSTTXm33BcJkl4rHZlwOyne5LR7fxSu7eboNalqrIg/640?wx_fmt=jpeg&from=appmsg "")  
  
那么就可以去设置下一个  
  
![1744620261_67fccae51d7b190694c2d.png!small?1744620170175](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaahkDYliasPK8yiac890TnQhwmIc0kFLjeMO2vULePySQkTokKfZykNZVg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620264_67fccae8d658c05cbc197.png!small?1744620174176](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaiasribVCP5yA7DDvQe25icgxGh8ErcYicg9uvVOGbCNAzZS1C8N2jCmLzg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
我们可以就以百度这个做一个造假的页面：https://www.baidu.com/index.php?tn=75144485_4_dg&ch=1  
  
![1744620280_67fccaf82ea640854ebed.png!small?1744620189145](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaGoehw0rLJWU2U4ATFz1Tgz7KqPib6r9ztKiaPQTK65GDc4BnysqKmMQA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620283_67fccafbf3cad973630fb.png!small?1744620192896](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaabK8EiaUoVC3fZtRibMRIDIh0J7g7QdVibKxRqWa9Kd5OkxACtNJGwVUWw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620287_67fccaffc97a0d289a95b.png!small?1744620196902](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaso2UXGibToz6juBmNq6t65J6mVyiaYkibSxRoVv9P4guiaj7GPtoFqKMibQ/640?wx_fmt=jpeg&from=appmsg "")  
  
密码我们先不填，跳转我们填写：https://www.baidu.com/  
  
![1744620298_67fccb0a80cef7a85614b.png!small?1744620207462](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaayBrBcTZtS3arWLHDA2sFQAg1shODDEccM5pBiatLJr1fGqqjXKOD7NQ/640?wx_fmt=jpeg&from=appmsg "")  
  
下一个，钓鱼邮件模板  
  
![1744620320_67fccb207204cf302555a.png!small?1744620229384](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaayWwu7JCZM4j0hJR6XFXFRh8wgbanNM85oMavkkuGEaPefazvkhUXxA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620324_67fccb2444bcee81b1204.png!small?1744620233296](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaYmwuzwCTmt74icsgLNC7RjzLb3lj3Q0WVgRokBXibiakbbrY1mtzB8XAg/640?wx_fmt=jpeg&from=appmsg "")  
  
怎么做呢？比如我们要伪造一封官方邮件：  
  
![1744620369_67fccb51a661426ae0d6c.png!small?1744620279059](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaRO6SsyGYs5I9lAhSqKoPRQOYZvJacVHBzButh9h6o1EwjlicFXnW3Eg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620375_67fccb57493a0de8d6e26.png!small?1744620284452](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaIrxBYuCUldhQYKe4TVY9PbibgAoN3GdnTq1B9rQr81hVUp6bRZibicMbA/640?wx_fmt=jpeg&from=appmsg "")  
  
然后将内容下载后，使用记事本打开，复制。  
  
![1744620396_67fccb6cd9524b844ca1d.png!small?1744620306021](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaqPgPjrAtnhjndXV1uMPtNa2ibB3s2XYrDbeCeQqL8RXN3LoXOYch8Lg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620402_67fccb72399ec61a712ec.png!small?1744620311160](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaKcickHSniad3wqEB6p1b7v0NVnHeickcKrIEhhicVBjA6VgTIgiaAHVrFPQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620447_67fccb9f2890b490ad19a.png!small?1744620356421](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaKmG89BKsJkqtqEwiaB2DwlCudJ0dn3tFNia91PwLYtQjGzpWyM2wQBjw/640?wx_fmt=jpeg&from=appmsg "")  
  
你看这是不是就是一模一样了  
~  
  
![1744620468_67fccbb47869b32903d9a.png!small?1744620377626](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaibygibSLicqkBmgsMxrU4LrxHiasZwTuBPqHgUqEZawbGBUaDzTKjIL9zQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620471_67fccbb7a547e12a254b8.png!small?1744620380581](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaWlqBUnKaSlBv1BPHCYxOicO6HrZPgYrQWpLvJ5pIlbhDcI13nBdeQ4A/640?wx_fmt=jpeg&from=appmsg "")  
  
通过这里就可以达到邮件上传附件的效果了。这里就不添加了，自己试试就好  
  
![1744620486_67fccbc6e4ec5c337ed5a.png!small?1744620395782](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaOznIicI7C2xnxtYXwZHmgnXGLSHVIxnY2NQGBibhMBjzgZ0r4h87efzw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620490_67fccbca415642d4e3756.png!small?1744620399396](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa6lutdjI7e8U6r71sfxV94QxiaLMLyndicoogKjqmqrSSC8ibmVBaxfrqg/640?wx_fmt=jpeg&from=appmsg "")  
  
都创建好了以后，我们就可以创建攻击目标了  
  
![1744620506_67fccbdac693501ed1472.png!small?1744620415695](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaN3YUxQCMxh80OXrpE0M6ia2JODiaBI218kYGXuUfiaHa5KnBR9lo6ibMXA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620510_67fccbde4725c8abb30b0.png!small?1744620419383](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaFWRl0pJFL7OTn6OMX86jYItViaNEpL98FAHuiaPcWlWkcYhoaO6t1AxA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620514_67fccbe2978b6073683b8.png!small?1744620423863](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaic3nzkogJGeDBT6uD15jGzbbqhQMuNAwh0MHLe8nvHP6vWS9dg9s8ug/640?wx_fmt=jpeg&from=appmsg "")  
  
这里可以看到  
80  
端口，这个  
80  
端口对应的设置是：其实也可以不设置，因为默认80端口  
  
![1744620524_67fccbec8bff331075ee0.png!small?1744620433712](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaJcomiarqu88pZnf5aGcwHSiayIUy9driaWhmpMAmsStu8LPggXG9umOrA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620538_67fccbfad5297326efc46.png!small?1744620447785](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaawdVMU2va9fnQWWf1YAH8R0zo2VSVYM6HdIV7ibCupswBrewLiaBaLSaA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620542_67fccbfe13af153d63744.png!small?1744620450904](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaadQzQ1HQpbST1fda5ibtE2J0knjQcWa0OCu7yjsSqRBXtqAD2IeDuWRA/640?wx_fmt=jpeg&from=appmsg "")  
  
发送即可  
  
![1744620551_67fccc07b6edde5347cb4.png!small?1744620460670](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaSDD1VDqgP4EuKsialWrK81ibSiaBXMwar13rymGWBQMo2ViaiaRXhKG0ejA/640?wx_fmt=jpeg&from=appmsg "")  
  
发送后这里可以查看邮件的状态，这里提示  
550  
，那么八成就是伪造发件人的问题了  
~  
，我们需要去更改  
  
![1744620562_67fccc1297a4a9d0630bd.png!small?1744620471713](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaTEwDx44YD1J22Reib7mDSHFFn5W7np6DOkWRibwAyl5mkVI6FUt9Rvcg/640?wx_fmt=jpeg&from=appmsg "")  
  
改为带上你的  
QQ  
号  
@qq.com  
邮箱即可，  
然后我们再发送一次。（这个地方呢，就是我们要搭建邮件服务器的地方了，如果搭建了邮件服务器，就可以设置一个和其相似的域名也可以成功的发送，这里就先改为QQ号。）  
  
![1744620622_67fccc4e9c9885c62a1d4.png!small?1744620531549](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaz7jHv2RDibdDI5RRQ26x887eE29ceUaKq81w3DZCIs7kltOPXvnBRDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
就能成功发送啦，然后我们去看看邮箱  
  
![1744620643_67fccc6301087dfcff0d6.png!small?1744620551948](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaAC0TzCI2GyzbuUrfNWu27vI2cFryuibHAoJiazjSVJ6Zvt7V1xt8c3hw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744620735_67fcccbfd86aaa31ad77f.png!small?1744620644992](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaatnFmiaOYwkUmyuXN88qPxJKTCB3GVLzekDhvuzKYYZmM0ah6AKs13xA/640?wx_fmt=jpeg&from=appmsg "")  
  
点击链接看看  
  
![1744620750_67fcccce06c41ad02600c.png!small?1744620658991](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa7aOLibAIWMEiaj4qn1rGw3IE7CG1mACE5UU2MjoZSibhFX1pDzdUXviaZA/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到，这里就有你的  
IP  
地址，继续访问  
  
![1744620759_67fcccd79976b3aa44809.png!small?1744620668518](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaazIxrZEzAetic1U5cEqw1nFDVfq0NC5XWibBO5SGA1wpddHm83r7sfQxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
假如你输入一个  
123456  
，点击百度一下  
  
![1744620769_67fccce11e908a56a7839.png!small?1744620678199](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaapBtWnUOWUsInN94EMHXOyBicXD7jyazLrrDgHxdCzGIxwsAYzejg0qA/640?wx_fmt=jpeg&from=appmsg "")  
  
跳转失败了  
~  
，这是因为一些页面的克隆需要修改，所以我们需要去克隆一些简单的，或者后期自己去修改克隆的代码  
  
为什么要踩这个坑呢？因为很多时候都需要我们自己去修改一下克隆的代码，否则无法正常的使用  
~  
  
这里就是告诉你们，这个克隆功能并不是百分百克隆下来就能用  
  
有一个百分百成功的案例：  
EDUSRC  
  
![1744620779_67fccceb6e0f10296ddcf.png!small?1744620688355](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaamqPXUgGSluib2iaCzr2114G2Pvw8SUuar86xnMibqcQlepj9o3eA79oVw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
顺手打开记录的密码和账号按钮  
~  
  
![1744620817_67fccd11aaa76cc1a0abd.png!small?1744620726677](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaGJqWuFYtI5AIwaTutYFE9djSQTxsJjiambkGb3r9t5icI6fuibSfgkqnQ/640?wx_fmt=jpeg&from=appmsg "")  
  
跳转还是设置百度  
  
然后发送  
  
![1744620826_67fccd1aaed4c31c5c485.png!small?1744620735561](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaarx51ibwy8LjqXdUiaqWekoeXibzejtuslnRRIETleVCPGyZ5BaDoW6Egw/640?wx_fmt=jpeg&from=appmsg "")  
  
成功跳转  
  
![1744620833_67fccd21c9da8220fe433.png!small?1744620742915](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaa86WIOpeq55lk6ShrqObXp02rEsk8EMrKolc6qlPvv9sIlHrqFF1aow/640?wx_fmt=jpeg&from=appmsg "")  
  
查看大屏记录  
  
![1744620844_67fccd2ccbc2491bfd361.png!small?1744620754026](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaviaHchGde1rsniawwYqaazHIllpQnSjsanUx7X0SmU7ZPQ80HXzIiaaIg/640?wx_fmt=jpeg&from=appmsg "")  
  
返回大屏也能看到我们输入的账号密码  
~  
  
好玩吧  
~到这里就基本结束啦~  
## 注意事项  
  
1.  
捕获账号和密码这个格式  
gohish  
是有指定的，大致是要满足这个格式  
~  
  
![1744620890_67fccd5a09dc45c21c100.png!small?1744620798846](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVb5ic4kRHbm408dyL1icWYiaaaNVzWkjibaHDwSdib8nIsU5wSI2xU3aVZ7aH4vr2zQGtT7KwAUzupYxw/640?wx_fmt=jpeg&from=appmsg "")  
  
具体代码  

```
<form method=&#34;post&#34; action=&#34;&#34; id=&#34;loginForm&#34;>
            <table>
                <tbody>
                    <tr>        
                        <td>用户名：</td>
                        <td>
                            <input type=&#34;text&#34; name=&#34;username&#34; value=&#34;&#34; />
                        </td>
                    </tr>
                    <tr>           
                        <td>密码：</td>
                        <td>             
                            <input type=&#34;password&#34; name=&#34;password&#34; value=&#34;&#34; />
                        </td>
                    </tr>
                    <tr>
                        <td colspan=&#34;2&#34;>
                            <input type=&#34;submit&#34; name=&#34;按钮名字&#34; value=&#34;登录&#34; />
                        </td>
                    </tr>         
                </tbody>
            </table>             
        </form>
```

  
2.  
发件人的伪造，需要我们去搭建邮件服务器，去申请域名，搭建邮件服务器下一章讲  
  
3.  
如果想真正的完成钓鱼，记得搭建在公网服务器上噢  
~  
（就是在阿里云中完成刚刚的操作就好了  
~  
），但邮件服务器不能搭建在阿里云与腾讯云中，会很麻烦。  
  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```

  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于1000人 45元/年  
  
星球人数少于1200人 65元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXYSHg6L72Acqz6CcxdTTR72ic6bOSuMibJkYgVvibYfvrIwxESqR5TL8qrZhUQicKTUGeOic4VMibicF6Mw/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满1000人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXYSHg6L72Acqz6CcxdTTR7Fotibpcs8XRn33xic5cMHaRIVPPBX9pJynCUQ7II1kBnsQCfzwXSToMw/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  

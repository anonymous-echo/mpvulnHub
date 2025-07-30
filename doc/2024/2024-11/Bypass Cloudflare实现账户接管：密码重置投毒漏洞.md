#  Bypass Cloudflare实现账户接管：密码重置投毒漏洞   
原创 白帽子左一  白帽子左一   2024-11-19 04:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
今天的文章将深入探讨一种账户接管（ATO）漏洞，并分享我是如何绕过Cloudflare的保护机制，利用密码重置流程来进行攻击的。这个过程被称为密码重置投毒（Password Reset Poisoning），让我成功地获得了对用户账户的未授权访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR49jUia1dlxxBNRSricHicIticnggDbofiaIT1s2iciajxXYevffCZVhWTtobiaA/640?wx_fmt=png&from=appmsg "null")  
  
img  
# 什么是密码重置投毒攻击？  
  
当您忘记密码并点击“忘记密码”时，网站通常会将密码重置链接发送到您的邮箱。这个链接应是安全且专属于您的。但在密码重置投毒攻击中，攻击者会找到一种方式修改或“投毒”网站发送的重置链接。这可能使他们能够控制重置流程的某些部分，例如将链接重定向到自己或操纵链接以达到他们的目的。  
  
回到本文，我将分享我是如何通过密码重置投毒在绕过Cloudflare保护的情况下发现并利用账户接管漏洞的。  
  
出于安全考虑，我不会透露实际网站或程序的名称，因此将其称为“traget.com”。  
### 开始  
  
我通过Google Dorking寻找漏洞赏金计划时，发现了几个域名参与了漏洞赏金计划。我选择其中一个作为漏洞挖掘的目标。在15分钟内，我就发现了该域名的多个漏洞并提交了报告。  
  
接着，我决定优先测试账户接管漏洞。我尝试了登录页面，但无论输入什么payload，都会被Cloudflare拦截。于是我考虑尝试主机头注入（Host Header Injection），但尽管花了大量时间尝试各种绕过方法，Cloudflare仍然将我的请求拦截。  
  
我尝试了所有可能的主机头注入绕过方式，例如添加“X-Forwarded-Host”头、“X-Forwarded-For”头以及“X-Original-Host”头。我还尝试了使用自定义头以及诸如“Forwarded”、“X-Host”和“X-Forwarded-Port”之类的变体。此外，我测试了这些头与各种payload的不同组合，试图欺骗应用接受恶意的主机头。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR4pbRIVTicrFhc3LV7YgBHx29icicXTUEyWROz1bsbXg3KtvKFzk3cpB3Rg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
但我仍然没有成功。随后，由于速率限制，应用暂时屏蔽了我的请求。在观察请求并思考如何绕过保护时，我注意到一个细节：发往主机的域名是 **app.target.com**，但密码重置链接却来自 **pay.target.com**。由于这两个域名不同，我推测可能存在两种情况：要么服务器从请求中获取域名值来生成重置链接，要么是通过服务器端配置生成的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR4NmaqUFOwM7TXSTg52fr8sxGQNUc3x6caC98UQ84ib2qv2O7Qf9ZHgNQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
接着，我注意到 **Origin** 头中使用的域名是 **pay.target.com**。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR40BgbQmpHPlkic6ymybqvrmibd9car8k9EIto9DMlYQJhwstmmMmY4icBw/640?wx_fmt=png&from=appmsg "null")  
  
img  
# 什么是 Origin 头及其工作原理？  
  
**Origin** 头是一个HTTP头，用于指示请求的来源，包括协议（HTTP或HTTPS）、主机名和端口号。它主要用于安全目的，特别是在跨域资源共享（CORS）场景中。服务器可以通过Origin头来判断请求的来源，并基于此信息决定是否允许或拒绝访问。  
  
在这种情况下，我认为服务器可能并非使用请求中的主机值，而是利用了Origin头的值来生成密码重置链接。这意味着，如果我能够在请求中修改Origin头的值，就有可能控制重置链接中使用的域名。  
  
因此，我将Origin头的值从 **pay.target.com** 修改为我的Webhook网站的URL，然后发送了请求。  
  
这一次，Cloudflare没有拦截请求，服务器也接受了该请求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR4icRtGc4zcicw0Lbzg8rIDEibnOhpw7UFAAtwCwYLaHRaReO283eaKMLLw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
然而，网站显示了一个客户端错误，提示密码重置邮件未发送，并建议稍后重试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR4UUB7qghFggG5zjRmU6ooux6tBibPJA8j5VWIQJY2MadpYvlXlJI9wIA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
但当我检查我的收件箱时，我发现我已经收到了重置链接。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR4OvPianiapC44sECVFaEN1FQFbzoicgafzOnNxYIib2fasEz2XeseicrHic9Q/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR4UIOuHmoicicoMMFwIrTPxpotWdvXaZWDklq9de5ibxo2HOwjNjZxricCyQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
然后我点击了重置链接。刚一点击，网站并没有将我重定向到重置页面，而是将我重定向到了我在 Origin 头中注入的 webhook 网站域名，并带上了重置令牌。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR4m2x4827Xota4m1Ufb2BjEoUG2LeSeibOwaTLp2erIAnIfcAJgnXYiayw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSH2QElKiaicerFjDOG7tvxhR4joMCNQVN8ygHH1QQB46W8ic5RStlPicYu3IsCnzuKYxzib4eDcFvpLfqQ/640?wx_fmt=png&from=appmsg "null")  
img  
  
如果攻击者获得了重置令牌，他们可以利用该令牌重置密码并控制受害者的账户。  
  
以上内容由白帽子左一翻译并整理。原文：https://cybersecuritywriteups.com/cloud-flare-bypass-leads-to-account-takeover-via-password-reset-poisoning-ba349d784b97  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  

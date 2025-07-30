#  价值$3000的Google Slides IDOR漏洞   
 芳华绝代安全团队   2024-12-27 08:05  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvR1Awes6RbHS27L144QMPEl5FPgBicWPWMt4xzB8DcuBTyRgNxOz2nRiag/640?wx_fmt=png "")  
  
[2024年最后一波招生——玲珑安全技能提升班](https://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247499310&idx=1&sn=e9665007697fbf72d31075cab2123923&scene=21#wechat_redirect)  
  
<-点击查看  
  
[关注公众号，阅读优质好文。](https://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247499310&idx=1&sn=e9665007697fbf72d31075cab2123923&scene=21#wechat_redirect)  
  
  
  
正文  
  
某天下午，我在办公室用 Google Slides 制作演讲用的幻灯片。幻灯片完成后，我点击了“演示者视图”来预览。在活动期间，我计划与观众进行实时问答，于是上网查找 Google Slides 是否有相关功能。就这样，我发现了“观众工具”。要启用该功能，需要进入“演示者视图”，点击“观众工具”，然后选择“开始”。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834WBGpicRXNNMcchgb2cMKvC6btphtdVh0OVD9Q9ia3o04iaxHVZsurWcKZg/640?wx_fmt=png&from=appmsg "")  
  
  
开始会话后，系统会生成一个链接，观众可以通过这个链接在演示期间实时提问：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834W7WDqjRicrIJ3MrMmicLNlwAmL6AjF0UXgXZK4hddbOkFricNXFAj2icic6w/640?wx_fmt=png&from=appmsg "")  
  
  
出于好奇，我复制了链接并在 Chrome 的隐身模式中打开，想了解观众如何提问。任何人都可以提问，无需登录。  
  
提问框的界面看起来有些过时，我的漏洞挖掘直觉立刻被激发了。总感觉哪里有问题，于是我决定深入探究。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834WEMUm6opjntKJUcicOKs9ibiaaItQ1NV6rlbdrfmDpmScoGOG59uFLSvicQ/640?wx_fmt=png&from=appmsg "")  
  
  
我启动了 Burp Suite 开始测试。我注意到，每次有人提问时，POST 请求中都会包含一个唯一的 clientId  
。每条评论都有一个唯一的 clientId  
。这让我顿悟——这可能是个潜在漏洞。  
  
  
漏洞请求示例：  
```
POST /presentation/d/e/2QANgcCBH8YIx_f5yfCz0l5len6p5BDFsiROx_rcqbOqYgcByotn7pOpaS3kXb3YYffwepoOXCyzanE8ZCIw/submitquestion?includes_info_params=1 HTTP/1.1
Host: docs.google.com
Cookie: 
Content-Length: 84
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Accept: */*
Origin: https://docs.google.com
Referer: https://docs.google.com/presentation/d/e/2QANgcCBH8YIx_f5yfCz0l5len6p5BDFsiROx_rcqbOqYgcByotn7pOpaS3kXb3YYffwepoOXCyzanE8ZCIw/askquestion?seriesId=d90df436-a253-48a1-8aea-bf5c19761447
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
Connection: keep-alive

seriesId=d90df436-a253-48a1-8aea-bf5c19761447&clientId=e5j7slqfku2&questionText=Test
```  
  
请求响应如图：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834WJlsjibCp8h7F4WQ981Awtb5SQOwubn8bAhJ9EIFMJhbicaThobSLBHhw/640?wx_fmt=png&from=appmsg "")  
  
  
每当有人点击链接，所有提问都会加载，每条评论都带有不同的唯一 clientId：  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834WdYINy32oymPL2UWicuawUXNe66fyA875gRZaZ69c1tHElwYQMPLgwlw/640?wx_fmt=png&from=appmsg "")  
  
  
我立即意识到这里可能存在漏洞。我用两个不同的账户进行了测试。在账户 1 提交了一条“Test”评论后，复制账户 1 评论的 clientId。接着使用账户 2 打开另一浏览器，然后拦截账户 2 的请求，将其 clientId 替换为账户 1 的 clientId。  
  
测试结果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834WLlXzDfiaXzocJcffhhk7ibxbrmhAUDQ88vxbTmIPrChavqfBg3VLf3QA/640?wx_fmt=png&from=appmsg "")  
  
  
账户 1 提交的评论成功被账户 2 的请求修改。这证实了我的假设。更令人担忧的是，这种攻击甚至无需登录即可完成。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834WEnZz2wZxdAjGxiaO8rPd7s5XPXCTBhYuEo2XwPofOb8GvlFOtBg66kA/640?wx_fmt=png&from=appmsg "")  
  
  
报告漏洞  
  
我立刻向 Google 报告了该漏洞。令人惊讶的是，第二天 Google 关闭了报告，称该漏洞的安全风险较低。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834WiaqWpZkkt5uEPhXqnIHVCVrhPoW3yQs5oTaPtLbECNBD7wMpTU95WWw/640?wx_fmt=png&from=appmsg "")  
  
  
但我知道，这个漏洞的影响很明显：无需用户交互即可利用，也不需要猜测或暴力破解 clientId，因为应用本身会直接提供 clientId。于是，我耐心地重新解释了漏洞的危害性。Google 随后重新打开了问题并确认了漏洞。然而，十天后，报告再次被关闭，理由仍然是“需要猜测 clientId，因此风险较低”。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834WE4YcjCpWdKEh3rSYDQVGiat1J9KaPlYVeqpzVwWNuZIDGEngRGpXqVQ/640?wx_fmt=png&from=appmsg "")  
  
  
我有些失望，感觉 Google 的安全团队可能没有认真测试这个漏洞，甚至可能没有观看我提供的 PoC（概念验证）视频。我再次详细说明了攻击者如何轻松提取 clientId 并发起攻击的过程。最终，Google 的安全团队触发了该漏洞，承认了其影响，并将其归类为 S2 严重等级，奖励了我 $3,133.70。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrrA0ZjVZVS1fjaDicjc834WnKylvYLZUQqYh5xCgjLTqLdpbAaqmyQDggKW26yVL14vAQM1GFqnPw/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**培训咨询v**  
  
bc52013 或  linglongsec****  
  
****  
****  
**SRC漏洞挖掘培训**  
  
****  
玲珑安全第一期SRC漏洞挖掘培训  
  
  
玲珑安全第二期SRC漏洞挖掘培训  
  
  
玲珑安全第三期SRC漏洞挖掘培训  
  
  
玲珑安全第四期SRC漏洞挖掘培训  
  
  
文末抽奖：24年最后一波招生玲珑安全技能提升班  
  
****  
****  
**往期漏洞分享**  
  
  
通过有趣的逻辑漏洞实现账户接管  
  
  
一个漏洞让我年入数百万  
  
  
从2FA绕过到账户接管  
  
  
简单P1：通过开发者工具解锁专业版和企业版功能  
  
  
盲SSRF+CSP绕过实现XSS  
  
  
从NA到P1，我是如何扩大思路的？  
  
  
IDOR与JWT令牌破解相结合，实现编辑、查看和删除数万帐户  
  
  
我如何在旧的公共漏洞赏金计划中发现SQL注入漏洞  
  
  
  
**玲珑安全B站公开课**  
  
https://space.bilibili.com/602205041  
  
  
  
**玲珑安全QQ群**  
  
191400300  
  
  

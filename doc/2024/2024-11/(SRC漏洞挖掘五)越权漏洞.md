#  (SRC漏洞挖掘五)越权漏洞   
 Z2O安全攻防   2024-11-05 21:50  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！本文为连载文章欢迎大家关注红云谈安全公众号！  
  
  
# 客服聊天处  
  
进入客服聊天处，发送一条消息并抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4icPTqrkcMQvpNIq7xSzo2zZicR2gIMPZb0YUP7GRdlGjtmFBFTLqf1xQ/640?wx_fmt=png "")  
数据包如下，可以看到有个userid参数，并且该参数st为固定参数而后面的全为数字，代表可以爆破。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4LXMgytoOlSPwicpX802Jde85IYUdreuUM0TjxWDnTXvicRpBuqo4MKYA/640?wx_fmt=png "")  
这里就只是通过userBID来鉴权、我把userBId删除、或者随机填写一个userBID、会显示不存在userID  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4icFcD4XiacibSGASpG78Ny6a9WQIoueM3B2ATv1Ek4WwuVt8U7legVP5w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4J1vA1wCwkw6h2YXfAU9fg9OEDXbLic1icGcHqogZ4GXSlsRTprRviaglg/640?wx_fmt=png "")  
通过上面的步骤基本可以确定是通过userBID来确认用户，接下来我又换了一个号、点击客服并输入内容、burp抓包、获取userBID  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4FicWiaYlNibLiavrgBNdoNcUByOUtgbRI56FBk6pPKqomJTveG8yDvF9BQ/640?wx_fmt=png "")  
把这一个号的userBID替换掉另外一个号的userBID、成功回显、然后登到另外一个号上去、发现已经发送成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4PIwh1Hhnbod9AaicdA8XT8ibVpMv07ib1Vss1cPDhCqnRiaSQluvMzx80w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4LTpNRia5YNYPpicjaSiaRwD9h2KwRcJVYeWjRGtGOAhyhkN0b2LK9ia1rQ/640?wx_fmt=png "")  
# 个人信息处  
  
点击我的资料并抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4eiaWgicN4psXE2HFJiaucZwhyCxLW3XWoPXJYlpYBIzfpS4rOhyXJqqkg/640?wx_fmt=png "")  
在get里面我们看到了uid、sessionid、等等参数![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR40GH3KN6HrrQnsHNAKZVkHXOTJERoQuyzZ5ccrSwLCl82zDy9qm61nA/640?wx_fmt=png "")  
我试着删除其余参数只留下uid参数、发现还是正常响应  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4DOqianXIibuiaBkibcTibocge58ohiclezTma4GL4hbiaSUL9uGOxvVcicqTGA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4Cia5liaWkaf4QbbhlicKhkibnn2UmLwLvvhnTUysA7Mibg4Ymq4vfNKUaibA/640?wx_fmt=png "")  
  
在越权漏洞挖掘过程中要经常关注userid之类的参数很多都是这边引起的，cookie里面的ID参数也要经常关注，没有其他捷径反正看见数字类的参数要经常关注就是啦，以上是常规的越权。  
# 超骚越权  
  
进入我的卡券![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4p7ItSPHLNF7zNsdDCTZ4PXhDDn7sNkVKrxicV0VcbvySPRurrF7FUbw/640?wx_fmt=png "")  
点击一个卡券并抓包![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4SyvMpKNiaStaqb9QkEoRMyMyc1CI8ibQxsYibakBWZCibwSvw0yNeyJOEQ/640?wx_fmt=png "")  
卡券号全部为数字，可爆破这是毋庸置疑的，该数据包是通过卡卷号获取签名信息，而刚开始的时候我也知道这里面可能存在越权漏洞，就是通过卡券编号批量爆破来获取签名信息，但这越权的意义何在，这是一个值得思考的问题？如果就单单这样越权交上去产商肯定是不认的呀，因为你获取到的数据就是一段经过签名后的数据，没有任何危害！![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4zPXywyZia9k36KzQ179Cq80APjPicaF5kaaZYicWrgTkdVbOqmLWrs4bQ/640?wx_fmt=png "")  
为进一步证明危害，我通过在这个系统中抓到一个获取到个人信息的数据包（我们在测试时，如果遇到返回数据包中有敏感数据的时候一定要特别注意，因为这往往是一个个突破点，有敏感数据你脑袋中能够想到有哪些漏洞？越权？CORS？）  
  
这里你会惊奇的发现下面请求包中的一大串加密数据就是上面使用卡券号签名生成的数据，返回包中包含身份证号姓名地址等各种敏感信息！![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4KjPvlhrZic3DrjEhLpZO1QF9xMU0On0icgRd28cwPicQxQG84icnAMsrbg/640?wx_fmt=png "")  
那结合上面的卡号我们批量去爆破看是否能够越权获取到签名信息，这里批量爆破证明确实存在越权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4HeQ2sunDicwQKf1Rmpj7DXfJYlsOibZhibh37JyEEXEHxapHl6L94QRuw/640?wx_fmt=png "")  
  
最关键的就是我们能否利用该签名信息获取到他人的敏感信息，复制该签名信息复制到该数据包中成功越权获取到他人的敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMGFkuzstJcIgfFibFVAXpOR4iaLHJIwibo9wlKueasQCGst6zIJNtlep2yC5lW7Adq2LygtdTmypvib1A/640?wx_fmt=png "")  
# 越权漏洞挖掘总体思路  
  
1、看见有参数后面的值为数字，就要时刻注意是否有可能出现越权漏洞，可以爆破尝试一下，我们要经常关注数据包之间的联系，遇到敏感的数据一定要多去思考。  
  
2、观察前后数据包之间的联系  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  

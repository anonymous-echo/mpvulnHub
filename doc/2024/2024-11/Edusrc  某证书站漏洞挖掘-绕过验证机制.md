#  Edusrc | 某证书站漏洞挖掘-绕过验证机制   
原创 zkaq-满心欢喜  掌控安全EDU   2024-11-18 04:08  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -   满心欢喜 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
考生服务系统登录页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsxyo8Wibd0eSX1ib4jnZ2RUOPbFLQZkIekIz1owaXAfzEP8WDMD8zcFibQ/640?wx_fmt=png&from=appmsg "")  
  
img  
  
可以看到，有“忘记密码”，“注册”两大功能点，可以尝试测试逻辑漏洞  
  
所以首先放弃登录框 点击注册 到达注册页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsjryrMYRX6qbwF7JrL2gZN8ia1zy3ofrTrU8PNvalKeeHyhhcJiaSqd1w/640?wx_fmt=png&from=appmsg "")  
  
img  
  
可以看到，注册页面有姓名，手机号码，图片验证码，手机验证码，邮箱，密码，确认密码。 一开始我是测试验证码是否有复用，可爆破等漏洞  
  
输入必要的信息和任意手机号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsS79SCicjuf6ysl39DYBA6D6QGMz2UyocicwIjSoeAp002RsQftsTkEFw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
王六/13332231433(这里其实还有一个小漏洞，就是它没有验证手机号码真实性，我碰见一些站，像我这里打的这种手机号是用不了的，必须要我用真实手机号该两个数字才能用)  
  
点击发送验证码 发送成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsQfcKwcsGiaY6SZKW0FZDb713lJ6PAE9kRYwdkunqwp0YzRkSMdftiaicA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
填写任意手机验证码 我这里填1234 点击注册并抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsK6Siblytr8Ravd1PbBwpNj0RcSVUPhwCWI6woxicMo7rtdwdiaBfPPgkw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这是第一个包 我一开始是直接将他放掉了  
  
结果发现放掉了后就没后续了 我又抓了一次 拦截它的响应数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsVCbv0CXZRsSe9kia65Spia3EictVMVmEprkkshxwePvSCqgy1DS2dap2Q/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
将code改为1 放包 之后又有一个数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsVYZn1ib191icTSSibw1BYia0p0GbhCckROLe9qk4tkEe3UhwjN04wJYboQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我当时以为这是真实验证包了 ，就尝试爆破mobel_captcha参数，也就是验证码 结果刚爆破十几个就被封了。。。老实了，之后就不了了之了，又过了一天又回来了 这次给大家带来绕过验证机制的全过程  
  
输入信息，无需发送验证码点击注册并抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsktII3fDoEJuBJH3TQ6YgeJLaYMRTmv26lqCJwDeteJ3OrRDJ0VZwMg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsjtiaOYoGAg8tk6Y1MibhkF7NB0jj5tMer79KgUEK0TlzfxgCOMnLeG7g/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这是第一个验证包，这里前端输入的验证码为1234  
  
将其改成4321并拦截响应包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsk84NRIjAicA2j2zlUURlDWvpgdKzvKLz2a1ZHicNjdL2u0xmqG9A1icuQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这里是后端返回给前端的验证信息  
  
将code改为1，前端即认为之前的验证码4321是正确的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsqQFiaTLYsjynTtIXwfeGuY3Aremvdazib4veLvdtMAg5qLZBZNz4ySicg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsNsEc1udGXcLbVN4maLgYq9LEzaickicib5ic5aU47CbsXuZl6qE2ztUvBg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这个验证包已经无需再更改响应包只需要将验证码改为之前的4321，因为前端现在已经认定4321是正确验证码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcsZzjPDbjN764w4ToOAawvhibrRkMauLn4DTrBLnbZwDR5qYO3YvBoAdw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
4321注册成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqCAx0C6nd2Ric7e4ZzXhHcs3Rjm8ErVOrV4I4D9NJFBE22pAkNoHVic0XqdG2vt3wOPAA6DliaiaN5Sw/640?wx_fmt=png&from=appmsg "")  
  
img  
  
1234注册失败 成功绕过验证机制  
  
第一个验证包是关键， 原谅我的红色涂笔~  
```
```  
  

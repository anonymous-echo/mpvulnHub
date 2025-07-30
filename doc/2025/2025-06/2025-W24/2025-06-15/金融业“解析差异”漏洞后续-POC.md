> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMDM2MjY5NA==&mid=2247484254&idx=1&sn=b7b309dbe8f914abcb651cf418eef340

#  金融业“解析差异”漏洞后续-POC  
原创 testbywlp  安全边角料   2025-06-15 01:05  
  
接着上一篇文章，本篇文章将会给出具体可行的操作方法，如未看上一篇文章，传送门如下：  
  
[金融业“解码差异”漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMDM2MjY5NA==&mid=2247484243&idx=1&sn=dd3f56cb2e113d589d7e8fbdd373b32e&scene=21#wechat_redirect)  
  
  
上一篇中讲到，攻击者需要注册个非常规域名，那么这种域名是怎么去注册呢？是不是一定要去注册？分场景  
- 不需要  
  
如果我们在测试的时候，能够自行注册账号，为了验证这类漏洞的存在就不需要去注册这样的一个域名。我们只需要使用Burpsuite提供的域名即可，因为他也能收到SMTP协议的内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1X0vibLUNr5cbrfUrEKnXAo4eRHg0pP3Smm1ia9uD2p933fmhNr8bLH7icxJ5PaVHKf0fM7SZXpwlSag/640?wx_fmt=png&from=appmsg "")  
- 需要  
  
而一些没法注册，只能内部使用的系统，如果想验证这个漏洞就只能注册对应的域名闭环整个攻击链，拿到高危漏洞赏金。那么，我们来看一看一个b  
ânk.com的域名该怎么去注册呢？  
  
看看deepseek的回答：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1X0vibLUNr5cbrfUrEKnXAo4ZoAllJ05Ad6QNVPbZNpWUUH44SDia4Ls2agByFpcibzq20hxbeFV0kIQ/640?wx_fmt=png&from=appmsg "")  
  
也就是说特殊符号的域名会在解析时先转化为punycode然后进行dns查询  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1X0vibLUNr5cbrfUrEKnXAo4oMyBfkuZAVknnTOWbNaoPARXnHN5hibr0WUKoIBn2opDv1oENZbhcWQ/640?wx_fmt=png&from=appmsg "")  
  
所以域名  
bânk.com就变成了b  
xn--2cank.com  
- 视频验证  
  
- 参考链接  
  
https://www.punycoder.com/  
  
https://blog.voorivex.team/puny-code-0-click-account-takeover  
  
  

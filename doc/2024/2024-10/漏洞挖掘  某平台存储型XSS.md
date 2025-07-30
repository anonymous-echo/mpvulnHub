#  漏洞挖掘 | 某平台存储型XSS   
原创 zkaq-嘉名  掌控安全EDU   2024-10-07 14:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
本文由掌控安全学院 - 嘉名 投稿  
  
一、信息收集  
  
从来就没有弱口令成功登陆过网站,就想着找找看有没有暴露初始密码的学校网站谷歌语法搜索site:*.edu.cn intext:默认密码找到一个暴露默认密码的学校网站  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFvOiafG16K8MzWn6ul3qFy6QL4Ob8oFcR2Etd059vMOLlswtKYScEScvQ/640?wx_fmt=png&from=appmsg "")  
  
进入该学校的教材征订系统,需要用学号登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFvkEW9dNpWicUQafHfJnNlKYf6zYDmL6rX5XITSutlkibUCNvX5cGNjVqw/640?wx_fmt=png&from=appmsg "")  
然后在百度贴吧等社交平台收集学生学号信息,这里找到了一个15年的帖子暴露了许多学号的帖子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFvc8BHU2D8FC58pFjo69dc2AXhloF8gotyvicfXnwIAOSPvZZP7CW0bSw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFvZ5TEozDEwfjaYdAKfb8RlIMg56FuTrFTtr3chqs1ZyK0KicgzTrf1RQ/640?wx_fmt=png&from=appmsg "")  
# 二、测试  
  
随机找一个幸运儿的学号进行登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFvGHmqP9uUE0xstfdyHGjdP1lgLBKg7ER9faCCQ5PvM1ZqvWd2ibOaXsg/640?wx_fmt=png&from=appmsg "")  
登录成功之后,对头像上传功能进行测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFv3K6l0ic0Lu1NreSHu3z6xMx521ibwGAWDzBjhCnksJ1HOETmsbMKkG9Q/640?wx_fmt=png&from=appmsg "")  
  
上传图片马bp改成php文件,竟然显示上传成功了,当我以为能getshell时,发现被后台删了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFvFTQFIU3EAgcvWh5EYbVvz4jSibEWY53ZksMqiaibuUTsAhu6b4XLTQJIg/640?wx_fmt=png&from=appmsg "")  
用bp抓包时看到一个包里有文件保存路径,就突然间想到了zbs师傅打到的黑龙江某学校的XSS漏洞就对bp里面的路径改了一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFvzPEtJGVlmVw2hbMQFdyNWvLmsTO7RzegZ95jEwfv6xhEWEBL6CHFKQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFvANpfQQKrPcAX9ZJMHxzUTTaibaHficBSbx6ges9wjWs4KKC4552SR26g/640?wx_fmt=png&from=appmsg "")  
刷新页面有弹窗  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFv1ibshiaxACsd9NQ2phKOqBwVA3xD1PiatQ9RpNxkTKg6GyCiaw7m2ialTIQ/640?wx_fmt=png&from=appmsg "")  
再看前端代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpyxfRhWCEkumJG6WubzlFvNfichvKOssNiah7miaqy43lAjJP4rKHI12eDmM6D7ghI5twTGOzgsBqIw/640?wx_fmt=png&from=appmsg "")  
  
就这样人生中的第一个漏洞到手  
# 三、修复建议  
- 对图片路径得传参进行实体化编码  
  
- 多设置一些逻辑判定  
  
申  
明  
：  
本  
公  
众  
号  
所  
分  
享  
内  
容  
仅  
用  
于  
网  
络  
安  
全  
技  
术  
讨  
论  
，  
切  
勿  
用  
于  
违  
法  
途  
径  
，  
  
所  
有  
渗  
透  
都  
需  
获  
取  
授  
权  
，  
违  
者  
后  
果  
自  
行  
承  
担  
，  
与  
本  
号  
及  
作  
者  
无  
关  
，  
请  
谨  
记  
守  
法  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**没看够~？欢迎关注！**  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+靶场账号**哦  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
******分享后扫码加我！**  
  
**回顾往期内容**  
  
[Xray挂机刷漏洞](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247504665&idx=1&sn=eb88ca9711e95ee8851eb47959ff8a61&chksm=fa6baa68cd1c237e755037f35c6f74b3c09c92fd2373d9c07f98697ea723797b73009e872014&scene=21#wechat_redirect)  
  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[代码审计 | 这个CNVD证书拿的有点轻松](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247503150&idx=1&sn=189d061e1f7c14812e491b6b7c49b202&chksm=fa6bb45fcd1c3d490cdfa59326801ecb383b1bf9586f51305ad5add9dec163e78af58a9874d2&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  

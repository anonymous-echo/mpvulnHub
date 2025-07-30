#  某小说vip破解代码分析   
1708124866250085  神农Sec   2025-01-17 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
原文链接：https://xz.aliyun.com/t/17006  
  
作者：1708124866250085  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**代码分析如下**  
  
  
首先jadx打开，看看代码，老规矩，搜索isvip  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVhtOczBb4Q3osiat7wVkZmXKwWTTgEwo1Sf0WxmTnlahWPLqDINZOnpqjQWxZqZdiaYPhrJeF4RRkQ/640?wx_fmt=png&from=appmsg "")  
  
  
点进str2所在，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVhtOczBb4Q3osiat7wVkZmXxrSkv4HJaGLI8PvibfSWwD6CeE6BGFmvGZuNrDKaMXicM7UZ6xEfSWjw/640?wx_fmt=png&from=appmsg "")  
  
  
  
可以看到str2不是传统的bool类型，而是一个string，然后expire也是一个string(通过frida hook之后发现是vip的到期时间的unix时间戳)，所以话不多说，直接上frida，  
```
Java.perform(function () {
    var VipInfoModel = Java.use('com.dragon.read.user.model.VipInfoModel');
    VipInfoModel.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'boolean', 'boolean', 'int').implementation = function (str, str2, str3, z, z2, i) {
        console.log("VipInfoModel constructor called!");
        console.log("expireTime: " + str);
        console.log("isVip (str2): " + str2); 
        console.log("leftTime: " + str3);
        console.log("isAutoCharge: " + z);
        console.log("isUnionVip: " + z2);
        console.log("unionSource: " + i);
    };
    console.log("success");
});
```  
  
  
发现输出是  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVhtOczBb4Q3osiat7wVkZmXicuKavmjbnPTfPwlw5gBx9ic6sUibCKDKzJKEeWRSQVMLhYNXju3ZKygQ/640?wx_fmt=png&from=appmsg "")  
  
  
所以，直接改了就行，  
```
Java.perform(function () {
    var VipInfoModel = Java.use('com.dragon.read.user.model.VipInfoModel');
    VipInfoModel.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'boolean', 'boolean', 'int').implementation = function (str, str2, str3, z, z2, i) {
        console.log("VipInfoModel constructor called!");
        console.log("expireTime: " + str);
        console.log("isVip (str2): " + str2); 
        console.log("leftTime: " + str3);
        console.log("isAutoCharge: " + z);
        console.log("isUnionVip: " + z2);
        console.log("unionSource: " + i);
        var ret = this.$init("4102415999","1","100000",false,false,0);
        console.log("Modified constructor return value: " + ret);
    };
    console.log("success");
});
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVhtOczBb4Q3osiat7wVkZmXlDodz0UJNOFM1ch4QurnBBTDhf3d4Lj5VFIEVoO8O73xm7brIaM8Lw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
我们是神农安全，  
**点赞 + 在看**  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
圈子专注于更新  
**src/红蓝攻防**  
相关：  
  
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
  
  
  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9HiabHicghO61zG96hG318zIWdzPq1qMibtbLPlDocib1ndkeMCNOge8AdDB2dXj8bQ2WuIibcrUvEuQ/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满200人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
    
  
  
  

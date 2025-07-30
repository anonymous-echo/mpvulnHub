#  漏洞挖掘|从edusrc转战到企业src的漏洞挖掘   
 信安404   2024-03-20 19:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNJUTyXhK4Iic6TJFLAAboGBK3V3tSviaWr4PZG8a6IYoiaMTg23QFLvasNxpQL1Ed9qLsPUmGPH1mPw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**0x01 前言**  
  
    在日常挖掘漏洞的过程中，本想拿点edusrc，毕竟还没挖过相关方向的，动不动就是学生认证，社工、账号收集本就是让我头脑发热的  
  
    本次漏洞基本上以API接口延展的，中间经历了文件上传方面，奈何没有利用成功，后端限制严重，基本围绕逻辑漏洞、信息泄露，短信HZ等，先放一张相关企业的查询，由于权重低，注册资本低，交公益SRC了，总结最后写，希望各位观众老爷们看个开心就好  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQHrB3dvyXuE73icibvsO7KRk9Lhasjo6tYDPd31ib68njQl4s483yAmDqg/640?wx_fmt=png&from=appmsg "")  
  
*** 文章仅供分享学习参考、请勿用于非法用途、后果自负**  
  
**0x02 趣事历程**  
  
    打开某小程序，基本上都是介绍学校和报名的，域名是某企业做的服务，并非学校的域名，那么我就先点个人中心，抓到一个发送验证码的包，尝试第一个发送验证码和第二次发送验证码，都收到了，直接开启intruder模块，成功收到短信，按照补天的说法，超过15次就算是纵向轰炸了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQHULoKpMPfpdHUnofoDo55PkwNibnH3ayDFZ9ibOxj1H5icRbCYpumJgaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQiba5oaT3TkCIEf5G9h3N6OOZkiblkZ7ca0iawIl1icibpUvlXwfm9kChweQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQZTnibIicUhNibicRpibyiawibC9u8ZHEouvWFribS3NWv1nze93dr06aU8iaOeQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQmHyvMdibIQdI0xWpLtwnUVItUS0TvKyREwTh3iaKmrnwUW7njwGVD0iag/640?wx_fmt=png&from=appmsg "")  
```
短信HZ +1
修复建议：
        对发送频率进行限制，如限制在5分钟内发送一次，每天限制发送3-5次
        如已经限制了发送次数，则限制发送频率
```  
  
      
后来登录进去了小程序，越权是不行的，后端会在登录的时候生成一个token，这个是没有规律的，然后有个头像上传点，经过测试，前端设置了扩展名上传白名单，此处利用失败  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQNKhRcTKxEiaZMzlhUV9Fn1vQ9edPYvfBtL7gdsqmwmVVU0orGic5BVog/640?wx_fmt=png&from=appmsg "")  
  
      
前端接收到文件后，会判断扩展名是否符合白名单规则，如果符合，则上传到对应的目录中去，以当前项目+时间命名，有意思的是，开发把文件落地的file.xxx.com的异机服务器了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQGfx1zP6qd4ZTUAP6c4Z4D0lFRV388d02wgsSGKtgw1kaEDaDwg2mYw/640?wx_fmt=png&from=appmsg "")  
  
    经过测试可以断定，是白名单策略，而且没找到文件包含的相关漏洞，暂时告一段落，然后接着对此域名进行打点，fuzz根目录没找到，根据抓包的小程序路径特征，对路径进行fuzz，看到有swagger-ui  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQ7LHZzEibGDwibCPTtp2GAOMgGcuicqp686EsHq7icNAPwkJwMmNRI2qlibQ/640?wx_fmt=png&from=appmsg "")  
  
    查看此页面，基本上所有的api都在这了，玩swagger-ui靠的就是运气，因为有很多请求的要求必须要ID相关的参数，如果id是明文还好说，如果是加密的或者是token无规则的，就得靠运气了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQP3szqibCiaEBwtJ6zHo662Ribibeg7u7icjcm35ofrvwNDE3GyJzSTPCbWw/640?wx_fmt=png&from=appmsg "")  
  
      
参数比较多，直接用工具碰一下运气  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQHyfgaFlhoxt1anvkyn9YAG9urzXa8mbfrwD0CJvXHbHPd8uDo3eZmw/640?wx_fmt=png&from=appmsg "")  
  
      
运气比较好，检查一遍，跑出两个信息泄露，用户和员工的，基本上是姓名，手机号，住址信息，大概几千个左右  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQ8SOxE1MRXLZTE8P9yHqgEH4BqiaUbkxIAHfzXOO4kvTehM0h6jIWlzw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQaHCGibX4uXH4XHlDFctT29fkWNzb7ToJ8hjxfK2ia69bqvcCbGNPhlUA/640?wx_fmt=png&from=appmsg "")  
  
   
**个人信息原因需要厚码**  
```
未授权访问 +1
信息泄露 +2
修复建议：
        对swagger-ui开启鉴权
        如非必要则不对外开放
```  
  
    此域名基本上打点完了，就是api站点，打点其他子域名，先进行互联网收集其他子域名，根据当时用fofa打点的语句  
```
host="xxx.com" && header="200" && host!="xxx.xxx.xx"
```  
  
    然后挨个浏览打点资产，继续在xxx.m.xxx.com页面拿到短信HZ  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQCt6LspTZupK8vS1qAsep7HgHHicVAhVuEfg9MiaNYESMcuRW8aWVCQPw/640?wx_fmt=png&from=appmsg "")  
  
     
 登录成功后继续查看，在功能处有文件上传，前端js判定文件类型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQ3jZibdv5VYbAjib2ahkibk6HV0znm9ZoSO1pSoIa7OfZxtodcK9HE2mcQ/640?wx_fmt=png&from=appmsg "")  
  
    按照规则，上传一个图片类型的文件，先绕过前端，然后上传成功PHP文件，还是同样的套路，让人无语的是，图片和txt格式文件可以正常在线预览，其他格式直接下载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQ7Yf1Fm9cPXy0e2jUjwWnVqG0pwsEm1CeJvuRfF4PBgkf4apKyVqJeg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQwUeia0zibpazWpfialNz4IffpGwqnn1xicKbJpZ81ol6qta5Mm06ialbGBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQZ05ETdjLDribwpspbM0E3M80A7ZRPjROLs8AXsouOz5zCwI7MFv4hcA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQCsfGsMOJNTMecibtqa13nL5gVm04KsNsqedSDtBhJbLZ8HVPkGibkZEg/640?wx_fmt=png&from=appmsg "")  
  
    很可恨，到嘴的鸭子又飞走了，无奈继续往下打点资产  
```
短信HZ +1
```  
  
    
  由于资产比较乱，而且时间匆忙，转战到hunter搜集资产，找到了一个测试站运营后台  
```
domain="xxx.com"&&header.status_code="200"&&web.title!="Welcome"&&web.title!="HTTP"&&web.title!="xx"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQxjwt8JexcYrIukG18o8EiclxWia0icotA92Vx4phxGXtdaILRBxlzT2WQ/640?wx_fmt=png&from=appmsg "")  
  
      
值得注意的是，这个测试站test.xxx.com/admin(类似于OA，后台管理系统),主要是工作人员管理客户和办公用的，和他们的主站www.xxx.com/admin数据是同步的，但是前端的一些问题主站是没有的(后面才发现的)  
  
    首先测试站登录auth.xxx.com页面，当时有两个思路  
```
1. 撞库手机号
2. 爆破验证码
```  
  
     
 可能我运气比较好，输了个18888888888加无验证码就登录进来了，未授权到手，他这个应该不是故意的，按正常业务来说，在测试的时候，不加验证码是为了方便，而且测试完以后同步到正常业务站，所以说，这个可以当成正常业务站来打  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQOsLgoiaYo20t7ZQ51rAXRZiacIM7WFzVSlpJgvepydNIGHG3lDcXTEaw/640?wx_fmt=png&from=appmsg "")  
  
    登进去了，但是吧没什么功能啊，正在一筹莫展之际，翻了一下流量包发现，还有惊喜，登录进来后有一个我的同事流量包，从中获取到同事手机号，登录成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQ1O8icPDWRRsh7BTfZ0YxtOaobPp05tjzdIRvkrvr1HOZBuvmVN2hYWw/640?wx_fmt=png&from=appmsg "")  
  
      
可以查到所有负责的企业和客户信息，该员工负责的某业务下有3000+条客户信息，一千个企业信息(备案资料等)，此外还有6-8种其他类型的业务，其他员工信息没登录测试，证明存在即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQhh8gxrqDibg0rnOjRuGX4OPicJj8SiaSUXleWcjibSf9MoYurMQNtneic7A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPNkArT7IuS6QVG6Uv3UbD9SVDukNV9PVDdvSNRSqP28pmdciaDHwBWMgBCINDia5XfckibR7xpfLakQ/640?wx_fmt=png&from=appmsg "")  
  
     
 其他都是业务上的一些东西了，没有其他功能点，也挺匆忙，没有打点，此外就是xray出来的druid  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOstXeeJA7ATNNFw6lIHpSQJfo9rUQln9QShlnHHWvoVicHhs54R8rzThXYzXPFky5mZJfqXNrFpsw/640?wx_fmt=png&from=appmsg "")  
  
     
 里面没有可疑uri和session，只能当低危交上去了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPNkArT7IuS6QVG6Uv3UbD9vBiaIPMDCL9flpojsAzYVq9D3d6N9ILhGt7pQGm5oOElibdFVw764OyA/640?wx_fmt=png&from=appmsg "")  
```
任意用户登录 +1
信息泄露 +2
未授权访问 +1
```  
  
**0x03 总结**  
  
      
该企业的站点比较纯，没有涉及OA，框架之类的东西，唯一一个就是堡垒机，基本业务就是计算机和线下业务，面向用户的前端基本上就是报名和学习，下单等，和员工绑定的就是一个id，数据通过swagger-ui传入到数据库，面向员工的前端就是后台(类似OA),对客户企业信息进行管理，同样操作也是通过swagger-ui，值得一提的是，该swagger中需要进行的敏感操作都需要uid或者token，这个是后端无规则生成的，但是信息泄露有些没有进行规则配置，靠运气好直接打点了，总体来说比较简单，但是所需思路很清奇，对api的判断，对swagger的路径遍历等，并没有出现所谓的shiro，fastjson之类的一把梭漏洞，对于用户的操作过滤的还算是比较严格严谨  
  
Tips  
  
项目地址:  
  
https://github.com/ExpLangcn/FuYao-Go?tab=readme-ov-file  
  
**安全交流群：**  
扫码**加好友**  
邀请进群。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bQCwTicVAUKUCwRmO6KxMXG52pS3KOhmnDiay4Uy6NIPZiazyicITgR0ck4iaUXDT5kuJrnvF2Kc1pBq5rB6rUCwVcw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
往期推荐  
  
  
[冰蝎（behinder）免杀魔改](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247488073&idx=1&sn=f999f5bdf38cbe0dc9c81766e0d6c04c&chksm=c30408f0f47381e6851c59a63a7b0e214306f15c45e6f0f07cdd77ef372b0acdbae6489902ed&scene=21#wechat_redirect)  
  
  
[社工密码字典生成工具|字典工具](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247488059&idx=1&sn=06c9133558c199477b8ff3b53a3fd7e8&chksm=c3040882f4738194184ce2f111dff8a2e4397cf295ad8922e997348e031b07e4f43b4d2733cc&scene=21#wechat_redirect)  
  
  
[某单位软件供应商黑盒下的0day挖掘](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247488059&idx=2&sn=60ca77ef3bdc240e749749e224ce7c86&chksm=c3040882f47381945de3570a39f341ecad7ce4867715f66b88ed48ced00f3288b7bb6eb29a8c&scene=21#wechat_redirect)  
  
  
[一个CTF+渗透测试工具箱](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487954&idx=1&sn=fcd0b61cdc8bd9c28b625b50f9c7c759&chksm=c3040b6bf473827d05336086de3f48d20c5e72b1f3ec90bbd22f2dafa86af86914215b60e038&scene=21#wechat_redirect)  
  
  
[专注一站式解决渗透测试的信息收集任务的工具](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487922&idx=1&sn=96691a3d4ebf62f161c300d731ae7e9b&chksm=c3040b0bf473821d26a33ca26db7dbc9c8caff91b8f3034d9f482bb001bfa61f7752e3e32b7e&scene=21#wechat_redirect)  
  
  
[【CTF-OS】开箱即用的CTF系统！](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487772&idx=1&sn=4a7da494018d04337c9a5e400a40adaf&chksm=c3040ba5f47382b3b1ff4f6a8f14f4ec9f8029aee7d31aefcf5949cffcb54c9d06dcf9d0ba1f&scene=21#wechat_redirect)  
  
  
[【2024HW】招聘早班车](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487769&idx=1&sn=e3e22f1b757f97f284330644c059ee68&chksm=c3040ba0f47382b6041ae857b203d7b4bb9bee462bc2fac3b835a9407ae0f23d3af5198054a6&scene=21#wechat_redirect)  
  
  
[自用超轻量级【渗透系统】可一键还原！！！](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487767&idx=1&sn=175c430b2ab3c2c827efe4e50aab8320&chksm=c3040baef47382b8aa3b20d0a6fb161074ebe48a191abf78de01e69565e1b5e62c47c4bd3199&scene=21#wechat_redirect)  
  
  
[【安全服务】XX公司应急响应处置报告](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487680&idx=1&sn=4ad96f1b7000861593f84e59f5bf7b06&chksm=c3040a79f473836f0c00c77eea70afa3d88132a06be134d7bffae6fa6ac2cbee46ecbcbba0d9&scene=21#wechat_redirect)  
  
  
[WordPress爆炸性0day，直接RCE！附POC](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487662&idx=1&sn=cd04fc0d0c5eabe96ce62fd7bcd49c3a&chksm=c3040a17f4738301f97a0d244839440f83be6e70c2e0bc8779ac08f7dc4785aea1e5318b9b5b&scene=21#wechat_redirect)  
  
  
[攻防|记某次极为顺畅的实战案例](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487662&idx=2&sn=64ad07828691cf8ffbf391e551b7ee7c&chksm=c3040a17f47383013d087030c444aa63b7963cd037c5c76cc0197753e62d75523c9894c5bfe0&scene=21#wechat_redirect)  
  
  
[多人运动又添神器，快来一起！](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487603&idx=1&sn=8bd325ec854514b3ad615f748af5038f&chksm=c3040acaf47383dcc7e6e7d75536548bd4afadd5356a879100bd32342fa930061bc336e7671e&scene=21#wechat_redirect)  
  
  
[一款自动化提权工具](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487603&idx=2&sn=4cc78cf9e491668475fee3b857bf6723&chksm=c3040acaf47383dc11ba138c947f04d9cdf8bd67d200bd31e6ceb002cee2d0ad8fe717c87ad1&scene=21#wechat_redirect)  
  
  
[APP渗透测试环境搭建](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487368&idx=1&sn=8834b7286c3f35abb5404b014551a3ad&chksm=c3041531f4739c276d40fc0abb82e3823e51be2d1aea400a637df685122c9bdb58c07cde8ae2&scene=21#wechat_redirect)  
  
  
[漏洞扫描的工具 -- Golden-hooped Rod（2月15日更新）](https://mp.weixin.qq.com/s?__biz=Mzk0NjQ5MTM1MA==&mid=2247487365&idx=1&sn=018042e091abade77478283b8c731b95&chksm=c304153cf4739c2a9d0485ca26d986bcc5fd2fceb0e6cf5d6c6654b57eb06fed9bd3641efe93&scene=21#wechat_redirect)  
  
  
  
  
  
  

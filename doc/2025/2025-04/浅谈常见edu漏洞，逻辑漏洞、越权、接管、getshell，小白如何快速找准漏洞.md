#  浅谈常见edu漏洞，逻辑漏洞、越权、接管、getshell，小白如何快速找准漏洞   
薛定谔不喜欢猫  神农Sec   2025-04-28 01:02  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
原文链接：  
https://forum.butian.net/share/4291  
  
作者：薛定谔不喜欢猫  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 教务系统登录处短信轰炸**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5XrCURQticqcEo5jwHFAVGvU8TmcgXFkBBh8ySaBuaWS0OtkknKbmlzg/640?wx_fmt=png&from=appmsg "")  
  
  
  
学校的教务系统登录处，发现有一个手机验证码认证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5MHhnmpFYBsQzfGwDGCXe0XfW0kSjYhDeibkiaEwOotiaHXRQ5Hmt1MGAQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
这里会发送一个验证码  
正常来说，每发送一次短信验证码，这个校验码就会自动更新一次，然后会报错：“验证码错误”。  
但是这里抓包之后，发现能抓到两个数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5yxPJnjWBtpc4LAPACzLJRenCjqcDcQPHmzibhaLL7qmUUvzvty5iaAKg/640?wx_fmt=png&from=appmsg "")  
  
  
  
这是第一个数据包，可以发现是对验证码的验证，我们把第一个数据包通过之后，拿到第二个数据包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5fISrrlJ7hVPWq4aCtGFOibS0Y9RO9Wic5l85x1gpalYFxY3haBxRwQZA/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到我们的手机号出现在了第二个数据包中  
我们点击放到repeater，然后点击send，可以发现一直发送：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5eBHK4SKehNeOWKojnS7DHoeCE7O2baTcGmicx7SicaVemMOqljfQzyMQ/640?wx_fmt=png&from=appmsg "")  
  
****  
**原理**  
：正常来说校验码的验证和发送短信应该是在同一个数据包中，这里不严谨的设置，将校验码的验证和发送短信的数据包分成了两个，我们输入正常的验证码，通过第一个验证的数据包，拦截第二个发送短信的验证码，即可实现短信轰炸。  
  
  
这里分享一下短信轰炸的几种绕过方式：  
#### 1.手机号前面加空格进行绕过  
  
这是挖某专属src时遇到的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5HP4qDok3sFMDCGRjpEJceoxtEe9Mz4zMnHFyVWSHLwLRh7IzdZ4aJg/640?wx_fmt=png&from=appmsg "")  
  
account为手机号，正常情况下，一个手机号短时间内只能发送一条验证码。  
  
在account中的手机号前面每加一个空格可以突破限制进行多发一次验证码，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5okOI4Vj9kyqsR5rdHSJibRN1wjvHoDyaE0kdZh3oFM3zxia3oLTxibUfw/640?wx_fmt=png&from=appmsg "")  
  
  
burp设置两个载荷  
  
第一个载荷用于填充空格，设置为50（这样设置，一个手机号就可以发送成功50条短信）  
  
第二个载荷用于循环遍历手机号，可以设置遍历10万甚至更多的手机号  
#### 2.加字母等垃圾字符绕过或者+86  
#### 3.伪造XF头  
####   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 校内某实训平台任意用户注册、任意用户登录、修改任意用户密码、验证码爆破**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5ibtPd80kI7MibkPqhrVJA4xjUPkGPNGX8kzLnibONB0Ps71y48BNMaTxQ/640?wx_fmt=png&from=appmsg "")  
  
  
这是校内某实训平台，我们先点击注册功能点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5Y9YGuMffJFQlXF6RbTib1JgIXH0hoCia1jkUiaX8vjuuianibutm79zn5OQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
我们点击获取验证码，然后进行抓包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5CEVwJfwQ88MmpTfzPLmibM7Hs4NwrBPNcENy0MQWQPtBwa2NibZcebqg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到手机号被编在了url里，我们这里使用“,”去拼接手机号，这样就可以把验证码同时发送给两个手机号，并且收到的验证码相同。好比我知道你的手机号，拿你手机号去注册，我根本不需要知道你的验证码，因为验证码也会发到我手机上。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib52pFcMdj0mImcQibFDqbD53cHjbrDx71bMZ13XQRqybs7Kkcfib2xZ65w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5htChmJWticap2OSnibxC2KGO1AT234sCAcF9hRbAAbdnttW5u90X0wsg/640?wx_fmt=png&from=appmsg "")  
  
  
修改密码功能点也是相同，我这里不进行过多赘述  
#### 验证码爆破  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5GLSwWzkkmnCg7SKDZkIWoMYZia47AdIouJZcyesMucOZTIwSezP4Vbw/640?wx_fmt=png&from=appmsg "")  
  
  
正常发送验证码，然后在填写验证码的地方，随意输入四位数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5Gx1Owr0hOvbG4XNLDJEH0fAeHyicIicjzeA7kUNlaWCE84lencHoI9lQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib54fOEa83lfcoudKaCG37LWyOLMWC3VYqZXxMKvib6FvZ40GF8rFA6MLw/640?wx_fmt=png&from=appmsg "")  
  
可以看到在7710的时候，长度不一样，成功登录进去了。  
  
**修复建议：**  
：对验证码输入次数进行限制  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 越权查看所有学生和教职工个人信息，数万条记录**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5YZ67eia0FQanxFuibp7zy4SYIQajkjjlbibUwBRjMWNpZrfHzleeFvicfQ/640?wx_fmt=png&from=appmsg "")  
  
  
教务系统个人中心处有一个查看最近登陆记录的功能点，发现右上角有个查询，我们抓包尝试：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib52NILna0Ys4l9OSLtk4yF1eS3rr55TpkBVC3CyAfrUgg1qKcbTic4fAQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到这里可以看到我们的登陆情况，我们尝试去修改value的值，看看能不能直接越权查看别人的登录信息。但是发现无论修改成什么都会提示登录信息错误。  
  
修改成0、1、-1都不可以，但经过我的尝试发现，只有一个值可以，那就是null！  
  
我们让value=null  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5Qh8kgfHPpOFJABD0CvlsRkXwtqFRjg7TicDNAJS1V81qPFicS5oObMWg/640?wx_fmt=png&from=appmsg "")  
  
  
但是登录的记录明显有点少，而且观察发现好像都是登录失败的记录，这时我发现有个name字段，我把userid改成*：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5Wymyoc6cXZ6TicbqhQXXf0FGyOZ37g3ibm4d3QOe5q10LQQvXsNBtEwA/640?wx_fmt=png&from=appmsg "")  
  
拿下所有学生和教职工的个人信息，包括姓名、手机号、身份证号、学号、教职工编号、登录ip等  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 教务系统绕过手机验证码换绑手机号**  
  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib55bN8auUvwx6qSvia5Fx2KO1XyA1gibsMDNYra4DQKpp8fbkffwh5IUog/640?wx_fmt=png&from=appmsg "")  
  
  
  
也是这个教务系统，安全中心有一个换绑手机号的功能点，我们点击发送验证码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5hK10uKASdCHs4mT3k0EHkDtS0O6KmnO3oibkDdWeW0nQcIlfXCichmbQ/640?wx_fmt=png&from=appmsg "")  
  
  
这里可以看到是修改195开头的那个手机号，然后我们forward  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5oUdQFvj12iaxZ9R7lMgTuTWpAkZicpGdYf97ic5oIgkqaNpMgab5VF6Ww/640?wx_fmt=png&from=appmsg "")  
  
  
  
之后弹出一个验证码，我们输入验证码点击确定  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5xzPj2SxRPA1m6vpmPcibYb8tKzFhzvlHfbRlXnDzkt58JnEu4yhCKog/640?wx_fmt=png&from=appmsg "")  
  
  
  
这里的验证码就做的很好，和发送短信的验证码数据包放在一起了，杜绝了短信轰炸。但是我们这里把195开头的手机号修改成我自己的手机号。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5toCE1JFw3RWpXkuDTmkKAPZj7U1c7ibg36gRpAmibaron5hYFicdN7pnw/640?wx_fmt=png&from=appmsg "")  
  
  
成功让自己的手机号收到验证码，以为皆大欢喜了，结果。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5AgKXezXwibQ6euvJCuibvYPVl2nSSa7MpAIwRj1cicsyTiaaz2F87bnicibA/640?wx_fmt=png&from=appmsg "")  
  
  
  
显示验证码错误，这是为什么呢？  
  
我们继续审一下错误的数据包，也就是我们抓输入完短信验证码，点“下一步”的那个数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5EMLVKWOsZL0DvibHkgeOTcUqzy96Bv0UZObICmWpsDcDBnZ8NgwDvCw/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到居然在“下一步”的地方，对手机号又进行了一次验证，我们将这里的phone改成我自己的手机号，然后forward  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5kO1B02tlicS1oTyiaQOYQAXEjz2L2bpiciaMPwv7aM0j356HBbo6LX41Ww/640?wx_fmt=png&from=appmsg "")  
  
成功到达绑定新手机的界面，成功绕过了验证码认证，可以换绑任意用户的手机号。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x5 校内某平台druid未授权访问，导致泄露用户session，可以实现任意用户接管**  
  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5ibsIZVFocrsBeEcBWYLbBSIdXFVSZCibBgM3PgU7ImVN3BByuVu03A7w/640?wx_fmt=png&from=appmsg "")  
  
这是校内的一个实习平台，url为“  
https://xxx.edu.cn/shixi/  
”  
  
然后之前读文章读到了一个druid的未授权拼接，/  
/ druid /  
  
/  
  
于是尝试拼接 ：“  
https://xxx.edu.cn/shixi/druid/index.html  
”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib54xoaiaogMheicet4FxKFoDmCawbXwibKXGWnsxBYmrXmice3qDGSmTUk6w/640?wx_fmt=png&from=appmsg "")  
  
可以看到是有druid的未授权访问，这里会泄露很多东西，比如数据库信息，数据库查询语句、访问记录等等。我们这里搞一下session。  
  
可以看到有一个session监控：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5AWNPxdnxjwDptYydqoP8Jibm1CcXC8NwIOfIFYVrRz9mHlNNgCJxHWw/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里有登录过系统的用户的session，我们要做的就是把session收集起来。这里我有个比较好用的方法，可以ctrl+a复制全页，然后粘贴到excel里，然后选中session列，就可以快速的把session复制到txt里了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5GhBJ3EicapF6Aukg186zebRUSWqNT1fOP8OgT61LYcGX8dUJTFapZWw/640?wx_fmt=png&from=appmsg "")  
  
可以看到我们把session这样收集到了txt里，然后打开yakit  
  
把txt导入到yakit的pyload里，然后去抓一下登录窗口的数据包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5NTtq2ibdeNibrBRkWSYIP6dLkeoZLsgDuKfFL802ic0ictozsNHRlv7aGQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到cookie有个jessionid，我们把他的值设置成标签，然后去拼接刚才的session的payload去批量访问：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5rpAIZWZsucE9WU1EXlaDEL5vssfIcSaZUwbEL31Ml4iaqjXw5nrI42A/640?wx_fmt=png&from=appmsg "")  
  
可以看到有很多200成功访问的，也有一些无法访问的，无法访问的原因主要是因为session是具有时效性的，长时间后这个session可能就会失效，但是只要源源不断的访问这个系统，我们就可以源源不断的盗取新的session。  
  
我们找一个200正常访问的数据包，把里面的session复制下来。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5E0mEAH170YmOKIIJ7DFYiba33whRreMhMCgmTNhgdJFvClAoW7PcBTQ/640?wx_fmt=png&from=appmsg "")  
  
然后回到网页，打开f12里的存储，替换里面的jsessionid  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5fEXHEsIYu0jXcOWeCuIUPprKwZicZKSPDHSd1Svrz4cRTtcxOgGdngg/640?wx_fmt=png&from=appmsg "")  
  
然后刷新页面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib55ccTAwtwPfrrvCfEruoD3NicG0het9sdfnLria73t9KGXic5Lqjybl9eA/640?wx_fmt=png&from=appmsg "")  
  
可以发现直接接管了别人的账号，登录进了系统。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x6 内部系统存在sql注入导致rce**  
  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5LwhiaTkR52Lz0VeD7zQogzfmXo6ibcqafJPaXthANB8YgXqQMSHqemLw/640?wx_fmt=png&from=appmsg "")  
  
学校新出的一个平台，还是挺重要第一个平台，负责校内事务和档案的，应该还是个通用，很多学校都购买了这个平台。  
我在那个平台抓包的时候，这个数据包偶然出现在我的burp里，我一看，居然直接把sql语句写出来了，这不就可以直接利用了吗？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5RRUakH02uPVCmPCaGVnmgMCujCZHlIgt9pceCZ14a4Ge1VJfGsTfXQ/640?wx_fmt=png&from=appmsg "")  
  
直接执行select user，可以看到右边直接进行回显了。那个user字段的内容就是回显的。  
  
后来我写报告的时候，怎么找也找不到这个包在哪抓的，没办法，只能转化思路去找js接口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib52WcYQlUGxMArP5QRpDZdQ52qKYCVvMsgEvdicYuKbpK9n9AQNMmcPNQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到这个data里有sql:t  
  
成功找到了这个接口，然后还有意外收获！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib58NNiaKUupqniaDhsAPhmtDILIPaxicAgQdNdTLcqbhtr4GHaSa24vib8bw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5xx5xlCYiakDyJhw0gbC2lpoMCRK0IYAaCG7cXco88JHWXduz4PBAlBA/640?wx_fmt=png&from=appmsg "")  
  
找到了近400个接口，这400个接口基本上都和上面的一样，直接写出了sql的语句，都可能存在sql注入！  
  
那么多接口，第一想法就是爬出来测一下未授权和越权。  
然后写了个爬虫python脚本去爬js  
```
import requests  
import re  
\# #proxy={'https':'127.0.0.1:8080'}  
\# url=""  
\# headers = {  
\#     'cookie':'',  
\#     'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',  
\#     'Username':'',  
\#     'Accept':'\*/\*',  
\#     'Te':'',  
\#     'Priority':'u=',  
\#     'Sec-Fetch-User':'',  
\#     'Sec-Fetch-Site':'',  
\#     'Sec-Fetch-Mode':'',  
\#     'Sec-Fetch-Dest':'',  
\#     'Upgrade-Insecure-Requests':'',  
\#     'Referer':'',  
\#     'From':'dzj-pc'  
\# }  
\# def get\_html(url):  
\#     res = requests.get(url = url,verify=False,headers=headers,allow\_redirects=False)  
\#     # return res.content  
\# #  
\# html = get\_html(url = url)  
\# print(html.decode("utf-8"))
```  
  
爬出来之后，使用正则去检索我们所需要的东西：  
```
file = open('C:/Users/xxx/Desktop/111.txt','r')  
lines = file.read()  

apis=re.findall("url:\\"(.\*?)\\"",lines)  
for api in apis:  
    if '?' in api:  
        print(api.split("?")\[0\])  
    else:  
        print(api)
```  
  
. 表示除\n \r 之外的任意单个字符  
* 匹配零次或者多次  
? 指定为非贪婪模式  
  
然后我们将收集到的api，放到burp里去批量访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib54s0byib6Fs87nmfoBMUka2GJia8BkJeJQrBjq9x4QV3q2ibNNKzaJPUpQ/640?wx_fmt=png&from=appmsg "")  
  
但是没有跑出来，应该是没有未授权漏洞，做了全局验证，逐个删除cookie字段，但还是不行，没有cookie就被深信服的设备拦住了。  
  
那我们回到最开始的sql注入，该如何扩大危害呢？  
首先我们要判断数据库类型，于是我继续看js  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5rPtr6DlG3ZXgWjABgt13ypCdtsAS2Tav8mzicwgMcj1pUF8icOa5tapg/640?wx_fmt=png&from=appmsg "")  
  
一开始看到了from dual，我以为是oracle数据库，然后尝试了oracle数据的sql语法，发现总是报错。  
后来再翻js数据包的时候，发现了这个包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib5QpkK02OJoDgicc6DGkQoQIr3WWWWJF8Z1CclIVEqJRGs6Ogox68TDLQ/640?wx_fmt=png&from=appmsg "")  
  
这个数据包不仅直接暴露了usr_bsp，重要的是告诉了我们这个是postgresql数据库，这个数据库不太了解，我去百度了一下sql语法。发现他和mysql的语法差不多。  
```
select table_name from information_schema.tables where table_schema=''
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU9MJx8rBFLAP6icoy9Wiaeib53scwIlXRn7woADsCxpD1rBxs4PUeIcCoWWHW8RMZ7VGUvGAO2cBtJg/640?wx_fmt=png&from=appmsg "")  
  
成功注入。然后在征得校方同意后，可以使用postgresql数据库的集成利用工具直接进行rce。  
  
至此，渗透告一段落。  
  
注：严禁未拿到授权就进行渗透测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x7 内部圈子详情介绍**  
  
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
  
星球现价 ￥40元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于400人 40元/年  
  
星球人数少于600人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWeuMPBRkPema0jlwibpxWEDJSWyZvtpib5n7NJiaM1lqSeSYeiaKmFrRj7wfHjEWkgTH2zZHiaxKsG2MQ/640?wx_fmt=png&from=appmsg "")  
  
  
欢迎加入星球一起交流，券后价仅40元！！！ 即将满600人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUnhlsZ6XSFnqia8w2c1EicoYZYx1WKX3mtsCeiblhQKkonJr1BXj5mlefZE8U2ibUnyibG9ZvbibNMC8Rg/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
  
  

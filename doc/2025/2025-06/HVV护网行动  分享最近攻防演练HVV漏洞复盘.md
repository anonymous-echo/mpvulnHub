#  HVV护网行动 | 分享最近攻防演练HVV漏洞复盘   
 安小圈   2025-06-05 00:46  
  
**安小圈**  
  
  
第680期  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPWCg0bWJibYH4B7Ij03RyfQDRJyuK7yjQdbAibIk92HedGlXIEqlU6udyn2CnicjOcEiandrU9xP8f2w/640?wx_fmt=png "")  
- [HW必备：50个应急响应常用命令速查手册一（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546304&idx=2&sn=45ef99e528ded7ff2e65e4d70e6d5181&scene=21#wechat_redirect)  
  
  
- [HW必备：50个应急响应常用命令速查手册二（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546327&idx=2&sn=cf1ebbd2b511524ec965a3672b6fc3dd&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPHxBKycX4wbkZKPG894ae9pzqf0iagDegRFPKLVKK8r4gKWR0fbwSwHScSa6s7PzOBVlIXp5NibCAw/640?wx_fmt=jpeg "")  
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。#   
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**0x1 前言**  
### 浅谈  
  
师傅们又又又到文章的分享时刻了，这次给师傅们分享的是前段时间打的一个省级HVV的攻防演练，然后呢，也是借着这次写文章的机会，给师傅们复盘下，然后自己也可以总结下，把团队打的部分漏洞也复盘下（漏洞不完整，部分敏感的getshell、rce的不透露了）。  
  
总的来说团队的几个大牛子还是蛮厉害的，菜鸡的我都不好意思了（哈哈哈），然后呢今天给师傅们写这篇文章，分享下漏洞挖掘的案例（好东西心里面藏不住，就想着给师傅们分享了），然后顺便把我在这次攻防演练打的漏洞给师傅们分享下。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf07R7zWRCbmUEfxUltRG2vIqcNGretUC7jibvvk0oZM1UW5wzvCgpaJZQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**0x2 攻防演练的简介和注意事项**  
  
### 一、什么是攻防演练  
  
攻防演练是一种模拟真实攻击和防御的活动，旨在评估和提高组织的安全防护能力。在攻防演练中，一个团队（红队）扮演攻击者的角色，试图发起各种攻击，而另一个团队（蓝队）则扮演防御者的角色，负责检测、阻止和应对攻击。  
### 二、攻防演练的步骤  
- **规划和准备：**  
确定演练的目标、范围和规则，制定攻击方案和防御策略，并准备相应的工具和环境。  
  
- **攻击模拟：**  
红队使用各种攻击技术和工具，模拟真实攻击，如网络渗透、社会工程、恶意软件传播等，以测试组织的安全防护措施和响应能力。  
  
- **防御检测：**  
蓝队负责监测和检测红队的攻击行为，使用安全监控工具和技术，如入侵检测系统（IDS）、入侵防御系统（IPS）、日志分析等，及时发现和报告攻击。  
  
- **攻防对抗：**  
红队和蓝队之间进行攻防对抗，红队试图绕过蓝队的防御措施，而蓝队则尽力阻止和应对攻击，修复漏洞，提高安全防护能力。  
  
- **分析和总结：**  
演练结束后，对攻击和防御过程进行分析和总结，评估组织的安全弱点和改进空间，制定相应的安全改进计划。  
  
通过攻防演练，用户可以发现和修复安全漏洞，提高安全防护能力，增强对真实攻击的应对能力，同时也可以培养和训练安全团队的技能和经验。攻防演练是一种有效的安全评估和提升手段，有助于保护组织的信息资产和业务安全。  
### 三、攻防演练常见丢分项有哪些？得分项有哪些？  
#### 常见的丢分项  
1. 漏洞未修复：如果目标系统存在已知漏洞，但未及时修复，红队可以利用这些漏洞进行攻击，导致丢分。  
  
1. 弱密码和默认凭证：如果目标系统使用弱密码或者默认凭证，红队可以轻易地获取系统访问权限，导致丢分。  
  
1. 安全配置不当：如果目标系统的安全配置不当，例如开放了不必要的服务或者权限设置不正确，红队可以利用这些漏洞进行攻击，导致丢分。  
  
1. 未发现攻击行为：如果蓝队未能及时发现红队的攻击行为，或者未能有效地监测和检测到攻击，导致丢分。  
  
1. 未能及时响应和阻止攻击：如果蓝队未能及时响应红队的攻击行为，未能采取有效的防御措施，导致攻击成功或者造成严重影响，会丢分。  
  
#### 常见的得分项  
1. 漏洞修复和安全补丁：如果目标系统及时修复了已知漏洞，并安装了最新的安全补丁，可以得分。  
  
1. 强密码和凭证管理：如果目标系统使用强密码，并且凭证管理得当，可以得分。  
  
1. 安全配置和权限控制：如果目标系统的安全配置正确，并且权限控制合理，可以得分。  
  
1. 发现和报告攻击行为：如果蓝队能够及时发现红队的攻击行为，并及时报告，可以得分。  
  
1. 有效的防御和响应措施：如果蓝队能够采取有效的防御措施，及时响应和阻止攻击，可以得分。  
  
得分项和丢分项的具体评判标准可能因不同的攻防演练规则和目标而有所不同。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**0x3 漏洞复盘**  
### 一、文件上传  
#### 1、浅谈  
  
因为这次地级市的攻防演练的资产范围非常广，你比如说像市、县、镇等这些有关的政府、学校、还有这个市里面一些大点的企业的资产都可以打，所有来讲难道不是很难。下面这个站点就是一个事业编政府单位的站点，开始也没什么说的，像这样的登录站点，一般上来就是弱口令测试，下面的这个站点也是先使用弱口令test:test进去，然后再扩大危害。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0qoel3LHQbicwNQOQONFuG6ibPDxoqGUPHa0oUJ31rHicdHA06q0KjvFew/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
后面的深入利用就交个队友了，自己对于内网的渗透测试还是没有那么熟练，后面进行getshell拿权限，提权等内网遨游的一些敏感的截屏和数据之类的就不给师傅们演示了，其实吧像这种，主要就是思路，案例都差不多，因为这个站点也确实是没有做任何的防御。  
  
#### 2、具体打法如下  
  
因为是test测试账号，所有进去师傅们可以看到功能点的权限并不多，师傅们可以看到下面的议题列表中的添加功能，然后这里存在文件上传的功能点  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0iaNWbNuXhITOAYSdHZcETjKsHjjiamZ5YHAEJenbXjAsFBrmZmPDI0jw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
下面来试试这里文件上传，随便上传一个图片上去，然后利用bp抓包看看里面的数据包  
  
这里我只是点击选择文件，没有点击下面的绿色提交按钮，但是看数据包可以发现已经上传成功了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0WL2ugQ5IOtCDurUHk4ldHUPMtv2uzrAAibFTooydGAPml7Q2wH2xQMw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
我们访问下这个图片上传成功的路径，看看是不是真的上传成功了  
  
访问返回包的路径，可以看到确实上传图片成功了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0wqicWiaBbhT8jM5ouPOh7Htnqc1QZWjDoCricejPRhnNp8aDrzAkr2eQA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
删掉后面的图片名称，然后看看能不能打一个目录遍历漏洞但是这里没有成功，返回403权限拒绝访问，说明存在这个目录，但是没有权限，也算是一个思路了吧  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0rQ9XgaXN0lt6kSIs7LL6EiaIhHGKrWC5xQfrut1JM0h4Ycal20dqHBQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
 通过几次数据包的抓取，分析发现这个站点的上传文件的方式没有任何的过滤方式，应该可以直接上传恶意文件，然后getshell一波。  
  
  
使用wappalyzer  
插件，可以看到这个站点是使用php搭建的，那么就可以上传php木马上去，然后打一波phpinfo()了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0YueH7ucZoNe6W3MW6oE1W5mCbziboibVz9ZUzF0BnN1UkHuHQnLeTRvg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
  
直接打一个phpinfo()证明危害即可  
```
-----------------------------19248753661017244075365571982
Content-Disposition: form-data; name="file"; filename="xiaoma.php"
Content-Type: image/jpeg
GIF89a
<?php
phpinfo();
?>
-----------------------------19248753661017244075365571982--
```  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0cgsm04sw7Sb0AhYThAu7b3rSB9E4eBQMmdYvPeXIVR19YSSMjEFc6A/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
  
   
  
然后再直接访问这个地址，可以看到直接打出来了一个phpinfo()的页面  
  
后面要是上传木马，然后getshell也是可以的，但是这是测试，没必要上传木马，直接证明危害即可  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0YyeCIib3xUWrOicnjk5KaZSEkclxr58qpiaZITC4G7duqLqZlchic7F1UQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 二、微信小程序两个key泄露  
#### 1、session_key三要素泄露  
  
下面呢是我在挖那个市里面的人社局的微信小程序，说到微信小程序呢，师傅们应该是不陌生的，特别是打微信小程序常见的几个泄露，比如说这次要分享的session_key三要素泄露案例漏洞就是其中一个。session_key三要素泄露指的是SessionKey、iv以及加密字段全部泄露出来，一般在微信小程序使用手机号一键登录的时候常见的泄露，但是很多都是泄露iv以及加密字段，但是session_key值泄露的少。  
  
可以看到这个数据包直接把SessionKey、iv以及加密字段三个部分全部泄露了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0BBXTDTo46Ifph4qvqza7QN5geosnzLKy684h3h6ndYzOiao1TCl5MoQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
得到session_key三要素泄露之后呢，就需要使用我们的一个Wx_SessionKey_crypt这个工具了（需要的师傅们可以私信我，或者加我微信获取）  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0ftXwu51GQSLayd6EfISEL5PQkdJ26DHjYjEEdSFxu3e2wBmR2dtDyA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后把泄露的三要素放到工具里面，然后解密，就可以看到我们的手机号了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0RYShAiaaZXLcemZfNe1SHGvv2EfcOmictV8w2xFKib0aYBo3iaxHKDkxyg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
其实利用这个漏洞的危害也很简单，就是我们可以在这个微信小程序的站点找到里面管理员的手机号，然后去替换手机号，然后再反向加密，然后再替换回开始登录的数据包中，然后再一键放包，就可以成功登录我们管理员的后台了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0oM0Cx5qLJ5Y2eXzyjAS6MTnbvEPSCseibEoJstdFNic4T7vSkoqK0e8w/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0Dn5oB9A541zLQPOX6ooAXgmKuDL3WPskzoxOH7LIutnqc924h5e5Qw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
#### 2、微信API接口调用凭证+Access token泄露  
  
这个access_token泄露我感觉蛮多师傅都不是很了解，师傅们可以先去网上找下Access token泄露的相关文档，比如微信官方就有相关的文档记录。  
  
在公众号和小程序均可以使用AppID  
和AppSecret  
调用接口来获取access_token，所以一般在打微信小程序的时候，一般都是泄露AppID  
和AppSecret  
，然后通过微信官方的接口来获取access_token，然后进行再一个利用  
  
获取Access Token接口的网址如下：  
```
https请求方式: GET https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=[APPID]&secret=[APPSECRET]
```  
  
给师傅们看下在一些站点的网页源代码泄露的appid和appsecret参数值，长什么样子  
  
不过下面的这个参数进行了魔改，是key和secret泄露，也就是对应的appid和appsecret泄露  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0OblGHeDgVg2uxSib1ibGzoeT7ibUjWph1wF6cUKtMzNCJaicX1SXSiaKicHw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
先利用  
appid  
和  
AppSecret  
获取这个大学的微信小程序的  
Access_Token  
值  
  
显示7200，说明我们的Access_Token值获取成功  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0XialyPJFlUJFibbhg4cMzWwmuuibvctcaA8GNoRAibUdKgE7fvkWKsAO0g/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
后面再利用就是直接使用微信官方的一个站点进行深入利用了，后面就不继续写了  
  
下面这个在线的测试接口的地址是微信公众和小程序的官方测试使用的网址，相比上面的需要记住GET传参的url，下面的在线的测试接口的地址更加方便，且功能点也全  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0psVHt1ojDtyJtPok2umchZgDJUtZb89zicKasySn8BoIibsicnND8s7RQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 三、Springboot泄露  
  
下面的是Springboot泄露的漏洞，然后呢这个最后面是打穿了，云接管，OSS存储桶接管、数据库什么的都拿完了，拿了很多的权限分和数据分数，这里简单给师傅们分享下  
  
他这个是那个里面的好几个Springboot接口泄露，然后/actuator/env接口泄露泄露了我们常说的ak/sk和用户账号密码之类的，直接可以云接管  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0VVLSXTbH6BPoBSlC0PDUejQywgrqE1G9TbaU9gFIbRETfpwh8tUiaAg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0MMryOozHuvr47AHrEI1XKAUl30PGmTBRicAPyMic3rEojanKiaSLoeoUQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后在上面的云接管以后，找到了mysql数据库的账号密码，后面也是直接拿下了这个mysql数据库  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf09cLcM6dPnGOAmDu0xMf1aqULE1iaXHjYVujoArFP17LQ6gSHs3D5fibQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后还有就是这个OSS存储桶泄露了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0TzMQfaeqvQf6wN3uXEsmrRm5iccHoBRNh8PcKzuGVVqmq6JCfibLeicQw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 四、druid弱口令/未授权  
#### 1、弱口令  
  
碰到若依，一般都会去尝试拼接下druid路径，然后要是有登录页面，那么我们就可以尝试下使用常见的druid弱口令进行登录，或者弱口令爆破了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0yfc0ZmWE3IN6J02hDeroS0RuWc8o2VS0KOEOQKNc1FVSS2PeWdBeAg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
常见用户:admin ruoyi druid  
  
常见密码:123456 12345 ruoyi admin druid admin123 admin888  
  
其中在这次攻防演练中找到了好几个站点都是druid的，且都是使用弱口令可以直接登录进去的，其中druid:123456占多数  
  
泄露很多url接口，且都可以进行访问测试  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0NV2Jwlt2mxWWI8DaQHicBr9odnxw8l3clBmDQWYtlKnicedO2nlvLT4g/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
#### 2、未授权访问  
  
如果网站无需登录，则可利用未授权访问漏洞，直接访问下面的springboot常见报错界面404直接拼接**常见路径(可构造未授权拼接尝试)**  
```
html:
ip/druid/index.html        ##Druid Index
ip/druid/sql.html        ##Druid sql监控页面
ip/druid/weburi.html      ##Druid Web URI监控页面
ip/druid/websession.html    ##Druid Web Session监控页面
json:
ip/druid/weburi.json      ##Druid Web URI json
ip/druid/websession.json    ##Druid Web Session json
Druid 登录接口：
ip/druid/login.html        ##Druid登录认证页面
```  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0iclTXtibib1FEIiaYUy8zukSasaF0dlpXdfCaaCHuiabZxkWvscian2mwZaA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
### 五、存储型XSS漏洞  
  
这次在打到最后一天，说什么还有好几个资产没有打动，目前还没有扣分的记录什么的，说打了漏洞双倍积分，然后也是在这上面水了两个存储型XSS漏洞，就当是给小白看看吧，大佬直接划下面看别的漏洞案例吧。  
  
打的方式也很简单，像在评论处容易存在存储型XSS漏洞，下面给师傅们演示下漏洞案例  
  
直接在评论处插入XSS的简单语句，我这里就不打出来了  
```
```  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0Gd4ibD0GNGEFzFlJGStdwMyho6kSnibgibyc9EqibKfXR3ntp3kOwyvh5g/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
插入之后保存，然后刷新下页面然后再次访问这个关于我们这个功能  
  
可以看到直接打了一个XSS漏洞，且是存储型的，每次访问都会弹一个XSS  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0Jw9plOtROm5tssu8sevMLke7ibG4IicFcRUBw8icR7RMflKibbnWoJ34xw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 六、nacos未授权  
  
正常的nacos系统是需要登录才可以进去访问的，但是在这次攻防演练中也碰到了好几个直接IP或者域名后面扫描目录，扫到/nacos路径，直接拼接就可以直接访问  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0PqFAOHZIiaicKqsftG4IlGQv3DiaKc6h49NqQwfUia91HqUn03tPS8Zpjw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后可以在里面看到一些mysql数据库的配置信息，包括我上面写的泄露ak/sk，然后云接管，这些漏洞我之前都打过  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf08vVw2m6bLVZqYUxhEcxzCEY3nngzUH76xc1pNEfKIJ3ObB0wKVTTxw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这里有一个通过弱口令nacos:nacos登录进去的一个系统，然后我在里面的配置文件中找到了shiro的key密钥，然后我直接打了一个shiro反序列化漏洞，且可以直接执行命令  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0nVWic1erMVe1BNwXaBySebFK8anxjqZl0d6BOaAN36xwzYib0sbDeLww/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf03zp2ZtpVo9L56oCM29AfHfZbFicwU2RHJPbHiaSvibvibC1TcdF5fumrVQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 七、swagger接口泄露  
  
最后来给师傅们分享下swagger接口泄露的这个漏洞，我发现好多系统都存在这个泄露，虽然说有些系统泄露的swagger-ui接口需要进行钥匙验证登录，但是还是有不少是直接可以调用这个接口使用的，这里建议师傅们使用曾哥的spring-boot工具的字典去跑，然后我这里也总结了自己的一个dir.txt敏感swagger泄露的 字典（有需要的师傅私信我，到时候免费发给你）  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0lxibyibw93cFBoYAPQOSMAlMAjw8pWkcc56peic9KSouSwiaBUfbqibb0cg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
像这样的swagger-ui接口很多，且这样的泄露大多还没有加密，直接就可以调用接口  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0CdfkuljJshQC74rCHb09yRxS0nrwt52bb5G6jsHgA9kVsJpvCpuW1w/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
还有更加离谱的就是直接泄露doc.html后台接口管理页面，里面改系统的所有接口你都可以查看，而且看着也很清晰，就像下面的这个一样  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0QLpibv6ichC7qOkHJfDCs6YRnqFlrvDRVb9P1uELkdbp9fm9TxzbX6jg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 八、某站点未授权创建普通用户  
  
这个也是通过弱口令进入管理员权限的登录后台，然后在创建用户的功能点进行未授权测试  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0BDyibBrGDK4RnEDO35IEub5FmohGUUTrfZL95BRaibhkBkDJFta6Hickg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
下面我们直接拿bp抓包，抓这个admin管理员创建用户的数据包，那么我们要是测试未授权，就可以尝试把这个token删掉，然后看看还能不能创建用户了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0HcgkdXG5LnVhRGGFSvrUanXXosYMfj9vNDVuKftCdwYWP9Gibm8nnqQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以看到把token删掉了，但是还是可以创建用户成功，这样未授权就成功了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0YicfSGIMsmXPsKMr4jVG1k2Kpssqc9PposICG22u7Sstj2AvnGFNysA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUdw0fIEibpEVmUKvoKLgdf0Kk1UxBLwpcZUSfLukKJ6Ver6sMODy4ybN3yIcU73adDtnBXLaqOMTA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**0x4 总结**  
  
好了，师傅们文章到这里就给大家分享完了，上面有看的上的工具都可以私信我，我免费给大家分享，主打一个贴心，师傅们看完觉得作者写的可以的，也可以点赞收藏加关注噢。  
  
上面介绍的案例呢只是这次攻防演练的九牛一毛，但是因为很多涉及的截屏和内容比较敏感，不太好拿出来，太显眼了，一看就知道是哪个系统，到时候人家给我举报了，就吉吉了。然后看完文章以后，也希望对师傅们有帮助，祝愿师傅们多挖洞，多出洞！  
  
  
  
END  
  
  
  
****  
****  
**【内容**  
**来源：神农Sec】**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeeR4VInT56J0KCLD3HkiaRxjMLLV6rricOadHohJB1sOtPT02fETAxr4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
- [HW必备：50个应急响应常用命令速查手册一（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546304&idx=2&sn=45ef99e528ded7ff2e65e4d70e6d5181&scene=21#wechat_redirect)  
  
  
- [HW必备：50个应急响应常用命令速查手册二（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546327&idx=2&sn=cf1ebbd2b511524ec965a3672b6fc3dd&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOYnlSTuddD9AoYM6ZLqHdXZD7gtWoJu7iaLlM0VoeDsEeDuvntc8l44mHvKarBMTrrciaibgaqNiav6g/640?wx_fmt=jpeg "")  
- # 公网安〔2025〕2391号《关于印发《网络安全等级保护测评高风险判定实施指引(试行 )》的通知【附下载】  
  
- [等保测评 |【2025版】网络安全等级保护测评高风险判定指引（报批稿）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546234&idx=2&sn=a9b86c571d82e7ef70017f9a84e011be&scene=21#wechat_redirect)  
  
  
- [【实操篇】等保三级 | 安全区域边界-测评指导书](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546234&idx=3&sn=bc5d50602c2b7bd8f5a8f6eaa86e2ed0&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
- [2024年网安上市公司营收、毛利、净利润排行](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
- [突发！数万台 Windows 蓝屏。。。。广联达。。。惹的祸。。。](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
  
  
#   
- # 权威解答 | 国家网信办就：【数据出境】安全管理相关问题进行答复  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247539649&idx=1&sn=8858b449c89d21240e1f522e92be4fbd&scene=21#wechat_redirect)  
- # 全国首位！上海通过数据出境安全评估91个，合同备案443个  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544405&idx=2&sn=a961d43ca4a9ed667fccbbab758d9196&scene=21#wechat_redirect)  
- # 沈传宁：落实《网络数据安全管理条例》，提升全员数据安全意识  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
- [频繁跳槽，只为投毒](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
- [【高危漏洞】Windows 11：300毫秒即可提权至管理员](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
- [针对网安一哥专门的钓鱼网站](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
- [为什么【驻场】网络安全服务已成为大多数网络安全厂商乙方不愿再触碰的逆鳞？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOYPldtHVUmKQJ2WtL12GUnHRyzBiaKosLNicTZ2QkDFSRPUha2Eiaqk8R5fPdXc75zxprkTRB0ib5hUw/640?wx_fmt=jpeg "")  
- [HW流程以及岗位职责](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=3&sn=97e6083dbfbdd896680e24770a10d319&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247543989&idx=1&sn=2821b91efdd626e1a38ec6b2b439186b&scene=21#wechat_redirect)  
  
- # 网络安全【重保】| 实战指南：企业如何应对国家级护网行动？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542929&idx=1&sn=8cf6f15ddca44e343a494eea0fa619b2&scene=21#wechat_redirect)  
- **DeepSeek安全：AI网络安全评估与防护策略**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542701&idx=1&sn=567674aa12d861c3561d453268badb91&scene=21#wechat_redirect)  
- **虚拟机逃逸！VMware【高危漏洞】正被积极利用，国内公网暴露面最大******  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542458&idx=1&sn=d81d049331d175a2176f0978d7f032a8&scene=21#wechat_redirect)  
- **挖矿病毒【应急响应】处置手册******  
  
****- **用Deepseek实现Web渗透自动化**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542225&idx=2&sn=244a465fab183f4fa91a284b92a920e6&scene=21#wechat_redirect)  
- **【风险】DeepSeek等大模型私有化服务器部署近九成在“裸奔”，已知漏洞赶紧处理！**  
  
****- **关于各大网安厂商推广「DeepSeek一体机」现象的深度分析**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
- [Deepseek真的能搞定【安全运营】？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540432&idx=1&sn=b9e7e6103e86b9966f29d7eacf8e3d1e&scene=21#wechat_redirect)  
- **【热点】哪些网络安全厂商接入了DeepSeek？**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540206&idx=2&sn=300737ad84f684e622fdde03da0fc1a7&scene=21#wechat_redirect)  
- **【2025】常见的网络安全服务大全（汇总详解）**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540343&idx=1&sn=59d6f592f71a7f1e3a18fd082aa3de40&scene=21#wechat_redirect)  
- **AI 安全 |《人工智能安全标准体系(V1.0)》(征求意见稿)，附下载**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMbfUY7RtO1t6ZAxjoibZoZ8DSVPU0yI9v2nXpiat0oN8eLia5jiaoWOhlib5GiaPWQJeCsUmShI4QOqaGg/640?wx_fmt=png "")  
- **2025年 · 网络威胁趋势【预测】**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbM09kF5tXEb8PRXicFibPic4un6rwDI2CBUxrVaDINuM8ChyotgWiag4icErAHniaYNYiccQiaVkyyJUTX13w/640?wx_fmt=jpeg "")  
- **【实操】常见的安全事件及应急响应处**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbMASB7RibZ1nezrias4SvtcqzjvsJJPXhFiceJPEoVHVLhI2Soolaf8OhWQOVafycOibiaclJkT7NgG4Nw/640?wx_fmt=jpeg "")  
- **2024 网络安全人才实战能力白皮书安全测试评估篇**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeOsnl5ayrQXc0wPVutL1dQXg7BugT7vAe8qkpfszTrlhUAq4DQZFaVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  

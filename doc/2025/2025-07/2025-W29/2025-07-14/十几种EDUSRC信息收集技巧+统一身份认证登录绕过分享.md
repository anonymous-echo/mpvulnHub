> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247493169&idx=1&sn=afaa43d238367731678a16f4743b3963

#  十几种EDUSRC信息收集技巧+统一身份认证登录绕过分享  
原创 神农Sec  神农Sec   2025-07-14 05:20  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
  
**EDUSRC挖掘技巧汇总+信息收集各种姿势**  
  
  
## 0x1 前言  
### 浅谈  
  
哈喽哇，师傅们！  
  
这期文章给师傅们分享下针对于edusrc的挖掘打点和信息收集过程，非常适合小白师傅（厉害的大牛就当看个热闹哈），然后写了很多信息打点的，对于目标站点的一个资产收集的一个流程。  
  
然后呢最近在挖教育类edudrc漏洞，然后最近在研究大学都有的站点功能——校园统一身份认证登录。这个站点每个学校的学生管理端基本上都有，然后每个系统的认证登录点也不一样，对于这几天的研究，然后也是成功先通过信息收集这个关键的步骤，然后再对校园统一身份认证登录点去进行一个认证登录的绕过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx73iauX6yyhW73TQdVv2xTtTGFcdiaabKX1MfUCXf95LtbB63ZLdAic4Cpw/640?wx_fmt=png&from=appmsg "")  
## 0x2 信息收集+资产收集  
### 域名查询  
  
开始我先介绍下使用域名查询的方式，给师傅们演示下利用域名的一个信息收集和资产的收集过程  
  
就比如说下面的这个大学的站点，这个一看就是官网，首先我们看到的就是这个域名  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7PJFze7wN0G9NQwllQWIp8sVRWfz208WjEhVYatVbg7ub97MvomH1FA/640?wx_fmt=png&from=appmsg "")  
  
然后我们使用这个域名进行一个信息收集，给师傅们分享一个信息泄露比较好用的一个站点：  
  

```
https://intelx.io/
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7qb2VkcNKxs7dr5VMG18eibteTLaAfJhts8dya5XwxMwXtxVcaJVfkuw/640?wx_fmt=png&from=appmsg "")  
  
我们直接把刚才要收集的edu站点域名之间放进去，然后进行相关资产的收集  
  
师傅们可以先看到下面的对于该大学的域名的一个图形化的收集数据如下，可以看到收集的还是蛮细节的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7OfDcNFUrrct5YEm16icNwOvBIEaMOoF1WCFQE7EhJZIODwRDPAhwiaJA/640?wx_fmt=png&from=appmsg "")  
  
里面的相关泄露的信息需要师傅们自行去筛选，不一定都是正确的，因为这样的站点也都是通过一个一个数据进行爬取来的，作为一个信息收集的库，也就是只能碰运气了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7ibaqz3ujibKKGHnmvG26OlVlAnvmX1dyR9XN7UDBiasUrFKvwVOysjfcg/640?wx_fmt=png&from=appmsg "")  
### 邮箱查询  
  
那么我们再在该大学的官网站点进行一个往下看到最下面，一般都会有这个大学的邮箱信息，那么邮箱信息也是可以可以打一波信息收集的了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7ianvrZIWdicocDUJeNPv7aSozRujQYKDRyuia9tJhvbH5iaeiajENgNhpZw/640?wx_fmt=png&from=appmsg "")  
  
那么说到邮箱的信息收集，我就要掏出我的
```
小狐狸头
```

  
站点了，也是常用的一个针对于邮箱的资产收集的站点：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7IDn47b8icciaHrI2yp30hQc464YtrU51IclWszrpyY8HhSMC1SL1sj5g/640?wx_fmt=png&from=appmsg "")  
  
然后我们之间把我们需要收集资产的该大学的邮箱丢进去，看课能不能收集到什么有价值的信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx70gh8tpTpRl5bl8PiajPAajte0fvN4iaT7BJkFasVEMumEoKic59zDsonw/640?wx_fmt=png&from=appmsg "")  
  
一般来说 什么edu学校邮箱 或者某些HW行动 企业集团 这种查询邮箱效果比较理想  
  
比如其实有的时候 你查询某edu大学的邮箱的时候 ，其实你可以从**邮箱都能找到学号和工号**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7tRGLt6M0a9K0zveoBFK5jbtZd3btWTeTgHsGlCQiaw9tEgq3P5jsubw/640?wx_fmt=png&from=appmsg "")  
### ICP备案信息查询  
  
还是按上面的一个思路，看到大学站点的最下面，ICP备案信息也是一个资产收集的一个重点，因为像这样的大学备案信息相对来说比较全，然后我们就可以利用比如说空间引擎啊进行一个检索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7hAGhfE2QJZHgoqlosnJACJlbJcJXFc9XCvjznCF0P6J6fiavCSJJKGA/640?wx_fmt=png&from=appmsg "")  
  
比如使用常见的FOFA和鹰图这两款空间引擎进行一个ICP备案信息的一个检索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7LgfgSqIt6r1BYlhofofQcs8YTdd5tJJ3EREUunzzGtQgNp1kFXPEPw/640?wx_fmt=png&from=appmsg "")  
  
可以看到下面利用FOFA的一个ICP备案信息的一个查询结果，可以看到查到了8条站点，然后还找到了两个icon图标，这些都是信息收集，都是可以记录下来的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7vy14Btic7IzujXvofqGco6Yx5VJDfUDy4KPXL32KpxW34kqlfndckuw/640?wx_fmt=png&from=appmsg "")  
  
可以看到下面的这个关键信息，这个学校的
```
校园统一身份认证登录
```

  
 的站点被我们找到了  
  
那么我们后面再利用鹰图进行一个检索，然后看看校园统一身份认证登录相关的信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7xiarVOy8VNLf6C7picP5hibLMayhp69BpicPcJibmIUmfstDVt1j7awrjgg/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到我这里也是找到了该学校的校园统一身份认证登录相关的信息，因为这次我主要是针对校园统一身份认证登录来打一个漏洞的，因为校园统一身份认证登录相关的信息很多的站点你要是通过信息收集到关键信息，是很好打一波逻辑缺陷漏洞的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7tXQySINm8VQiaITHfqnsJzKbjWRZqtP2ibT2D0KLsmErpV4lVWUKvcicQ/640?wx_fmt=png&from=appmsg "")  
## 0x3 综合资产查询姿势  
### FOFA+鹰图  
  
刚才上面通过空间引擎FOFA和鹰图都查询到了
```
校园统一身份认证登录
```

  
站点，那么我们这里之间去访问这个站点，  
  
可以看到很常见的一个统一身份认证的一个界面的功能点，一般常见的就是利用学号/工号/或者身份证号之类的作为账户，然后再利用密码进行一个登录的操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7pdU3mWMlJibdAjNLiaaIpwdg5Gic7b1b26IzKJDeesjwqF19RhIUYOQibA/640?wx_fmt=png&from=appmsg "")  
  
比如要进行统一身份认证的一个账号的收集，也就是常见的收集学号之类的，可以看看左边的这些系统，比如你可以去找下这样的web系统，然后可以看看在里面通过一些nday漏洞啊或者常见的弱口令登录管理员后台，然后拿到一些学号之类的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7At8sjGQM3pyia144V0uGaUdOAIxbE7rbnQDMIltyz0yZjqKgoS8PT7A/640?wx_fmt=png&from=appmsg "")  
### 企查查/小蓝本  
  
这里给师傅们分享下使用企查查和小蓝本相关的操作，我们在平常对于某一个站点目标进行打点的时候，会经常碰到要收集该目标的相关资产或者说收集到的资产不全。那么我们就可以利用企查查和小蓝本的作用了，特别是里面的vip付费的模块，可以很大程度的帮我们快速找到对应的目标的相关资产。  
  
比如下面拿企查查查询某个资产，然后可以特别关注下面的知识产权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7Wj5ntibWGfTvd7bkVuQNCm4axMTag7ibOibL25w6SSesq3zelFQL5Jqxg/640?wx_fmt=png&from=appmsg "")  
  
下面的域名收集起来，然后使用灯塔ARL或者oneforall子域名收割机去跑相关资产的子域名，然后进行去重，然后就可以收集到很多可以打点的资产了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx78Db4sHbK7QutPWHSqKuJFMmIp6UibANsskhB1rjFEfzibhqOaAJEUavQ/640?wx_fmt=png&from=appmsg "")  
  
还有就是微信小程序的一个收集了，有些时候web端没有账号密码进不去，那么我们就可以尝试下在微信小程序进行一波打点，然后通过微信小程序的一个漏洞打点然后再到web端  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7d4zzaIt7WpjSp72yGemwiaJTcZmbV9xNodFS2QH452cp2meeWO6nGhw/640?wx_fmt=png&from=appmsg "")  
  
力推
```
小蓝本
```

  
可以直接新媒体 能查到公司旗下有哪些公众号小程序或者APP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7aic7VxlvfWdsNKKgo4Zq7iaLoObic8D8QZhIEjCCTukVS42FfuhEk1S1Q/640?wx_fmt=png&from=appmsg "")  
  
下面推荐一下狼组大佬的爬虫工具，专门针对于企查查和小蓝本的一些付费功能的信息  
  
基于各大API的一款企业信息查询工具，为了更快速的获取企业的信息，省去收集的麻烦过程，web端于plat平台上线  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7EZJ8TvspmN9crtBdMpyNThrSOqQNqBicRIsj91Jem11MR660JL4IJiaA/640?wx_fmt=png&from=appmsg "")  

```
pythonENScan.py-kkeyword.txt//keyword.txt里面填企业名称
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7Cvxce3icLfX7I05oyYgvXa2BlWQ9cUbXoBt9cAITzzf1fibbmI3uHBBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx74Z3Ag7W6VP454vBKqNFicSRDEppzkAEQhiaNzN4mFddkKQ5fFBicVBjQQ/640?wx_fmt=png&from=appmsg "")  
### Google黑客语法  
  
收到信息收集和资产收集怎么可能少的了Google浏览器呢，Google浏览器的黑客语法是一个十分强大的存在，特别是在以前网络方面管的不是很严控的时候，很多大牛都是使用一些厉害的Google语法进行一个资产的收集，在以前学校的一些
```
身份证
```

  
和
```
学号
```

  
信息经常能够利用这些语法找到的。  
  
下面我也简单的给师傅们整理了下一些常见的一些
```
Google检索的语法
```

  
，如下：  

```
1.site:域名intext:管理|后台|登陆|用户名|密码|验证码|系统|帐号|manage|admin|login|system2.site:域名inurl:login|admin|manage|manager|admin_login|login_admin|system3.site:域名intext:&#34;手册&#34;4.site:域名intext:&#34;忘记密码&#34;5.site:域名intext:&#34;工号&#34;6.site:域名intext:&#34;优秀员工&#34;7.site:域名intext:&#34;身份证号码&#34;8.site:域名intext:&#34;手机号&#34;
```

  
然后还有就是使用厉害师傅手写的工具，你把你想检索的关键字放进去，然后这个工具给你相关信息搜集的Google语法，比如下面的这个工具比较喜欢，感兴趣的师傅们可以去github上下载。  
  
或者师傅们私信我，然后给师傅们发下这个Google语法工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7d7GIEIY9p0uNEWRibHWswe2ZbxiblYodYpACnQdVSOVAxTU1vrsAzSwg/640?wx_fmt=png&from=appmsg "")  
  
下面就分享下之前我利用这个Google黑客语法工具拿下的一个大学的统一身份认证管理后台，当时也是尝试了很多的学校，然后进行挨个语法检索，然后再在浏览器中去进行信息检索，然后也是找到了该站点的身份证以及学号，后面也是成功登录了后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7mPWyGLS3PSgchxVhM1xicryUd84JVDPZS75kIr5ibpibWWpCo3zZdxM3g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7o4xso1icsQ8yqLiaMg9I9VJyBV1ibBuyZwnvoTCrQvia4WnRJiaGn6leDTg/640?wx_fmt=png&from=appmsg "")  
  
下面是成功登录该学校后台站点的页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7GnruVNuzK0xXqPSKQyjMpGutJNKBue1iaQ256dIfqkiaX6jOOM1SuoLg/640?wx_fmt=png&from=appmsg "")  
## 0x4 统一身份认证登录绕过  
### 一、逻辑缺陷绕过  
  
还是以刚才最开始进行资产收集的那个大学站点，然后也是开始进行资产的收集然后后面通过FOFA和鹰图找到了比较多的站点的信息，然后找到了一个实验室的一个后台站点，刚好那个站点使用弱口令admin:123456直接登录了进去  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx70HibDarPTjyRwicfX2ribHibUtg7GM9a6ciasnyWHoySqSf6LdRo7UE0snA/640?wx_fmt=png&from=appmsg "")  
  
然后里面有一个导出数据的功能，然后也是可以看到该实验课的所有学生和老师的姓名、学号、班级信息，信息泄露严重，可以看到下面的数据总共有好几千个学生和老师的信息都出现了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7BA44PPwLWgm0DgxDcDia8wz6GwKO5QuH9ed2ia4wdYMoS1oBDOBlC5Fg/640?wx_fmt=png&from=appmsg "")  
  
上面的就是我在进行信息收集的时候收集到的该学校的部分学生的学号信息，你像要是在打edu的时候，获取到了该学校的学号以及身份证之类的敏感的信息，都可以去找找该学校的统一身份认证管理后台，然后看看他的这个登录机制有没有可以绕过的功能点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7pdU3mWMlJibdAjNLiaaIpwdg5Gic7b1b26IzKJDeesjwqF19RhIUYOQibA/640?wx_fmt=png&from=appmsg "")  
  
下面我们首先看，这个统一身份认证的登录时要我们输入学号和密码，我们这里知道学号，然后密码的话，我们是不知道的，但是我们可以尝试使用bp进行一个弱口令123456的爆破，看看能不能出一个弱口令的账号密码，然后进行一个登录后台的操作  
  
可以看到利用bp抓取数据包，且账号密码都是以明文的形式输入，所以可以尝试爆破的方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7HUfUibA1c5GedL6ib4TV8ibAYGtzYynk7gjicOQ2OYvm8cib6nZ3MzARNHw/640?wx_fmt=png&from=appmsg "")  
  
爆破没有成功，应该是要求改强密码了，不过没有关系，这个也是一个思路，主要是想给师傅们分享下一个在拿到账号的情况下，可以去尝试的操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7vRcB0fwibslaM5knS9dKU0uLhkZhnWazkXQSbdsUFG5Giav9W9lqMvYA/640?wx_fmt=png&from=appmsg "")  
  
1、首先我们点击下面的忘记密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7tQGCNqSHt7wUpSoAicdnWWhiaYQHyKkSCSCB6DuriaJeGZ3IUiaNibrzTKg/640?wx_fmt=png&from=appmsg "")  
  
2、一看可以找回密码，且要我们输入账号，账户就是我们开始收集到的学号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7ibtRZV8hBiaHFcxTpznOypcOlibrwrTFyMvTnAJiaakg56JSv9FRPn9sLw/640?wx_fmt=png&from=appmsg "")  
  
3、然后就到了这一步，师傅们一看是要接收手机号，那么一般就在想着应该没戏了，其实不是的，像这样的站点，其实可以去抓它的数据包，然后看数据包进行一个尝试逻辑绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7LwqibUKm0UErGArMNINuyqqTiaaA3IrzlUWb1cYfjjz9wAZCh46BLjDw/640?wx_fmt=png&from=appmsg "")  
  
4、通过bp抓包，然后进行数据包分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7w8v4MUaPpFUMeE0hAvelNBLdiaQEYVSiaUFMza0JmzibsBuSXfuRP8RiaQ/640?wx_fmt=png&from=appmsg "")  
  
5、这里直接右击看看返回包，然后通过返回包看看这个是通过什么方式进行的前端校验  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7jFaIbia09ASh16M4Haxkq5eUfnHmMRcFc0vicGKDKsibdbcClBdoTdGcQ/640?wx_fmt=png&from=appmsg "")  
  
然后进行分析这个返回包，师傅们可以看到这里可以判断下这个前端是通过下面的返回包的哪个字段进行的校验  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7UoEibnXGrHpSicxdVSCenJDdaHKQB5mlK8OH1VkBaeORW2l9pYkJAboA/640?wx_fmt=png&from=appmsg "")  
  
一般就是code和这个false错误进行的一个前端校验，那么我们就可以挨个尝试下  
  
后来把false改成true后，然后再放包，就直接绕过手机验证码了  

```
{&#34;code&#34;:&#34;B0000004&#34;,&#34;data&#34;:{},&#34;flag&#34;:true,&#34;msg&#34;:&#34;您输入的手机验证码错误&#34;,&#34;rows&#34;:[]}
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7wbBe3HxZqPicvjMqNV4QicFiaBUNRnrz0g0icl1lflSILwW9icEOHOibyLNA/640?wx_fmt=png&from=appmsg "")  
  
到此为止，我们就成功的绕过了改身份认证登录后台的修改密码的验证了，主要还是开始先收集到的学号信息，然后再进行一个前端绕过的一个判断  
### 二、爆破账户/前端绕过验证  
  
下面这个站点也是之前遇到的，改站点登录也没如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7m4rHdyedRlfC7FISXiaw0zVCaXlgzQUles2Qr7KvQkSNUZJBABatrdQ/640?wx_fmt=png&from=appmsg "")  
  
1、老样子，跟上面的一样，这里直接点击忘记密码，然后看看后面的验证机制是什么，然后再看看可以通过什么方式进行一个前端的绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx713IEnLERZWgpharUIZKnbuGREAzdjlrofiadB5QEn4P2lVSFyIqK4ZQ/640?wx_fmt=png&from=appmsg "")  
  
2、然后点击这个里面的用户名验证  
  
然后可以看到下面的验证机制，是验证用户名，那么我们就可以尝试一个用户名的爆破了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7mgzH56Hq4u17Tttvy0icmSnEQHy5YnVtax3A4iayPkJJJpWRePkL2qZw/640?wx_fmt=png&from=appmsg "")  
  
3、输入用户名test点击下一步并抓包，可以看到msg字段返回1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7Ud4v4uTNo1wpoMicSXqicWHR9H2Prfcp17bhcxuic7c5I8q7iamyjrjT5g/640?wx_fmt=png&from=appmsg "")  
  
然后再看看test666，看到msg字段返回0，那么通过判断发现返回0就是用户名不存在，返回1就是表示用户名存在，那么我们就可以是要常见的用户名字段去爆破  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7NQpswOlib7XD50aVicc0zG9ib4KHJrHPyTgEBR2ibmO3m0nxSfDAUICcOw/640?wx_fmt=png&from=appmsg "")  
  
4、爆破用户名，可以看到爆破成功了很多用户名，最后使用一个
```
108万姓名全小写
```

  
的这个字段爆破了很久，然后爆破出来了好几千个用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx78Ajnk7dQia8obKEYz8ytiaA9mQFQ2oQ376vO5NSmAsZ0kMDnaxp24PtA/640?wx_fmt=png&from=appmsg "")  
  
5、拿上面的用户去演示下绕过的过程  
  
然后直接这个也是跟上面的站点一样，使用手机号验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7H6GAmFJnHkUeP7sP1z4djMMJHTmcFYvdIXsDZcIDxuiavYh2nVsmvrA/640?wx_fmt=png&from=appmsg "")  
  
6、这里抓包，然后看这个数据包的返回包，然后进行判断一个前端绕过  
  
可以看到这个又是一个msg参数的前端验证，那么下面就是尝试一个msg的修改，然后看看当修改为什么的时候可以进行一个前端绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7Q8PXvXswGnI5ERibgWhx6rMia7D1MnkVRSo1EzlCNyhk8k79RATR527w/640?wx_fmt=png&from=appmsg "")  
  
这里后来通过判断msg修改成2，然后就可以成功绕过前端验证码的验证直接绕过了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7ygBQAIEoZMEq165jKTvDjvZytzx2IwiamyCBVg789plMPX8vibjEqxDw/640?wx_fmt=png&from=appmsg "")  
## 0x5 关注edusrc开发商排行  
  
随着edu平台的跟新，我发现他多了一个开发商排行，这样等于是给我们列出来了edu用户的系统公司，就可以节省我们的时间再去查找开发商来找对应的系统.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx79ZoRStQYrTZqw2OPlHmgBF7PHpFNMeNvKk9iaibSYUoYCWoSJicVXyoVw/640?wx_fmt=png&from=appmsg "")  
  
那么我们知道这些开发商后，我们只需要把这些开发商是产品进行收集，然后一些空间安全引擎比如使用FOFA、鹰图等进行产品查找不就可以达到系统通杀的效果呢？  
  
再看下面这个标题，很明显存在大量的弱口令漏洞，且修复率不是很高，那么师傅们这不就可以尝试下了嘛  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7mFfiaJIVfJB3F0hlJA8ibKh6KBhJduWy8f3qHtHGyWzpP786BssM1qcw/640?wx_fmt=png&from=appmsg "")  
  
可以看见对于系统的弱口令通杀还是通杀挺多的，当你通过弱口令进入后台后，继续挖掘可以扩大rank值。  
### 具体操作  
  
1、首先我们需要确定我们的目标厂商  
  
开发商名称：北京某某科技有限公司  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7YmlyZNkjzNqanv68iae1S5icSxHtgRhGcm2Cgjib2ZLq3CFjX36M0fjKg/640?wx_fmt=png&from=appmsg "")  
  
2、然后就可以使用我们的空间安全搜素引擎了，比如我平常常用的FOFA以及鹰图，都是蛮不错的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx79Tician37LW3DEV2LAcoOWDQ5GMworEdZvzrBrbicoTEe4pue2mbicF3bg/640?wx_fmt=png&from=appmsg "")  
  
这里需要主要的是这里FOFA还给我们整理了icon图标，可以找对应的icon，然后也是同一系统，然后也是可以打一个通杀的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7aiboSiaBBqZHfHBOEQFtqwFbicUSHDRu2HLhK1FnR7ibl3hA4eAGVw5Dug/640?wx_fmt=png&from=appmsg "")  
  
对于这些都是属于网瑞达公司的这个产品，点进去你可以发现全是教育网段的！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7Ed4ic2fibnibmvSNXKrmASaRfAJMiar3TZuF2kgbz8QHcBVWvndYlJ54AQ/640?wx_fmt=png&from=appmsg "")  
  
3、接下来就是比如你可以去找该系统或者该学校的手册，然后去里面找找有没有系统的默认弱口令，因为很多学校系统都不该密码，运维人员也少，所以维护也没，这就可以去找下系统的默认弱口令了，然后再进去打一套别的漏洞，提高危害rank。  
  
你也可以先尝试常见弱口令，比如admin/admin admin/123456一类的，不成功就是寻找手册  
  
关键字查找方法：xxxxx（公司名部分关键字任意组合）xxxxx（某某系统）操作手册、默认密码、管理员手册（这里自己补充能涉及密码的关键词）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7WhLGwicY7sfpWpiaj5ZxFh07REnYh73oWVFK06DCqu6RJb0bMB0L0cMA/640?wx_fmt=png&from=appmsg "")  
  
可以看见有很多文档，需要自己花自己整理，找到有效的数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7yL9Lyz0lDry1qYzA5JNk4p1Y8PjXPY9N3KP2uv1yQCdqbicq80fqwRQ/640?wx_fmt=png&from=appmsg "")  
  
继续在里面找，还可以看到别的关键信息  
  
在我们的眼里这些是弱口令，但是在运维眼里这些密码均为强口令了，给自己减少工作量，有多少运维会去改密码呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx72vXxhRLounDmDF3YyyibK4aa0Gu4DsNYFC1HgSNuUNuRuHzwbyCxjbA/640?wx_fmt=png&from=appmsg "")  
  
其中也可以使用Google浏览器进行信息收集，也是会发现一些不一样的收获的，我们可以看到下面的检索内容，就可以很明显的看到这几个学校使用的系统就是我们的目标开发商的系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7R5RTZ1aNOKMFa742Cxb9AWnGYh5ytv0CglYvKSVz9icKYzlanfdeO6A/640?wx_fmt=png&from=appmsg "")  
  
当然如果你没办法找到手册，那就自己构造密码：方法也很简单，通过企查查一类的网站对公司信息收集  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx7vnjLwac4sf80zf3QWicaVM6xMwAnicP9q0kic4QT4nM5zkibop3B32cLnA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVCzQGkhbC4ibmqOYUYBiaGx78NkRJD7LCicrK4LBNxeMPpE04IkNfic7Qdxib9pUVBREwnQeA94Fp6Z7A/640?wx_fmt=png&from=appmsg "")  
### 浅谈  
  
可以得知网站命令习惯：wrd wrdtech webvpn 这一类信息（这里的信息你收集的越多，构造的字典爆破的机会越大，其余同理，自己扩展）  
  
我们就可以利用wrd这些来组合密码，比如wrd@123 wrd@admn123456 wrd!@#qwe123 这样构造弱口令去爆破，这里你可以花1—2天 如果一旦突破那么就是一个通杀！相对于还是划算，没成功就等于锻炼了信息收集能力。  

```
123456adminadmin@1231qaz@WSX10dingdm1n$10@ding@dm1n$wrd@admn123456wrd@123wrd!@#qwe123
```

  
这几个是我收集该系统时候收集的密码，账号可以使用admin/root跑一下  
## 0x6 总结  
### 浅谈  
  
这篇文章很详细的给师傅们总结和演示了统一身份认证的一个绕过的过程以及这个思路，先是给师傅们很详细的介绍了各种对于一个目标资产的一个收集，然后再到下面的利用这个收集到的资产信息去打一个怎么样的漏洞，收集的信息越多，对于我们后面的打点渗透测试工作就会越轻松。  
  
下面给师傅们分享了两个真实网站的大学案例的绕过过程，像这样的站点，尤其是Java开发的站点，都可以利用这样的姿势去尝试绕过，可以说这样的技巧都是通杀的，只不过前提得看你的信息收集能力了，你得收集足够多的资产然后再去一个统一身份认证的登录后台去进行一个逻辑缺陷的一个绕过。  
  
  
**内部小圈子详情介绍**  
  
  
  
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
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于900人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKogHTNRKIZQVcM0QQE3wbFrFciafzrEaRcia7gkRFb4vujBubqic3sPIN1g/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满900人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKovBgx57dc6Ql2yRSPBJGA5fde4sQJzOomD1GURVibZeCNzXM6iaGrSe8Q/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  

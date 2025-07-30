#  手把手edusrc漏洞挖掘和github信息收集   
想当文人的黑客  Z2O安全攻防   2024-09-18 21:07  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
## 0x1 前言  
  
这里主要还是介绍下新手入门edusrc漏洞挖掘以及在漏洞挖掘的过程中信息收集的部分哈！（主要给小白看的，大佬就当看个热闹了）下面的话我将以好几个不同的方式来给大家介绍下edusrc入门的漏洞挖掘手法以及利用github信息收集的过程以及给师傅们分享一些比较好用的工具哈。  
## 0x2 信息收集——github  
#### 介绍:  
  
在漏洞挖掘的过程前期我们进行信息收集，github和码云搜索相关的信息，代码库，运气好的话可以在库中发现一些重要配置如数据库用户密码等。  
  
这里先给师傅们分享一下**手工gtihub搜索语法:**：  
```
in:name baidu              #标题搜索含有关键字baidu
in:descripton baidu         #仓库描述搜索含有关键字
in:readme baidu             #Readme文件搜素含有关键字
stars:>3000 baidu           #stars数量大于3000的搜索关键字
stars:1000..3000 baidu      #stars数量大于1000小于3000的搜索关键字
forks:>1000 baidu           #forks数量大于1000的搜索关键字
forks:1000..3000 baidu      #forks数量大于1000小于3000的搜索关键字
size:>=5000 baidu           #指定仓库大于5000k(5M)的搜索关键字
pushed:>2019-02-12 baidu    #发布时间大于2019-02-12的搜索关键字
created:>2019-02-12 baidu   #创建时间大于2019-02-12的搜索关键字
user:name                  #用户名搜素
license:apache-2.0 baidu    #明确仓库的 LICENSE 搜索关键字
language:java baidu         #在java语言的代码中搜索关键字
user:baidu in:name baidu     #组合搜索,用户名baidu的标题含有baidu的
等等..
```  
  
然后再给师傅们分享下**github官方文档**：   
github检索文档  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIdODicgnZK7mucIniariaVDl9Wu6PrVjrR0QwpDOQC8ibduRU9uxPmd3JUQ/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912192939830  
### 自动化工具——GitDorker  
  
GitDorker工具下载 GitDorker 是一款github自动信息收集工具，它利用 GitHub 搜索 API 和作者从各种来源编译的大量 GitHub dorks 列表，以提供给定搜索查询的 github 上存储的敏感信息的概述。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIE9ToddlK2xCiaC8eKVqZyZR1Hu5cGPoETNblSTq2fc6AiaC11pMkU5cQ/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912192955572  
  
**挖掘泄漏方法:** 可以从域名开始找比如: xxx.com 我们就使用github.com 等平台等搜索语法对包含xxx.com进行搜索，再一一进行逐个排查或者直接使用上方等自动化工具，直接跑也可以。  
  
**高危案例:** 某某某.com 存在敏感信息泄露，数据库用户名密码等泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIibZ6uoQK2qJ2d2Z4erSE4yDk23zqw2Qzkep22H8LdbeeM3E4500UC8g/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193420899  
  
通过查看库内文件找到了 数据库配置等信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIVYXMe02dyn3MTpme2ljalOHSlaMBm3ZPrmNL7SXiaY7h11Mp4NU5ichQ/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193428440  
## 0x3 利用FOFA打管理系统src  
### 浅聊下  
  
对于新人刚开设挖edusrc的时候需要花大量的时间来找系统和信息收集，当你遇见的系统又waf的时候可以适当的放弃别再这上面花时间了，列入sql注入，一个单引号尝试报错和闭合（最多就是把简单的绕过尝试一下）如果不行，那就果断放弃。其实对于新手来讲，可以多去尝试挖下edusrc的XSS漏洞，这个简单，且也是TOP10，感兴趣的可以看下我上次发的一篇文章  
记某大学智慧云平台存在弱口令爆破/水平越权信息泄露/Wx_SessionKey篡改 任意用户登录漏洞 新手入门edusrc还是推荐先从微信小程序开始。  
  
主要还是说一些系统的收集方法：1.利用fofa 语句："系统" && org="China Education and Research Network Center"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIZ4ib2YjjWzVK0vZpRDicY9Mdia0ib3z6QrogYDfo3ey0QxH9AAcM4msrbA/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193436225  
  
我们可以看见红色框内是有很多图标，这些有可能就是系统的指纹，fofa直接给你归纳好的，接着点进去查看即可：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIDoPWgY9XMrhwTEoXTH2iaibWpKJJoK5Aibb0jL94luHWicJFksHjIxzaNA/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193446271  
  
现在我们只需要一个一个图标打开然后用傻瓜式渗透顺序打一通：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIhsNUBXylIHKoy2agHvcIgwbhHiccicBFAQaOm48TnOmroFRMoXa0bicKw/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193454442  
### 案例分析  
  
例如上图所示，我们可以看见独立的xx条ip那么就是说这个系统有xx个用户在使用，点击查看：标准的某某系统后台，而且暴露出用户手册。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIbsPzejVia6P4xvKgMaYObfeDIjtl6v77DSTmsd1W43OEXL3orSopyow/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193501800  
  
第一个就是弱口令操作：admin /admin admin/123456 admin/admin888 这样的，最好的方法就是自己积累一个常用字典，当然还可以去全网寻找这一套模板的管理员手册，在后面就是github去寻找一下，最后都没有办法的话,那就放弃。  
  
第二个自然就是top10：万能密码（sql）、xss漏洞的挖掘。  
  
第三个：逻辑漏洞分析 首先还是先使用f12查看页面源码，说不定管理员密码写在页面中的！然后可以注意到功能点是密码重置点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI425SpIqxTrs3wkjepV6oTrPia8TqlFX4EGu4KzsUic1oWyaTLic8PxCKw/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193509869  
  
那么我们可以简单的两个操作，首先就是获取登录数据包进行修改返回包看看是否可以成功登录，如果登录成功就是逻辑一个，不能登录成功那就绕开进行下一步测试，第二个操作就是我们分析js，查找重置密码的接口，看看接口是否存在未授权。  
  
其中看js接口也是蛮重要的一个点，比如常见的api接口，就可以尝试使用js接口探测插件————FindSomething 可以探测到我们自己手工去找可能找不到的接口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIBCplMJNCgkSiaBBFJx7Hy0Uia9OvaqgIxUy6WFWpWPbIcHwzTazsozag/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193520681  
  
可以看到我这里使用bp进行接口爆破，然后配上bp的插件HAE，可以检测到一些存在未授权访问，敏感信息泄露的信息，常见的比如身份证号、手机号、姓名、家庭地址、毕业信息什么的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugInRTFo7FOaFthfkfX0rPosleoqflmg6tefxR7DBSIxwQXTrMyI8tR3A/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193533261  
  
上面就是我尝试爆破然后成功获取到了上万条敏感信息。  
  
上面的功能点没有的的话，那就换下一个功能点：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugILTic8gqYiaQMeNQJpQkuiavwV7RQVcthSGR4vkgiaS7BPEoELQTUDAj1AA/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193540755  
  
显而易见的是查询功能，那么第一反应是sql注入，如果有waf,可以轻微尝试绕过，因为edu中的系统相对于企业中就脆弱多了，当然sql注入理解的越深入，那么你挖sql注入的概率越大，任然常规操作，可以看看逻辑漏洞是否可以直接爆出密码这些。  
#### 案例：  
  
使用语法，这里需要自己灵活收关键字，只要组织对应是edu，那么站点都是可以收纳的，我们可以看出来是30个独立ip，那就是有30个学校在使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIaeKy98RWXeeacyXRiaAcUVFGHcUEZOiazIXxCSeHlibRrKwoAzctX0Asw/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193548405  
  
下一步任意点进去可以看见是一个系统后台：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugINl8la0WVdPKglQJbB3vuL4rSJzS20g0E4jt3SBHxDnNQ0JCnnPLksA/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193556085  
  
常规的都操作了，这里就是这么简单，修改返回包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIasUHic8VJfVg9iatTaQQXibmgcdpa2iafaU7DVO0pGbtSy9srYjDbQq27w/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193604416  
  
后面将"err_code"改成1，然后放包即可成功登录后台，这不就是一个edusrc的通杀了嘛。  
## 0x4 总结  
  
edusrc漏洞提交平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIMoArcy4rmicr70r6m3nKMfhOLJIEpCicd4Bhc25rj4X24MpZibK8Aq83Q/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193611717  
  
在edusrc漏洞平台提交漏洞的话是可以换取精美的学校证书以及一些实体礼物，还是蛮不错的，但是更重要的是可以提升自己的实力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIE7HQF3Mib4LojhvsVCzrhZ5qmjQADBrRmSianQvru0RvbWSXpseZMcMg/640?wx_fmt=png&from=appmsg "null")  
  
image-20240912193622065  
  
这篇文章主要是讲述开头利用github信息收集，可以手工以及使用github的工具进行资产测绘。但是一些空间引擎也还是蛮不错的，比如FOFA、鹰图等都是可以资产测绘的。然后最后希望这篇入门的edusrc挖掘文章能够对师傅们有一点帮助吧！  
  
原文地址：https://xz.aliyun.com/t/14970  
  
### SRC专项漏洞知识库  
  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCOPMibnJIeBT6Yv0RwBJT9AFHKEbo3BxYkLnE00jVuoLicSOBCIzMiaJKQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZgZWOn7rbuXzhsF8NTxQxiaysdet2jL9s2nNdDGwscgXVbAgNsFeQQG7uO5askUSYFMsWKlkIicEaw/640?wx_fmt=jpeg "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIx3z6YtXqmOkmp18nLD3bpyy8w4daHlAWQn4HiauibfBAk0mrh2qNlY8A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI5tZcaxhZn1icWvbgupXzkwybR5pCzxge4SKxSM5z4s9kwOmvuI3cIkQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIstia27YLJFBtC5icJO6gHLLgzRDqib6upI3BsVFfLL02w6Q8jIRRp0NJA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
  
****  
点个【 在看 】，你最好看  
  

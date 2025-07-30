> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTQ5MTAzMA==&mid=2247484517&idx=1&sn=e03f98bbb89978b550a97c773fa5a27a

#  盘点闭眼就扫的RCE漏洞利用工具  
 天黑说嘿话   2025-07-18 00:50  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**前言**  
  
安服累，渗透狂  
，一入网安破大防，莫说勤奋自然强；  
  
挤地铁，上HW，渗透工位坐机房，意淫桃谷伴身旁；  
  
电脑背，把砖扛，夏日无处可乘凉，聊得牛马命更长......  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wglPJSKsjavlPXbVSOeibPolksYTMZEHOUvXmnBne1o8aZl6pbx1ch1cUbhneAPGhhc8icfJ33S52L5ZKCVzXgOw/640?wx_fmt=gif&from=appmsg "")  
  
网安沉浮数载，今抬眼望去，乌云密闭，熊猫也曾见过网安璀璨，奈何世事境迁，昔日行业追捧的网安牛马已沦为吃瓜群众，坐看漫天风起![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Sigh.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Sigh.png "")  
......  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPWAcVBMB8x2uUiawAHSbKrn0cc8YMXs2SVEdTVMKxjI4HWddHpxKib20g/640?wx_fmt=gif&from=appmsg "")  
  
之前熊猫发过两篇关于遇见WAF如何凑漏洞数量的文章，发现不少兄弟都比较感兴趣，也对，老话说得好，坐着不如倒着，好玩不如......  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPsxTnAsXgTM1cewC3ibjdakkD6m6ELMLraRxxATDaYfAmzgpZrI7p4Sg/640?wx_fmt=gif&from=appmsg "")  
  
疲惫的日子里，谁不喜欢省力又舒服呢？感兴趣的兄弟可以翻看下之前的文章......  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwOTczNzIxNQ==&mid=2247484942&idx=1&sn=c4b3823c9ede37dd09890612a713419b&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwOTczNzIxNQ==&mid=2247485156&idx=1&sn=7524e1eb352e6b71471d5c14aab911d0&scene=21#wechat_redirect)  
  
今天熊猫分享一些闭眼开扫的RCE扫描工具，漏洞检测工具比比皆是，但是熊猫分享的主打的是图形化![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
，所有工具均有分享，见文章底部......  
  
**WARN**  
  
**提前说明一下：**  
  
**本文章涉及漏洞扫描工具均为开源工具，所有涉及工具只可用于安全测试自用，请勿对任何网站进行入侵攻击，小日子的除外......**  
  
  
  
**愿兄弟们看完文章之后**  
  
**划水越来越多，挖洞越来越丝滑**  
  
**注：本期只发傻瓜式扫描器，后续会分享一些其他工具单独再发一篇文章**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg26qToz9ts0NJic0of6uibrMGZheo9pf9ZlKR90picqzMG9NRmic3Vtz9QsA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**Shiro反序列化漏洞综合利用工具**  
  
Shiro的特征判断比较简单，  
响应报文中会包含rememberMe=deleteMe字段，在任意一个抓包工具中都可以看得到。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPhUu5S3fMXApzxl8J3j1Lml1yYXs592OgfrSkPp5qZ1Dzcbk0mFyIlA/640?wx_fmt=png&from=appmsg "")  
  
但是熊猫不推荐使用人工判断，因为人工判断到Shiro框架后未必能找到Shiro的漏洞目录，熊猫推荐个BurpSuite插件，直接可以命中Shiro漏洞存在的目录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPoAFaxtDp2icHDdvySN7BKEIsAZKAyuV8gCAXib8zBwEDu25UzOLOXDeQ/640?wx_fmt=png&from=appmsg "")  
  
之后就可以爆破Shiro秘钥一条龙，比较简单。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPK7NVw9icnPJrYqDIib8sKiafz6KnFpKlHrvcqegEu0yBjp28MPkStEcTg/640?wx_fmt=png&from=appmsg "")  
  
确认漏洞URL拿出我们的Shiro反序列化RCE工具扫描漏洞URL就可以直接任意命令执行了.....  

```
#Shiro反序列化漏洞综合利用工具项目地址
https://github.com/SummerSec/ShiroAttack2
#Shiro的Burp插件项目地址
https://github.com/pmiaowu/BurpShiroPassiveScan
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDP6MVoSUB0NLhjSf8lvcIeg3iaOwSraHOg8jBTy8h5hkqqCafHtq8VGCw/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**Struts2全版本漏洞利用工具**  
  
ABC_123大佬前些天刚发的最新版，熊猫还没怎么用，Struts2框架熊猫通常是用一些CMS扫描工具直接铺开了扫描框架信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPwgMTGCab7AcEVjicMQCNRAZHTnpCaHPI1kpG3ibjGQTMLabSFRz6kvFw/640?wx_fmt=png&from=appmsg "")  
  
导出扫描结果后筛选Struts2、Log4j、SpringBoot框架，  
或者使用Burp插件被动识别  
（下方工具也是一样）  
，然后无脑开扫......  

```
#Struts2全版本漏洞检测工具项目地址
https://github.com/abc123info/Struts2VulsScanTools
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPEUtb6qMGoHrZyB6m6kcMicNyrrFziaCUZcqH5y1AtGNibrxr0Ll2FOnLw/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**JBoss漏洞利用工具**  
  
JBoss环境的漏洞比较老，目前基本很少会遇到，但是熊猫也一起讲讲吧，通常JBoss漏洞成因都是一些接口开放存在隐患，比如  

```
CVE-2017-12149：http://域名:8080/invoker/readonly
CVE-2015-7501：http://域名:8080/invoker/JMXInvokerServlet
CVE-2017-7504：http://域名:8080/jbossmq-httpil/HTTPServerILServlet
CVE-2007-1036：http://域名:8080//jmx-console/HtmlAdaptor
......
```

  
手工利用没必要，直接上工具，工具也没什么好说的，扫描确定好框架，点击即用  
（注意Java环境需1.8）  
.....  

```
#JBoss综合利用工具项目地址
https://github.com/fupinglee/JavaTools
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPOFmvPuzsicZuY4XqwroGia6ogjicSowsM82YN3umDK2AQibbXM3ibBIyf1Q/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**Jenkins综合漏洞利用工具**  
  
Jenkins 是一个开源的自动化服务器，用于实现持续集成（CI）和持续交付/部署（CD），很多公司都有部署使用。  
  
工具扫描依旧没什么好说的，  
确定存在Jenkins，点击即用  
（注意Java环境需1.8）  
.....  

```
#Jenkins漏洞综合利用工具项目地址
https://github.com/TheBeastofwar/JenkinsExploit-GUI
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPaVOkILwicdiclB2ozW1UroK3ZVnx9WKkfWSadCJibG7J6iaJ2nFtmX1Giag/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**Nacos漏洞利用工具**  
  
Nacos是阿里巴巴开源的一款动态服务发现、配置管理和服务管理平台，专为云原生应用设计，很多外包项目会使用这个。  
  
工具使用依旧没什么好说的，  
dirsearch扫描  
确定好框架，点击即用  
（注意Java环境需1.8）  
......  

```
#Nacos综合漏洞利用工具项目地址
https://github.com/h0ny/NacosExploit
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPLuibxPunsWRwu9RChJqBAJWmQhXK5ErZT2ruxU4hMI29OBiap87zWmEw/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**Spring漏洞利用工具**  
  
Spring漏洞，懂的都懂，更没什么好说的，  
扫描  
确定好框架，点击即用  
（注意Java环境需1.8）  
......  

```
#Spring漏洞利用工具项目地址
https://github.com/charonlight/SpringExploitGUI
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPXOwibAEnh0rxt8KFwM53AOyIDw43zlSCwlB1YrxnfD6c6R94euNMf8w/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**ThinkPHP漏洞利用工具**  
  
经典漏洞复现，相信网安牛马初入行的时候大部分接触的都是PHP语言，所以依旧没什么好说的，  
扫描  
确定好框架，点击即用  
（注意Java环境需1.8）  
......  

```
#ThinkPHP漏洞利用工具项目地址
https://github.com/bewhale/thinkphp_gui_tools
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPQR5k5TqiaDicWPr6gicSlTfj0jicicVcj7O2RFL9gQfpYJ3Ozh5pVX8xeUw/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**WebLogic漏洞利用工具**  
  
依旧  
没什么好说的，  
扫描  
确定好框架，点击即用（注意Java环境需1.8）......  

```
#WebLogic综合漏洞利用工具项目地址
https://github.com/KimJun1010/WeblogicTool
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPNuIZqyQ8n1xBtQ1LRjicESowF8S4JJqWJyicbv9KjYR9JI9iatOh7cOXA/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**XX-Job漏洞利用工具**  
  
依旧没什么好说的，  
扫描  
确定好框架，点击即用......  

```
#XX-Job漏洞利用工具项目地址
https://github.com/charonlight/xxl-jobExploitGUI
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPhc3l4GbBoWTn9syfRKSpjma3HOOmZuxPtDjh4JP0e3pex4BdTkiaa3w/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**其他乱七八糟的漏洞利用工具**  
  
漏洞利用工具多的一批，很多兄弟下载完了就放在电脑里落灰了，所以熊猫觉得用啥留啥，不用搞那么多，以下是熊猫的一些其他的漏洞利用工具，有一个共同特点，都是图形化界面的![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPMTIvlpwjpGqhtytumWclCRJeoC4rcVPxvaHtlP53f1GvgXkX6ibda4Q/640?wx_fmt=png&from=appmsg "")  
  
有很多大佬已经把这些漏洞利用工具整合到一个GUI上了，比如  
Spear工具箱  
这样的，自行根据所需配置自己能用的工具......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPCdboasyKLVmgYAA1QcPKq7bVNs18ZtqwDAyH59lrmiatet4oKpVvT0w/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**文章工具获取方式**  
  
觉得逐个下载麻烦的兄弟可以私信公众号“  
漏洞利用工具  
”获取网盘下载链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjaumRqiaQkdtic5f3ldExY2bDPq4Vw4jSAr8RRuaxon5iccMdvvFIojokKtQ8TsMI3UEG33VmcFJ4yuRw/640?wx_fmt=png&from=appmsg "")  
  

#  漏洞挖掘|某次SRC引起的连锁漏洞挖掘   
 白帽子社区团队   2024-08-12 23:08  
  
本文仅用于技术研究学习，请遵守相关法律，禁止使用本文所提及的相关技术开展非法攻击行为，由于传播、利用本文所提供的信息而造成任何不良后果及损失，与本账号及作者无关。  
  
**关于无问社区**  
  
  
无问社区致力于打造一个面向于网络安全从业人员的技术综合服务社区，可**免费**获取安全技术资料，社区内技术资料知识面覆盖全面，功能丰富。  
  
  
特色功能：划词解析、调取同类技术资料、基于推荐算法，为每一位用户量身定制专属技术资料。  
  
无问社区-官网：http://wwlib.cn  
  
  
  
**0x01 前言**  
  
**本篇文章共2700字，完全阅读全篇约6分钟，州弟学安全，只学有用的知识**  
  
 实在抱歉各位，我实在找不到什么好点的封面了，这个封面稍微有些装，请原谅我，言归正传，最近这几篇文章一直在围绕学习干货板块去写了，个人的写作和总结能力也有了不小的提升，停笔一想，漏洞挖掘的实战咱们也不能含糊啊，哪怕是水洞，本次是某次SRC中的一个不起眼的资产，引起的多个漏洞，在文章的最后会归纳总结，不知道各位还记不记得之前画的思维导图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpPLcVEBW08yse4Mc0Lx65sHKoXq0JrQygIDeRyNHhGNBbeEqEJaCe3OYF9GOicyibvVuvh0ou4KqR8w/640?wx_fmt=png "")  
  
    虽然在往下更细致的没有继续写，但是也算一个大概的框架，一个人一个思路一个想法，具体文章可以参考之前的一个总结  
  
**渗透测试|真详细！以实战学习渗透测试流程及报告(图文+视频讲解)**  
  
    当然，也可以前往：关注(州弟学安全)->右下角->历史合集->漏洞挖掘(学习)  
  
*** 本篇文章所提及技术仅供学习参考，请勿非法使用、后果责任自负**  
  
**0x02 漏洞挖掘**  
  
    开局一个小程序，能测的地方有限，在小程序上下功夫除了反编译分析源代码找接口就是找逻辑漏洞啥的，先看功能，是一个停车场管理小程序  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh50nCqGQHBZjXJ49bU6BJw37CmS8nQquwQ6DjFECwYx9xhhQP6uwsA3A/640?wx_fmt=png&from=appmsg "")  
  
    后面就是对于用户的功能，输入车牌号进行视频找车，现在看我们不知道车牌号，也不知道有什么危害，这时候一般就不想往下测了，但是为了放大危害面，抓包获取到域名及所属资产  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5T2hB2xdickqQa91icibXZWYf7S059GGbo3ICHhnicziaqsRrHTvB3GhH69Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5icvgiauyJibsI20K6wTNjpBbx0iaibxickvDIUJPWKOj2FOiafFHibd1xXW1SA/640?wx_fmt=png&from=appmsg "")  
  
    我勒个骚刚，注册资本还是以美元挂钩的，看了下股权穿透，实在不简单，这里就不放更明显的图了，搜集到相关资产，已知收录范围，存在的一级域名就这一个，直接挂ARL和手动在引擎搜集资产  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5HbTuVyXQuDROdKN42XeOO8DccR2yBic88Zx2ibWwaBJmFiaxvZFibGCYIg/640?wx_fmt=png&from=appmsg "")  
  
    有些资产因为端口开放比较大或不是常用端口，使用TOP100扫不到，所以建议工具+手工的方式去搜集信息，此处我也想扫大端口，但是网络由于运营商限制DPI原因，有端口并发连接限制，超出之后就断网了  
  
**一. 未授权访问漏洞**  
  
    这里是手动收集到的信息，和前面我们看到的小程序是一套，而这个未授权访问开放在10988端口(已虚化)，是车辆后台管理系统，而小程序则是用户端操作系统，前往车辆后台管理系统的WEB根目录我们可以看到一个目录页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh52MdhDTajHrabQBkRiaaPa3dwcibsup6uwzu1dn2QG4jkhp6YSbhsGDuw/640?wx_fmt=png&from=appmsg "")  
  
    当然，一般这个时候点击所谓的config或bin之类的基本上都是404，我们可以看到除了第三个目录，其它都是2017-2018年中间的，我们就看最新的，是一个日志目录，点到最新的日志文件看到车牌号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5u9n9nDrzh9hzt9Ymy4qTJLKibdncP3uyRJ571ZoIKiakibQ3EicibRyRbvg/640?wx_fmt=png&from=appmsg "")  
  
    日志开始->请求(加密)->传递参数(plateNo(车牌号))->响应参数(carImage(车头图片))  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5rztib5IYLhkeIssRvBHp4h3po6rcFiazBTCa2ibpVy6pZmpw63wuvhIbw/640?wx_fmt=png&from=appmsg "")  
  
    至于数据量，确实挺大的，然后这里的图片会定期删除，我们取出任一车牌号，在小程序是可以查询到相关信息前后视频信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5pIdPicI1icicnO4NmKEJ6ajdzpoUaaREnlOBmLkfstxBTicpibx7aVKwnQQ/640?wx_fmt=png&from=appmsg "")  
  
    这里复制图片地址，依次递归删除向上寻找其它敏感信息，很多的图片和文本文件等，直至登录后台页面/systemCar  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5RPo1ibVoMnssyQ39IlozRU3W9DlLoB2vT5q8FxP3a3gLKdUYyzwECcg/640?wx_fmt=png&from=appmsg "")  
  
    这里特征太明显，不便截取全屏，见谅！于是我又根据这个未授权访问特征，做为body进行查找相应资产，也有相关的资产，而且满足通用，先提交通用一波，至于后台登录尝试了，只有前端验证账号密码有没有输入，但是都输入以后点击登录没动静，就没再测试了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5dpRH9bGqibbiabpamNP00mwBXPj4d7To9nQ4LiaSJT0N0X1MYcPWkSV8g/640?wx_fmt=png&from=appmsg "")  
  
  
**二. SQL注入**  
  
    由于手动测试开放资产并不多，前往ARL看一下，我这里ARL配置文件开启了其它一些搜索引擎，应该会更全面一些，这里看到一个后台登录页面，非常简洁  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5f04Eb3hMGY4K1zuRoYZSjvUxavhqXf89IJf1AmGAZWZC2IvE9ziaZuQ/640?wx_fmt=png&from=appmsg "")  
  
    看这眼熟的URL，之前看过我文章的应该知道，非常像ThinkPHP，但是又不太确定，于是乎就随便尝试登录一下，确认为TP  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5VAxXc4Pj363kASn9JvFTpWTa6q2C8slrKAUSXmdpllUeFfFkUvhYGw/640?wx_fmt=png&from=appmsg "")  
  
    但是不知道开没开debug啊，没开debug就不太好搞了，由于不知道版本，先使用GUI工具测试一波，很好，没有漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh552NspmclQnUiaMXQvJvFAGlR9HjtKS4ABOcBQKC3cTHp0HWTLvticGsw/640?wx_fmt=png&from=appmsg "")  
  
    不知道各位还记不记得之前的一篇渗透测试的文章和打击杀猪盘的文章，同样都是TP框架，不同的是前者有历史漏洞直接梭进系统，后者没有历史漏洞但开启debug，获取到数据库数据  
  
**渗透测试|一次丝滑的渗透测试记录**  
  
[漏洞挖掘|记一次对某杀猪盘的漏洞挖掘(反诈)](http://mp.weixin.qq.com/s?__biz=MzkzMDE5OTQyNQ==&mid=2247485208&idx=1&sn=4b5cdb3715bc9f0e21f17e335f07f3cc&chksm=c27ca5f6f50b2ce0818dce243d0d90804aff4799026a9f0fdf7b8b1177cbe1f04638498047aa&scene=21#wechat_redirect)  
  
  
    我们此处在登录框内加入单引号或双引号等符号，尝试引起报错以查看敏感信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5HZZqjSlDo1nCvHcnDZavLibHIu3rUZ0DW2iaQTR3f530iawiajdJtmwMYA/640?wx_fmt=png&from=appmsg "")  
  
    经过使用单引号进行了报错，看到SQL语句  
  
```
SELECT * FROM `xxx` WHERE ( username='aaa'' and password='aaa' and deleted = 0 ) LIMIT 1
```  
  
  
    并且看到了当前使用的TP版本为5.0.5，以及一些其它的敏感信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5Ticiaj7fX3VZgK5z3B8tdNN66amsDvSBBqPoQHReibV5sSFsYn1WUNPtg/640?wx_fmt=png&from=appmsg "")  
  
    已知查询的SQL语句，直接构造payload测试延时，测试成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5aBDNtMvvIUzWwZN6GicTkHH0ph89MaoG1ZuOCOI901iaicZw0yLUuA1qA/640?wx_fmt=png&from=appmsg "")  
  
    已知注入点为username和password，直接使用sqlmap进行测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5VGIUSNibaXaTibs0ScQBCJ9LP5Y2De5qftcLQdBPC1RQLo5We33uA5Cg/640?wx_fmt=png&from=appmsg "")  
  
    不是最高权限用户，已知绝对路径，但是没法访问，而且版本无法写入文件，漏洞是没问题的，直接上交即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOne3OmyvIelAJMP9eTHnh5veA2Em0U0czsHsurOc4SjRqw4988RBIKY6iaPjE2czgM5rSDQZZ7DHA/640?wx_fmt=png&from=appmsg "")  
  
**三. 万能密码与文件上传**  
  
    不知道师傅们还记不记得以前文章说过的万能密码，此处已知sql语句，构造万能密码payload是否可以进入后台呢，可以参考之前的公交车漏洞挖掘  
  
**赏金猎人|SRC简单拿下某公交后台系统多个高危漏洞思路及试探通用型漏洞**  
```
1：'or 'a'='a 
2：')or('a'='a 
3：or 1=1-- 
4：'or 1=1-- 
5：a'or' 1=1-- 
6：'or 1=1-- 
7：'or'a'='a 
8：'or'='a'='a 
9：'or''=' 
10：'or'='or' 
11: 1 or '1'='1'=1 
12: 1 or '1'='1' or 1=1
```  
  
    经过测试以上payload经过闭合满足永真条件后，均可进入后台登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUK3GPzdMTKYj7PYfC5wKibI7xShMfQkjYiaVsbCQJI1tnaibKs4xLdyX8Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUo5ls7oIB0OpFHJ1gickHFVLJh1AVHmNB5YekdiaCoUW36EazGO1XA3LQ/640?wx_fmt=png&from=appmsg "")  
  
    这里没跑intruder模块，测试了几个payload可用就行，然后进入后台，看看功能点，其实很简陋，貌似已经废弃不用的样子，找到一个文件上传点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUHq13besh3TYJlhR2Qe78icflt1ecyUbztmrAhGMV3slZIsjQcicNgagw/640?wx_fmt=png&from=appmsg "")  
  
    想着上传shell，可能当时也是着急忙慌，一直提示我文件类型不对，我心想过滤这么严格吗  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUwHx7THnUybDOWG829YFc3HUfia7ibMmPuibdpiasPJFia4utKs7syiaucEFg/640?wx_fmt=png&from=appmsg "")  
  
    后面我尝试双写和文件头都不行，最后我才反应过来，是对content-type进行了检测，而我一开始上传的是php文件，文件类型不是图片，前端也没有校验，修改文件类型上传成功，但是没有路径，真的难受  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjU7pvPHByyp5R2UibkLn5KDC9Seh1ibhCujosYxmEboeVycrWyibslkBsaA/640?wx_fmt=png&from=appmsg "")  
  
    然后其它就是内部功能点的SQL注入，比较多，这里就不在一一提及了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUzhnVwwEsbFAoUFYZXmSDl3zlo0yvdfzNajwAqL74q7PRyvwSB9nJKg/640?wx_fmt=png&from=appmsg "")  
  
    然后前面咱们不是有泄露的车牌号了吗，因为进去得交钱，从这里貌似可以直接交钱，因为这是后台，相当于一个接口，前台收到钱后转给后台，然后后台进行缴费开闸操作，取到一个新的车牌号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjURw17hS5evRWRhcQQGxu3M3eDpT7d4ic69m45sffH8mZakJXsMOWXWNw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjULoniaytiaTOIEiayefy0m5AF8j7iaGQ3ZCerfXibjVoRSI1agyiaibicaHyO1w/640?wx_fmt=png&from=appmsg "")  
  
    感觉这系统挺奇葩的，没蜜罐特征，但又不像正常所为，看不懂哈哈  
  
**四. 小程序多处漏洞**  
  
    WEB资产很少，转战APP和小程序端，APP没有找到，依据关联性：比如公司名、下属单位名、品牌名等搜索到资产  
  
    (1). 第一个小程序漏洞是任意用户登录，此小程序功能是面向用户充电的，在登录入口输入手机号接收验证码，响应包存在验证码，如果已知对方账号，危害无需多说了吧  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjU7udGU6JthTjkSykIVXX9ibdGxQn9y9tyfzAO1d1nCnTnhp6ia3x9GrVA/640?wx_fmt=png&from=appmsg "")  
  
    接着可以在响应包的returncode看到验证码，可以直接登录进去  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUC9UTBUPFugvL35WNbL62ZR6LHqHFLKVbp0vgbuGT50NRBjO7dkfOUw/640?wx_fmt=png&from=appmsg "")  
  
    像这类问题之前也挖过不少，有的会存在cookie中，有的会存在请求包内容，有的可能在响应包  
  
    (2). 第二个小程序是企业访客系统，在登录时也是发送验证码，但是验证码在请求包内，验证码可控  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUqbXeG4cdWTvPvkTS1dGjfC1jppTmkSPo8b52S5t5DzWd2ePOnxhWZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUba1nC3Jq2Jiao2lK66WfNydRl8Zb9QdzNAFGzXzq5LLTxTjeRjFbcSA/640?wx_fmt=png&from=appmsg "")  
  
    这里我替换为自己的手机号，然后不限次数发送验证码+验证码可控进行验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUnN9lQGWZdEpqrmFiaxOvUCUWV4fNBqGsSkiaMvoF8YUGdbwgYslVUzwA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjU8Lp6UiaXJ5vs3oOHzzA4furEOU5eEicVVtlE2QdrfcpsMEVvMAjbvgLQ/640?wx_fmt=png&from=appmsg "")  
  
    至于能干啥，这里就不多说了，现在这个阶段对吧，然后我感觉他的逻辑应该如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUw916rukqIf9k7ica5l9WGrcjMSVuS8uApKXOqMWvyeNSQoEzt8OOEGA/640?wx_fmt=png&from=appmsg "")  
  
    之前也挖到另一个企业的SRC短信可控，但是那个是完全可控的，是一个SMS网关端口，参考下文  
  
**赏金猎人|记某商城任意短信发送(谨防电信诈骗)**  
  
**0x03 总结**  
  
    本次完成文章共耗费8小时左右(从信息收集到挖掘完成到全篇书写)，因为资产不多，然后也没有更细的深入，只验证了漏洞存在即可，各位师傅看个热闹就行，如果这篇文章对您的思路提供了帮助，也是我的幸运，最近写防守和学习文章确实比较多，没有此方向的更新确实抱歉  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOCkZt1wXl1GpNgeHiaBYVjUU1wQU5cUz1hBQWHWB4QafxkMDrlYnufDD9wXcLbibwzCWMvROPMibCNA/640?wx_fmt=png&from=appmsg "")  
  
*** 如您认为本篇文章质量尚可，麻烦点个赞，点个转发让更多人看到，万分感谢**  
  
****  
  
  
  
  

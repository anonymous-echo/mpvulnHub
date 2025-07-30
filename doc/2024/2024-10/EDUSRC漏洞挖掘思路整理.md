#  EDUSRC漏洞挖掘思路整理   
十二  秘地安全实验室   2024-10-13 15:01  
  
## 免责声明  
  
**本文所涉及的任何技术、信息或工具，仅供学习和参考之用。请勿利用本文提供的信息从事任何违法活动或不当行为。任何因使用本文所提供的信息或工具而导致的损失、后果或不良影响，均由使用者个人承担责任，与本文作者无关。作者不对任何因使用本文信息或工具而产生的损失或后果承担任何责任。使用本文所提供的信息或工具即视为同意本免责声明，并承诺遵守相关法律法规和道德规范。**  
  
  
**前言**  
  
挖edu一般来说有两种大思路，第一种通过代码审计审出某个cms的rce然后批量去刷分，显然不适合我这种混子，我只能先确定目标，然后收集目标资产一步一步去测  
  
本人第一次挖edu，发现大多数学校的系统都存在很多漏洞，可能常规的这些漏洞本身并没有技术难点，关键还是在于怎么拿到账号密码、怎么发现存在漏洞的接口，下面主要介绍一下本人的挖掘思路  
  
**关于信息收集**  
  
关于收集目标资产，这一步就不赘述了，通过鹰图、fofa、子域名工具去跑等等  
  
我个人是非常喜欢收集一些杂七杂八的信息的，当我确定目标学校的时候，我会把域名放工具里去跑资产，然后去谷歌、搜狗、github利用一些语法去收集一些信息(像学校公众号发的文章就经常发现一些敏感信息)，比如："site:xxx.edu.cn 初始密码/学号"后面加一些敏感信息去看一看，去关注一些操作手册、使用指南之类的，可能就会有意想不到的收获  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkS0Ajpicv4NvZ9xamJXe21r0WyaB3D5NovByPgoSdDicYfPf3PSqGk5mQ/640?wx_fmt=png&from=appmsg "")  
  
然后去学校官网简单看一看，收集下官方邮箱、客服电话这种信息，像这种表格名单里面没准就会有学号、身份证之类的信息，然后也有一些班级名字信息，以后钓鱼就可以用来冒充身份  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkz83frtuGU0jckrjAVc8ibop6aBz4Cr9o9xz14Cmj9fw01MOeHj7tSoA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkEjorhxCQescNVtMAavMDDRABARvwMicdLdAR7AYOy7Micm6Rib7e6ZibGg/640?wx_fmt=png&from=appmsg "")  
  
然后重点去关注一些社交平台（微博、贴吧、校园墙、小红书），800年没用过的qq也打开了，用来加一些学校相关的群，小红书我都没用过，但是大学生好多喜欢用，还专门去下载了个  
  
直接吧内搜索，搜索一些账号啦密码啦之类的，像学生的账号格式都是一样的，如果知道了默认密码格式就可以去密码跑账号了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkeia5Jteu36diakAA71JDEGBPk4PADic66XPE4WiasZibdlXNjnPXUPsBBbA/640?wx_fmt=png&from=appmsg "")  
  
像微博，直接去该学校的相关话题下去找一找有没有敏感信息，下面学生证里就泄露了账号，之前遇到了一个人直接发了自己被录取的几张照片，里面也发现了账号，很多系统的默认密码都为姓名首字母+身份证后六位的组合，然后我通过微博反查了手机号，又丢到了社工库找到了身份证，其他像表白墙、知乎什么的都可以去找找  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkNVO5siaEOLcs9WuyIaibKeRiaULc4aBM5kFZwbtUHjAUQrja4WesLldiag/640?wx_fmt=png&from=appmsg "")  
  
然后也可以自己去发布提问默认密码是多少  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkzYvVksIibiaw6F2I0Wj6cSMfy8ONIibCQpeINcH8g7dwrUfGEmQnBvoAA/640?wx_fmt=png&from=appmsg "")  
  
还有就是去发布一些招聘广告（百试不爽）钓鱼，像有一个学校，我是知道了他的账号是2022123272这样的，默认密码就是身份证后六位，于是我去找了下他们附近有名的酒店名字，去贴吧、校园墙发了兼职广告  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkCApUmAnelgES9TAmZ9kXlQpKSYtX6vbqn83NQdCMMwr6zBuKACuGLg/640?wx_fmt=png&from=appmsg "")  
  
然后问了下他大几的，确认了是2022级的，不过那个系统登录密码是加密的，跑的时候还写了半天脚本，最后也是跑出来了，没有强制更改初始密码的话大多数人是不会修改的  
  
这时候我们跑的资产信息也差不多了，进行个网站框架信息识别，对于springboot就针对性的跑一跑字典，很多cms都是买的别的公司的，也可以从这方面入手  
  
**关于JS**  
  
一个系统的js文件也要仔细看一看，前端有进行加密的话就要去逆向分析了（可以参考我之前的文章），像默认密码，初始密码格式就可能写在里面了，burp也有很多js敏感信息的插件，这里就不多说了  
  
关于接口信息，我很少用工具去跑，很多工具都比较慢，我都是手动收集的  
  
例如某智慧校园平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkHLoS11lkplmNww01dTUYibJuwq85Rm1kjq4yp937e0fM5rHRICWdAyg/640?wx_fmt=png&from=appmsg "")  
  
有很多js文件是需要登录才能加载出来的，这里直接全局搜下已经加载出来的js文件特征，可以找到全部的js文件了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkjLVN7JPQUoRx9hKIHQiclUqChg6JSHnwlooeFVt63FWYSj1UrZqyN2g/640?wx_fmt=png&from=appmsg "")  
  
简单修改下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkiakTEmPJOIXICZKszNDwibC921cQicJueUEcrnnLgFl2cdCPTicmLSVl1Q/640?wx_fmt=png&from=appmsg "")  
  
然后通过登录请求包的接口格式去全局搜索下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkiaiatTIkdNDgMAMPF2WOketS2G4Fg6Iib39R2ZnSbjShxc8xd7pVP8MzA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkpaD7b2gO92icpVxppSyicWzIFJBuLppOwXpKNQDJneo37PDpT0tkPRgg/640?wx_fmt=png&from=appmsg "")  
  
使用python解析所有的js文件，按照这个格式写个正则去批量爬取接口，然后放到burp里去测试  
  
有的接口可能直接返回了大量敏感信息，有的就需要参数，可能直接就在响应包里回显了需要具体哪个参数，如果只提示缺少参数，就去分析接口名字猜测需要电话还是什么，具体的就需要去分析前端的js文件了  
  
**公众号小程序**  
  
很多公众号里面也有一些系统可以测，多跑一跑目录之类的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPk62oZL3HO0vRicSUKJQ4FXQfwDFKTxhkR4wlHqUdkbwLCKZavwQllUNQ/640?wx_fmt=png&from=appmsg "")  
  
对于小程序我都是使用burp+Proxifier去进行抓包测试，教程：https://blog.51cto.com/u_13539934/8460648  
  
还有就是反编译小程序，然后使用微信开发者工具去分析，找一些接口、密钥、加密算法之类的信息，教程：https://www.cnblogs.com/Megasu/p/16501435.html  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64neGq57zmGSLM162PPellPkGdyASQ7vUzAf9zCt9Ev1YNIK69KPdbMbyXlMtv3ky985XyLibrpUdJA/640?wx_fmt=png&from=appmsg "")  
  
**注意事项**  
  
大家在测试的时候尽量不要开一些被动扫描之类的，如果对业务系统进行测试也不要去其他账号数据进行删除、修改等高危操作，插的xss也要记得删除，要保持良好的职业素养  
  
以上是一些大概思路，对于具体的漏洞挖掘、waf绕过那就要看自己的经验了，后续也会分享一些比较骚的手法  
  
****  
**交流群**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8ylMKoHJtGySCxBbQ8CGGica3FlC300D1koCCHKK5FwQHHWib63Ey3pHjRNWMIsic4QZlcEO8gVibwkI08wIveDoeg/640?wx_fmt=png&from=appmsg "")  
  

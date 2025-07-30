#  EDUSRC漏洞挖掘技巧汇总+信息收集各种姿势   
 sec0nd安全   2025-02-15 12:49  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
  
  
**0x1 前言**  
  
  
    
### 浅谈   
  
哈喽哇，师傅们！  
  
最近在挖教育类edudrc漏洞，然后最近在研究大学都有的站点功能——校园统一身份认证登录。这个站点每个学校的学生管理端基本上都有，然后每个系统的认证登录点也不一样，对于这几天的研究，然后也是成功先通过信息收集这个关键的步骤，然后再对校园统一身份认证登录点去进行一个认证登录的绕过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2PG8ZuuFNXzqnONR6lrlDnN93uZpchEdsFhvlKgnS4W7MvHezzTEf5A/640?wx_fmt=png "")  
  
             
  
             
  
**0x2 信息收集+资产收集**  
  
  
### 域名查询  
  
开始我先介绍下使用域名查询的方式，给师傅们演示下利用域名的一个信息收集和资产的收集过程  
  
就比如说下面的这个大学的站点，这个一看就是官网，首先我们看到的就是这个域名  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd20YQpocicEARcib6HS2XLLbCpibOKapryqyexjxKoSmv4lDTFdTQFn1ibGQ/640?wx_fmt=png "")  
  
             
  
然后我们使用这个域名进行一个信息收集，给师傅们分享一个信息泄露比较好用的一个站点：  
  
https://intelx.io/书签：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2Yu2frUeJCI63D5ymgag1rpuJkIHN5IiavZO3dEJH8iczl0XJPBdJkwAQ/640?wx_fmt=png "")  
  
             
     
  
我们直接把刚才要收集的edu站点域名之间放进去，然后进行相关资产的收集  
  
师傅们可以先看到下面的对于该大学的域名的一个图形化的收集数据如下，可以看到收集的还是蛮细节的  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2whqudShbv8RcN1kRChFuRpFWck6K7w687KR2PIBNnmhEFwu2Oaat4w/640?wx_fmt=png "")  
  
             
  
里面的相关泄露的信息需要师傅们自行去筛选，不一定都是正确的，因为这样的站点也都是通过一个一个数据进行爬取来的，作为一个信息收集的库，也就是只能碰运气了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2700EUiaDzd98PdZUiaFib5xdus8P1PrBrfmqnzGwpiaFbYFq4IEZ6h8CtQ/640?wx_fmt=png "")  
  
             
### 邮箱查询  
  
那么我们再在该大学的官网站点进行一个往下看到最下面，一般都会有这个大学的邮箱信息，那么邮箱信息也是可以可以打一波信息收集的了  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2ficFszQNkViaQkwLwPQiaYt7EdfH6ia0iaZYa2vBkAb1kibNnrtI6jeX5O7g/640?wx_fmt=png "")  
  
             
  
那么说到邮箱的信息收集，我就要掏出我的  
小狐狸头  
站点了，也是常用的一个针对于邮箱的资产收集的站点：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2IiattZGfPckFdXtibOnYszgZN8ibFobz5g01BSiaXPLfZX4q41L7sH9HOQ/640?wx_fmt=png "")  
  
  
然后我们之间把我们需要收集资产的该大学的邮箱丢进去，看课能不能收集到什么有价值的信息  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2FlMMtjS5VlUFUiauswljxibryeiaCqEGpb6aMRjKoZHqicrDrnHcRKURrw/640?wx_fmt=png "")  
  
       
  
一般来说 什么edu学校邮箱 或者某些HW行动 企业集团 这种查询邮箱效果比较理想  
  
比如其实有的时候 你查询某edu大学的邮箱的时候 ，其实你可以从  
邮箱都能找到学号和工号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2le0FJTAiba9ofOFpP6vLCibiag7MwkMRicxTpOX5y7uaTd55dWIWJVLXicA/640?wx_fmt=png "")  
  
             
### ICP备案信息查询  
  
还是按上面的一个思路，看到大学站点的最下面，ICP备案信息也是一个资产收集的一个重点，因为像这样的大学备案信息相对来说比较全，然后我们就可以利用比如说空间引擎啊进行一个检索  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2fjfOVcJKMQgkXBHonvt9ia9h1RBZrojpuuDcXLIHJKLxLz7GUHxY5Zw/640?wx_fmt=png "")  
  
             
     
  
比如使用常见的FOFA和鹰图这两款空间引擎进行一个ICP备案信息的一个检索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2ibmGljJOoANYPqdCvjkibJqImYOgHL69kSbszJD9biaIEz7eHvrcqcodg/640?wx_fmt=png "")  
  
             
            
  
可以看到下面利用FOFA的一个ICP备案信息的一个查询结果，可以看到查到了8条站点，然后还找到了两个icon图标，这些都是信息收集，都是可以记录下来的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd24PdNyBjibIia7H7AgOPrDZQxxVGRaNzqBoDadllxkPQVp0YAA0cGNRzA/640?wx_fmt=png "")  
  
   
  
可以看到下面的这个关键信息，这个学校的  
校园统一身份认证登录  
 的站点被我们找到了  
  
那么我们后面再利用鹰图进行一个检索，然后看看校园统一身份认证登录相关的信息  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2Hib9sx9aF9qZK4EwIeSCJweoNbcWQc7MYTRF6icDgVbbtGNiazdKIko0g/640?wx_fmt=png "")  
  
  
这里可以看到我这里也是找到了该学校的校园统一身份认证登录相关的信息，因为这次我主要是针对校园统一身份认证登录来打一个漏洞的，因为校园统一身份认证登录相关的信息很多的站点你要是通过信息收集到关键信息，是很好打一波逻辑缺陷漏洞的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2q8HMiby3a1fqQRzPuOLD7EVdBZGNwiafnViaJjKSlyZvJCKOcqiaj4lUrg/640?wx_fmt=png "")  
  
             
  
**0x3 综合资产查询姿势**  
  
  
### FOFA+鹰图  
  
刚才上面通过空间引擎FOFA和鹰图都查询到了  
校园统一身份认证登录  
站点，那么我们这里之间去访问这个站点，  
  
可以看到很常见的一个统一身份认证的一个界面的功能点，一般常见的就是利用学号/工号/或者身份证号之类的作为账户，然后再利用密码进行一个登录的操作  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd28KhLM7Yh0hXgwoqIcSOqspHBAUHO3t8ib8gfR92DnRLETNkviaaVDKgg/640?wx_fmt=png "")  
  
  
比如要进行统一身份认证的一个账号的收集，也就是常见的收集学号之类的，可以看看左边的这些系统，比如你可以去找下这样的web系统，然后可以看看在里面通过一些nday漏洞啊或者常见的弱口令登录管理员后台，然后拿到一些学号之类的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd25TO9KgO1EBkIqqJIPd5icvo75dBpMXBDwkucGVib6lokEK52xOOA7U9A/640?wx_fmt=png "")  
  
             
### 企查查/小蓝本  
  
这里给师傅们分享下使用企查查和小蓝本相关的操作，我们在平常对于某一个站点目标进行打点的时候，会经常碰到要收集该目标的相关资产或者说收集到的资产不全。那么我们就可以利用企查查和小蓝本的作用了，特别是里面的vip付费的模块，可以很大程度的帮我们快速找到对应的目标的相关资产。  
  
比如下面拿企查查查询某个资产，然后可以特别关注下面的知识产权  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2BmBXLr47whSy7ggia7oAUdEZU24qRWrLjVS8AIicibf5SdzsoERhUpicicQ/640?wx_fmt=png "")  
  
  
下面的域名收集起来，然后使用灯塔ARL或者oneforall子域名收割机去跑相关资产的子域名，然后进行去重，然后就可以收集到很多可以打点的资产了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd23HafaFLgqdibfVsXGLRgycoVGmfDwEUic7VycOJaFvNJLkPq8QfMeAkg/640?wx_fmt=png "")  
  
  
还有就是微信小程序的一个收集了，有些时候web端没有账号密码进不去，那么我们就可以尝试下在微信小程序进行一波打点，然后通过微信小程序的一个漏洞打点然后再到web端  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2QGHpHDia5qMKAmo2ic3reu4m86r67icr0zyLMxzejROhpaTniaIxeBU9cQ/640?wx_fmt=png "")  
  
  
力推  
小蓝本  
可以直接新媒体 能查到公司旗下有哪些公众号小程序或者APP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2JUP7yyqATscZnffAsHDYSZzJKhIcuDG3AbQeWM1BrA3cRMbGD2d9WQ/640?wx_fmt=png "")  
  
   
  
下面推荐一下狼组大佬的爬虫工具，专门针对于企查查和小蓝本的一些付费功能的信息  
  
基于各大API的一款企业信息查询工具，为了更快速的获取企业的信息，省去收集的麻烦过程，web端于plat平台上线  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2VkCn25MSsm809oSoB4O9uxQ71ZZuiauedpJVgG7W0gs0vTr9dfXymbQ/640?wx_fmt=png "")  
  
  
python ENScan  
.  
py   
-  
k keyword  
.  
txt            
  
            
  
//  
keyword  
.  
txt里面填企业名称  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2mXY9fUZvYvKEtNWPsdkwGQTZ9MeekEicFWxC32Uw6FdzjqmBVM4Cg9Q/640?wx_fmt=png "")  
  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2eGr5uxsVP2dUnqNLGurdqysl2ekSGR5VKrFbK68FLuPW5eicm00YicrQ/640?wx_fmt=png "")  
  
             
### Google黑客语法  
  
收到信息收集和资产收集怎么可能少的了Google浏览器呢，Google浏览器的黑客语法是一个十分强大的存在，特别是在以前网络方面管的不是很严控的时候，很多大牛都是使用一些厉害的Google语法进行一个资产的收集，在以前学校的一些  
身份证  
和  
学号  
信息经常能够利用这些语法找到的。  
  
下面我也简单的给师傅们整理了下一些常见的一些  
Google检索的语法  
，如下：  
  
1  
.  
site  
:  
域名 intext  
:  
管理  
|  
后 台  
|  
登陆  
|  
用户名  
|  
密码  
|  
验证码  
|  
系统  
|  
帐号  
|  
manage  
|  
admin  
|  
login  
|  
system            
  
            
  
2  
.  
site  
:  
域名 inurl  
:  
login  
|  
admin  
|  
manage  
|  
manager  
|  
admin_login  
|  
login_admin  
|  
system            
  
            
  
3  
.  
site  
:  
域名 intext  
:  
"手册"  
            
  
            
  
4  
.  
site  
:  
域名 intext  
:  
"忘记密码"  
            
  
            
  
5  
.  
site  
:  
域名 intext  
:  
"工号"  
            
  
            
  
6  
.  
site  
:  
域名 intext  
:  
"优秀员工"  
            
  
            
  
7  
.  
site  
:  
域名 intext  
:  
"身份证号码"  
            
  
            
  
8  
.  
site  
:  
域名 intext  
:  
"手机号"  
  
1  
.  
site  
:  
域名 intext  
:  
管理  
|  
后 台  
|  
登陆  
|  
用户名  
|  
密码  
|  
验证码  
|  
系统  
|  
帐号  
|  
manage  
|  
admin  
|  
login  
|  
system   
2  
.  
site  
:  
域名 inurl  
:  
login  
|  
admin  
|  
manage  
|  
manager  
|  
admin_login  
|  
login_admin  
|  
system   
3  
.  
site  
:  
域名 intext  
:  
"手册"  
  
4  
.  
site  
:  
域名 intext  
:  
"忘记密码"  
  
5  
.  
site  
:  
域名 intext  
:  
"工号"  
  
6  
.  
site  
:  
域名 intext  
:  
"优秀员工"  
  
7  
.  
site  
:  
域名 intext  
:  
"身份证号码"  
  
8  
.  
site  
:  
域名 intext  
:  
"手机号"  
  
      
            
  
             
        
  
然后还有就是使用厉害师傅手写的工具，你把你想检索的关键字放进去，然后这个工具给你相关信息搜集的Google语法，比如下面的这个工具比较喜欢，感兴趣的师傅们可以去github上下载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2RUMjf7bUwj4KWobftxO6sYbyBXyRRLmJRGNkrGQiaIEP0Cqictb2hBdw/640?wx_fmt=png "")  
  
  
下面就分享下之前我利用这个Google黑客语法工具拿下的一个大学的统一身份认证管理后台，当时也是尝试了很多的学校，然后进行挨个语法检索，然后再在浏览器中去进行信息检索，然后也是找到了该站点的身份证以及学号，后面也是成功登录了后台  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2fvkiahbzloRGcDtMqCoVAePaMTRLFmibKz551prp2f3VSAy7RXJQUERw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2v4AqCsq5AiaCaN0fia8BaViaMUrkPmYyxRSzbH2o6OKIvgWV0MhqkhBcQ/640?wx_fmt=png "")  
  
  
下面是成功登录该学校后台站点的页面  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2Hbj4GJP3acoBXlMjLTFEG2UWaLMepKjKFRvicj9IOz5X4PXZUSQh4Xg/640?wx_fmt=png "")  
  
             
  
**0x4 统一身份登录绕过**  
  
  
### 逻辑缺陷绕过  
  
还是以刚才最开始进行资产收集的那个大学站点，然后也是开始进行资产的收集然后后面通过FOFA和鹰图找到了比较多的站点的信息，然后找到了一个实验室的一个后台站点，刚好那个站点使用弱口令admin:123456直接登录了进去  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2RkH9Z7JGhVp5stiaMlo5m4WfNGYXVg8n7XIAKvkXtiaoqo8lbnicQeLMw/640?wx_fmt=png "")  
  
       
  
然后里面有一个导出数据的功能，然后也是可以看到该实验课的所有学生和老师的姓名、学号、班级信息，信息泄露严重，可以看到下面的数据总共有好几千个学生和老师的信息都出现了  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2bzY0LfCw67supbGbAciaTCzibiaNt32YQUzmO93fhLlvrWBibbicBzDlxmQ/640?wx_fmt=png "")  
  
  
上面的就是我在进行信息收集的时候收集到的该学校的部分学生的学号信息，你像要是在打edu的时候，获取到了该学校的学号以及身份证之类的敏感的信息，都可以去找找该学校的统一身份认证管理后台，然后看看他的这个登录机制有没有可以绕过的功能点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd28KhLM7Yh0hXgwoqIcSOqspHBAUHO3t8ib8gfR92DnRLETNkviaaVDKgg/640?wx_fmt=png "")  
  
     
  
下面我们首先看，这个统一身份认证的登录时要我们输入学号和密码，我们这里知道学号，然后密码的话，我们是不知道的，但是我们可以尝试使用bp进行一个弱口令123456的爆破，看看能不能出一个弱口令的账号密码，然后进行一个登录后台的操作  
  
可以看到利用bp抓取数据包，且账号密码都是以明文的形式输入，所以可以尝试爆破的方法  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2tZVmkZhpiaG8eJtGtA1ow5JZpTVcBZMGNcwk07RLFPCwqNzhicFG1WYg/640?wx_fmt=png "")  
  
  
爆破没有成功，应该是要求改强密码了，不过没有关系，这个也是一个思路，主要是想给师傅们分享下一个在拿到账号的情况下，可以去尝试的操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2PAHhPiaBvL9Uoyge8KjicPR4QrDs1oRAGNaRDB5K9je5kWxUmPsXOw8w/640?wx_fmt=png "")  
  
  
1、首先我们点击下面的忘记密码  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2fiaPHWm5CtCh4ibiaIwM9tcnkJspEJ8OYfJJDXgibRA6nBWlOia9TsqP76g/640?wx_fmt=png "")  
  
            
  
             
  
2、一看可以找回密码，且要我们输入账号，账户就是我们开始收集到的学号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2w36kUjyxQpyYJiazrX5ByBpUMEjeiaOnUwEEriaibXkxyZRSoIZOBJicJSw/640?wx_fmt=png "")  
  
             
  
3、然后就到了这一步，师傅们一看是要接收手机号，那么一般就在想着应该没戏了，其实不是的，像这样的站点，其实可以去抓它的数据包，然后看数据包进行一个尝试逻辑绕过  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2PwKKUmKQicvYtsSX9fcveBO1SHibMibceAtlfSjJQxnWfCf5sFVJFE9Aw/640?wx_fmt=png "")  
  
             
   
  
4、通过bp抓包，然后进行数据包分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2AqCjITqK4flmKeSkXic5iaIyRUVXeWjn9gltMP2WtibnLfVLl8ibevzHRg/640?wx_fmt=png "")  
  
   
          
  
             
  
5、这里直接右击看看返回包，然后通过返回包看看这个是通过什么方式进行的前端校验  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2vp4hBBPB71eKa6KFkNR5ibhjFMoYlewhLNoQ6iaLJrNxvgCW2YmRgu6g/640?wx_fmt=png "")  
  
     
  
然后进行分析这个返回包，师傅们可以看到这里可以判断下这个前端是通过下面的返回包的哪个字段进行的校验  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2uaXA0lIxmYh1pYKXhkdJHCTYGv9uC7L9cvRTCrr1eBiaR1xo7PXco1Q/640?wx_fmt=png "")  
  
  
一般就是code和这个false错误进行的一个前端校验，那么我们就可以挨个尝试下  
  
后来把false改成true后，然后再放包，就直接绕过手机验证码了  
      
  
{  
"code"  
:  
"B0000004","data"  
:  
{},  
"flag"  
:  
true,"msg"  
:  
"您输入的手机验证码错误","rows"  
:  
[]}  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2N4PdKtbAkmPaUhCcK1ezibbISJ6TUjj0ER6KmNUKicZeJAVicmaq9TGFQ/640?wx_fmt=png "")  
  
到此为止，我们就成功的绕过了改身份认证登录后台的修改密码的验证了，主要还是开始先收集到的学号信息，然后再进行一个前端绕过的一个判断  
  
             
### 二、爆破账户/前端绕过验证  
### 下面这个站点也是之前遇到的，改站点登录也没如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2vJjySP14rF5kias9zT8NjgOkVKKNM5hPZia9MGrZOTmymrHcT0gVBDfw/640?wx_fmt=png "")  
  
  
1、老样子，跟上面的一样，这里直接点击忘记密码，然后看看后面的验证机制是什么，然后再看看可以通过什么方式进行一个前端的绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2wJvzMjam4VkcEbSU8yg9xfdvRxO3XKQZBQbe5KmKfDGMNaXZ0LSb6Q/640?wx_fmt=png "")  
  
  
2、然后点击这个里面的用户名验证  
  
然后可以看到下面的验证机制，是验证用户名，那么我们就可以尝试一个用户名的爆破了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2KpXpnGmicTibnUuMe6Gk7rnCoKeFUicgCmmc54G4USHrK0OgjrogjTiaCg/640?wx_fmt=png "")  
  
  
3、输入用户名test点击下一步并抓包，可以看到msg字段返回1  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2Evy9por6swB9HZTPNE9RKW9Ib9kwMs7ZiaB0RdemXo7vvaVibOzbhXng/640?wx_fmt=png "")  
  
  
然后再看看test666，看到msg字段返回0，那么通过判断发现返回0就是用户名不存在，返回1就是表示用户名存在，那么我们就可以是要常见的用户名字段去爆破  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2Ezz3GmeJic77tVyu0uoGS5a4rzNBEibSic8nHFPaJicwPgAPPBrYWtDmCA/640?wx_fmt=png "")  
  
  
4、爆破用户名，可以看到爆破成功了很多用户名，最后使用一个  
108万姓名全小写  
的这个字段爆破了很久，然后爆破出来了好几千个用户  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2X1nbvibZ0NU1kJ6NAxvqAOgq9sP9Z0eiaHjKX7MX5MxABWgfxXWpm2jg/640?wx_fmt=png "")  
  
             
  
             
  
5、拿上面的用户去演示下绕过的过程  
  
然后直接这个也是跟上面的站点一样，使用手机号验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2WFLhhGlB0pRmhhBibqnY9xYL0b2POv3SHhLmWhQIDQibV0ic7ofkXSolA/640?wx_fmt=png "")  
  
             
  
             
  
6、这里抓包，然后看这个数据包的返回包，然后进行判断一个前端绕过  
  
可以看到这个又是一个msg参数的前端验证，那么下面就是尝试一个msg的修改，然后看看当修改为什么的时候可以进行一个前端绕过  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2D6IibqxZfrxm6UHsmD4ZagvofLcg12S1Un0nbk98ickA9d3shFlwbuKg/640?wx_fmt=png "")  
  
             
  
这里后来通过判断msg修改成2，然后就可以成功绕过前端验证码的验证直接绕过了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2pJYfDX9KLYedjIGdfJjibpiamPWlyP990gZCES9p93fib5tZWzc9pK3aQ/640?wx_fmt=png "")  
  
  
**0x5 总结**  
  
  
### 浅谈  
### 这篇文章很详细的给师傅们总结和演示了统一身份认证的一个绕过的过程以及这个思路，先是给师傅们很详细的介绍了各种对于一个目标资产的一个收集，然后再到下面的利用这个收集到的资产信息去打一个怎么样的漏洞，收集的信息越多，对于我们后面的打点渗透测试工作就会越轻松。  
  
  
下面给师傅们分享了两个真实网站的大学案例的绕过过程，像这样的站点，尤其是Java开发的站点，都可以利用这样的姿势去尝试绕过，可以说这样的技巧都是通杀的，只不过前提得看你的信息收集能力了，你得收集足够多的资产然后再去一个统一身份认证的登录后台去进行一个逻辑缺陷的一个绕过。  
  
  
**0x6 工具资料**  
  
  
###   
  
下面几个工具都可以扫描开头的二维码，加我微信，免费私发给师傅们！  
  
一、Google黑客语法：  
  
二、常用用户名字典：  
  
  
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
  
神农安全团队创建的知识星球一直从未涨价，永久价格40  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfdoYZ7FZXSES8r9QFcDXjpbIibhYUVEuvibILfCP7TkwhCLQoawUxv7RNcEfbuIPKKs8pHw7tYJNQ/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满300人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
****  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXfdoYZ7FZXSES8r9QFcDXjP3ZF0lU2nKHTIUqLbA2LYMFryx9ibkicj2eLJ1LwiaxnXkibgS2UNeqZmg/640?wx_fmt=png&from=appmsg "")  
  
****  
    
```
```  
  
  
  

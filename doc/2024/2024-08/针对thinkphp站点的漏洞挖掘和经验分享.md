#  针对thinkphp站点的漏洞挖掘和经验分享   
98k  掌控安全EDU   2024-08-10 12:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  98k 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
## 0x1 前言  
### 浅谈  
  
目前在学习和研究thinkphp相关漏洞的打法，然后最近对于thinkphp资产的收集方面有了一个简单的认识，然后写一篇新手看的thinkphp相关的漏洞收集和挖掘的文章来分享下。然后后面是给师傅们分享下后台文件上传，然后直接打一个getshell的漏洞点。  
## 0x2 thinkphp漏洞简介  
### thinkphp简介  
  
ThinkPHP是一个快速、兼容而且简单的轻量级国产PHP开发框架，遵循Apache 2开源协议发布，使用面向对象的开发结构和MVC模式，融合了Struts的思想和TagLib（标签库）、RoR的ORM映射和ActiveRecord模式。  
  
ThinkPHP可以支持windows/Unix/Linux等服务器环境，正式版需要PHP 5.0以上版本，支持MySql、PgSQL、Sqlite多种数据库以及PDO扩展。  
  
其中thinkphp 搭建网站常见完后，十分熟悉的thinkphp 架构的页面如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGAia9LpXlBQF6TqAWYddb5saOJaVOgZMOWYT7ZB9WZ6icyvBP8XowvXIA/640?wx_fmt=png&from=appmsg "")  
## 0x3 资产收集篇  
#### FOFA空间引擎  
  
那下面我就来给师傅们分享下我进行thinkphp 站点的信息收集，我主要是使用空间引擎，比如常见的FOFA和鹰图进行资产测绘，然后进行目标资产的筛选，然后进行一波漏洞的测试。  
  
FOFA语句如下：  
```
body="thinkphp" &amp;&amp; title="后台管理"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGNRn6H9gl1suZ3r1w54crVqacTbtVHEld0LCXJ6JLhT7fa1XaDCdl7g/640?wx_fmt=png&from=appmsg "")  
  
然后可以看到下面的icon图标特别多，一般像这样的你要是打出一个漏洞，后面很有可能能够打出一个通杀出来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGxtmyn5VaSVjia4GeLh5bMLibFyaia4pe31nQSwFvmQDGJkc0nwLbsibCDA/640?wx_fmt=png&from=appmsg "")  
  
然后可以看到下面也是有五千多条的资产可以让我们去打，资产也算蛮多的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYG8loUsuFhoBgWtCFxPMibVKA94FSKpKX0fDaIaS8Ce55j7Ibzy2QV3bQ/640?wx_fmt=png&from=appmsg "")  
  
然后还可以就是直接使用thinkphp 的图标，如下图保存到本地然后进行icon图标检索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGjwfwm0q1smCQcspaLSqypoZTsvU8TZjIvmibM3roFDFUkS9hMS3YicUA/640?wx_fmt=png&from=appmsg "")  
  
可以看到这样检索匹配出来的资产也都蛮多的，而且匹配出来的都是thinkphp 的站点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGcOdjKs1rLgibK4UcNdyJ19t2kqUyVqJI746fxUx5cBNnhXrICMz8Lcw/640?wx_fmt=png&from=appmsg "")  
## 0x4 工具篇  
#### Thinkphp(GUI)漏洞利用工具  
  
ThinkPHPGUI的工具下载链接如下，github上有蛮多的相关工具，但是都差不多  
  
Thinkphp(GUI)漏洞利用工具，支持各版本TP漏洞检测，命令执行，getshell  
  
https://github.com/Lotus6/ThinkphpGUI  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGiaicJC2zew3PS4IsZT5NSYU3CrjWjU3btE62V2rhUn2ZUQjeDCoweTicw/640?wx_fmt=png&from=appmsg "")  
  
工具的使用很简单，主要是靠这个工具武器库里面的poc检测，然后利用ThinkPHP工具去打一波nday漏洞，可以看到下面直接使用该工具进行poc检测，然后可以检测出ThinkPHP相关版本的漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGKvcV0hIMltYjxfDSZVvmb7BTibhDjCia77iaPs89iamnlnv2q83KCYTWUw/640?wx_fmt=png&from=appmsg "")  
  
然后可以使用Google浏览器进行检索这个漏洞 的打法，然后打一个nday  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGmODZjnORojEvPyVnRUNFVhuibicPE5hS28Yd9828jMpOBrDjn7vCmS3g/640?wx_fmt=png&from=appmsg "")  
## 0x5 渗透测试  
#### 漏洞一：弱口令登录  
  
然后就是先按照我上面的方法，比如使用FOFA找Thinkphp 相关资产的站点，然后利用工具去扫描，看看有没有nday  
  
要是没扫出来，我开始不是都是检索管理后台 的关键字嘛，都是登录后台的站点，那么我们是不是就可以尝试下弱口令登录呢，然后再在里面测试，扩大这个rank危害值。  
  
下面是我收集的Thinkphp 站点常见的弱口令如下，需要的师傅可以尝试下  
```
sysadmin:sysadmin123
admin:admin
admin:admin123
admin:123456
admin:admin@123
admin:1qaz@WSX
test:test
```  
  
还有就是很常见的右下角的Thinkphp 的站点的图标，师傅们可以记录下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYG3M1Fr7hXr692yb4bOQ3lGUhCJegibrykA7dQbWicibeJF11oibLHwhm9ibw/640?wx_fmt=png&from=appmsg "")  
  
这里直接使用弱口令admin:admin成功登录进来了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGU2dhx3nYHIoQC2X1uL5OwUVXUl86GuZTMvdfnQc3FFf6QvKa8Eq4Pw/640?wx_fmt=png&from=appmsg "")  
#### 漏洞二：存储型XSS漏洞  
  
下面看到该站点存在查询接口，一般看到这样的，很常见的手法就是测一个sql注入，先尝试一个手工注入吧，在bp里面测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGpEGjMQic0Qib5LJtLjNW12ibj5nLHodXajKwMKF8cIf5EyDjlUibJgSFrg/640?wx_fmt=png&from=appmsg "")  
  
然后还可以用下面的测试一个时间盲注  
```
sql注入判断
1' and if(1,sleep(5),3)--+
1" and if(1,sleep(5),3)--+
1) and if(1,sleep(5),3)--+
1 and if(1,sleep(5),3)--+
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGSia4YcCeIsaxDO7abMJBGSHypXLZYQRklm3c52djn5lQ8ic0TBVXZswA/640?wx_fmt=png&from=appmsg "")  
  
然后下面有一个添加的功能，里面出现输入框，这就可以测下XSS漏洞了  
  
然后在下面的输入框中都输入简单的XSS弹窗语句  
```
<script>alert(XSS)</script>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGC6ZiaAGP6ehS4rDvNnlH2Ebo63TRe6rJvHdzLOziaqsdNLFIGBL6up1w/640?wx_fmt=png&from=appmsg "")  
  
然后保存下来，直接就一直在弹窗，这个站点没有对输入的内容进行过滤和验证，直接可以打XSS漏洞，且是存储型，还会影响别的用户，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGXXjTlqJx0jI22kp3BKlndzaI1WtORNdnXVymbA3u4LkJlLMUjaDT4w/640?wx_fmt=png&from=appmsg "")  
#### 漏洞三：文件上传getshell  
  
进来以后，我这里直接使用findsomething插件小熊猫头，看看有没有什么铭感的接口信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGnsJsrbnnADmN4s3XZRZic6Elvnfjbq4qtOw5icmIBLSVIYY7E6x6jdLA/640?wx_fmt=png&from=appmsg "")  
  
师傅们可以看到下面的议题列表中的添加功能，然后这里存在文件上传的功能点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYG5EpzMoAbRTP2yjFVNcgdsxiaMLlCXxSB3U0Z9ou3zm0Uq70ZBjiaBEPQ/640?wx_fmt=png&from=appmsg "")  
  
下面来试试这里文件上传，随便上传一个图片上去，然后利用bp抓包看看里面的数据包这里我只是点击选择文件，没有点击下面的绿色提交按钮，但是看数据包可以发现已经上传成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGpBeaGibjfNwdnn6aqWNJ9ktXxoArsEYzmYxjD9WNCFDbRHe4kxoPrjA/640?wx_fmt=png&from=appmsg "")  
  
我们访问下这个图片上传成功的路径，看看是不是真的上传成功了访问返回包的路径，可以看到确实上传图片成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGVeGNyIGRfr3fCtez0OibJc2dS7I4O8ib8RFLSdKyuiavXNgHicggTvsq6Q/640?wx_fmt=png&from=appmsg "")  
  
删掉后面的图片名称，然后看看能不能打一个目录遍历漏洞但是这里没有成功，返回403权限拒绝访问，说明存在这个目录，但是没有权限，也算是一个思路了吧  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGXAYANTsO4wZoY9P5RXslt3Fg1L5hpTzIbZWvzBND40ic2RKpCUWNGOQ/640?wx_fmt=png&from=appmsg "")  
  
通过几次数据包的抓取，分析发现这个站点的上传文件的方式没有任何的过滤方式，应该可以直接上传恶意文件，然后getshell一波。  
  
使用wappalyzer插件，可以看到这个站点是使用php搭建的，那么就可以上传php木马上去，然后打一波phpinfo()了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGXnMUU9sLZufgJ4lIQ0x2AkHvAZu0HTJhBkCrhHFvI2icMcBAy1F2icwQ/640?wx_fmt=png&from=appmsg "")  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYG4DThUibibk1pouPARPp9ZC4ibib4Ic3XD3CzVyppcU5wQFGr8lzQeHLylg/640?wx_fmt=png&from=appmsg "")  
  
然后再直接访问这个地址，可以看到直接打出来了一个phpinfo()的页面后面要是上传木马，然后getshell也是可以的，但是这是测试，没必要上传木马，直接证明危害即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcqh4wMWDicicib1drLK1dw0JYGP3EvmxzscFcDb3kWC1OgprPhDic3zetMgAv4DicSBD9hx9YcPQHMlfOg/640?wx_fmt=png&from=appmsg "")  
```
```  
  
  

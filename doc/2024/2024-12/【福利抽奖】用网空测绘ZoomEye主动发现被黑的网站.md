#  【福利抽奖】用网空测绘ZoomEye主动发现被黑的网站   
原创 pbuff07  增益安全   2024-12-02 10:34  
  
ZoomEye用来干啥的不多说了，没听过没见过的直接点下方链接学习下～  
  
[如何用ZoomEye助力小白挖到第一个漏洞](https://mp.weixin.qq.com/s?__biz=MzI3ODk3ODE2OA==&mid=2247484285&idx=1&sn=3aaac48d48a2e19a2a202642feee0607&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARA1CNUQ1WQmMg7HLyOkYWtaZQ7HLACNZibFlJYbKaI7TZF5ZUUzwQKmicJMg3raHkU29WvnzlC42F6w/640?wx_fmt=png&from=appmsg "")  
  
  
除了可以用来发现资产、找漏洞外，还可以主动监控全网哪些网站被黑了，对于甲方或者监管可以快速监控和响应，下面介绍几个办法（也是目前我所采用的方式）。  
  
1、使用被黑的关键字  
  
黑客黑掉某个网页后多多少少会留下一些提示信息，比如"hacked by"、"xxxx黑客，联系QQ"之类的。  
  
通过搜索http.body="hacked by"，大约有9.7K的网站源代码中包含该关键词，也就说有这么多网站被黑了，  
中国还是挺多的仅次于美国。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARA1CNUQ1WQmMg7HLyOkYWta6dicFRcycAMoFIOhZldSZjb92hsJA75I8LcupHBxPoXvSOWOdEsVicyQ/640?wx_fmt=png&from=appmsg "")  
  
https://www.zoomeye.org/v2/searchResult/report?q=aHR0cC5ib2R5PSJoYWNrZWQgYnki  
  
随便打开几个看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARA1CNUQ1WQmMg7HLyOkYWtawK8vKMN9nKmgTywxc4havnXvUiashy1J7hGnIs6b5zReeK0RSZ9CQaA/640?wx_fmt=png&from=appmsg "")  
  
人还挺好，Webshell地址都给你了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARA1CNUQ1WQmMg7HLyOkYWtaVyBEnsVPT0mvCekmDcfHY9pCfoVVv6lwrdYN8D0KokqvwdMKfrtlpg/640?wx_fmt=png&from=appmsg "")  
  
用API写个监控轮询关键词查询数据并判断下是不是自家资产就可以实现实时预警了，不会写后台圈我，我免费教你写。  
  
2、搜索一些Webshell的名称或者特征  
  
有些黑客会利用Gayhub公开的的一些Webshell进行攻击，不排除没有修改名字直接上传的。  
  
比如搜索：http.body=">wso.php</a>"，有43多个站点被黑，网站被植入了wso.php木马文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARA1CNUQ1WQmMg7HLyOkYWtaCXQyVC7yVSKCmsY0KHZ2ic9Gl5P5FfAtYmA3DdfVnZfVaReVaF7MZXA/640?wx_fmt=png&from=appmsg "")  
  
https://www.zoomeye.org/v2/searchResult?q=aHR0cC5ib2R5PSI%2Bd3NvLnBocDwvYT4i  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARA1CNUQ1WQmMg7HLyOkYWtav141cjOyFlS8eicwiblguj24Vrb3F9x517ZGS7fv8aD3uKSbPsqW09Rw/640?wx_fmt=png&from=appmsg "")  
  
Gayhub搜webshell可以搜到很多乱七八糟的Webshell，拿到ZoomEye去搜就行了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARA1CNUQ1WQmMg7HLyOkYWtaCRnjy94ctA3kiaRtibibqXJdXsbibiblib9FqKCrPbRs5w3FQIcBFAd3zu9Q/640?wx_fmt=png&from=appmsg "")  
  
wso.php是一个Webshell木马文件，Gayhub一搜就有很多  
  
搜集多点Webshell的名称，在ZoomEye多搜搜能发现很多被黑的站点，和上面一样写个脚本轮询监控就行，不过这种方式查出来的数据不那么准确，可能还要进一步用“人工”智能审查一下是不是到底被黑了。  
  
PS：  
甲方让马喽看、监管让乙方看，乙方有自己的牛马看。  
  
3、供应链攻击  
  
前段时间听说xxx前端大量使用的一个js三方库域名过期了被黑产抢注了，导致使用了这个库的网站访问就会加载一些“奇奇怪怪”的东西或者直接跳转到黑产的赌博、色情页面等。  
  
这类事情的核心是网站前端中过分信任某些三方库，直接用<script>标签引用外部链接，一旦这些三方库出现任何问题，这些网站都跟着遭殃，俗称供应链打击。  
  
举个例子：你有一个网站，你想给你的网站添加一些前端功能，然后照着网上的一些教程用<script>标签直接引入了一个用得挺多三方库。（  
PS：这么多人用质量应该没问题吧？）  
```
<script src="https://cdn.xxxx.net/3.0.83/shCore.min.js"></script>
```  
  
突然有一天，  
https://cdn.xxxx.net被恶意的人控制了，往  
shCore.min.js代码中注入了一些“黑客”内容（恶意跳转、弹窗、窃取数据等）。即使你的网站很安全，但是由于你引入了有恶意内容的三方链接用户访问会自动加载，变向等于你的站点被黑客控制了。  
  
这不是开玩笑，2023年的时候BootCDN就遭遇过投毒，至于影响了多少网站直接看下面ZoomEye测绘数据吧。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARA1CNUQ1WQmMg7HLyOkYWtae2glpY8AzE4WIEn2HS1LiaEGqLfhkP1dzb6Z2qcoRgrM8w5IbbniaaOQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARA1CNUQ1WQmMg7HLyOkYWta2cazutA3euhwtMZQAUw9DGgrGGWPfxrsvGC1vxZlEQicTU9cqFTc7sA/640?wx_fmt=png&from=appmsg "")  
  
对这类被黑事件的监控没法立刻看到效果，只有不断收集供应链应用的特征并持续监控，才能在出现安全问题的时候立刻响应。换个方向思考，这何尝不是一种收敛攻击面的方法呢？  
  
欢迎和我探讨更多内容！  
  
凡是关注了“增益安全”的粉丝可点击下方链接免费参与抽奖，奖品是ZoomEye鼠标垫一张（大）。  
  
  

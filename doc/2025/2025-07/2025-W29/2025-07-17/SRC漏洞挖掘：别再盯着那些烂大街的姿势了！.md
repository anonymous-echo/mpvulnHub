> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU3MjczNzA1Ng==&mid=2247498061&idx=2&sn=ffc32316ce8cf9e9c0f235a248e8bcee

#  SRC漏洞挖掘：别再盯着那些烂大街的姿势了！  
龙哥网络安全  龙哥网络安全   2025-07-17 02:31  
  
**0x1 开场白：SRC挖洞，菜鸟的春天在哪儿？**  
  
别跟我说你还在死磕SQL注入、XSS那一套！大佬们早就把肉啃完了，汤都没给你剩。想在SRC或者渗透测试里混口饭吃，光靠教科书上的招式，怕是连门都摸不着。这篇文章，咱不讲高深的理论，就聊聊那些容易被忽略，但小白也能轻松上手的“冷门”漏洞。当然，别指望一招鲜吃遍天，但至少能让你在SRC的道路上，不至于空手而归。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7RibaKKSdIibYZa62SNM7QavweAibFNHLrcHlhE3mjRicz2nQGPJ9U84JNQ/640?wx_fmt=jpeg "")  
  
记住，别把鸡蛋放在一个篮子里！大佬们吃肉，咱们就喝汤，搞点中低危漏洞，积少成多，也是一笔可观的收入！以下内容，是我和几个“身经百战”的老司机交流后总结出来的，绝对干货，拿走不谢！  
  
**0x2 邮件伪造：被忽视的社工利器？**  
### 一、SPF：一道形同虚设的防线？  
  
SPF记录，这玩意儿说白了，就是告诉邮件服务器，哪些家伙有权以你的域名发邮件。但现实是，很多企业压根儿没配置，或者配置不当，这就给了我们可乘之机。  
  
**划重点：**  
 如果你发现目标域名压根儿没设置SPF，或者SPF记录配置有问题，那恭喜你，可能发现了一个高危漏洞！  
### 二、能干啥？不就是发邮件嘛！  
  
别小看这玩意儿，想象一下，伪造一封来自
```
HR@target.com
```

  
的钓鱼邮件，内容劲爆一点，比如“你被裁员了”，或者“年终奖翻倍”，哪个员工能顶得住？社工的威力，远比你想象的要大！  
  
虽然SRC可能给的钱不多，但渗透测试项目里，这绝对是个加分项。  
  
**记住：**  
 没
```
v=spf1
```

  
或者没
```
spf
```

  
，邮件伪造漏洞跑不了！
```
~all
```

  
能伪造，
```
-all
```

  
就歇菜。  
### 三、实战：Kali在手，天下我有！  
  
先拿
```
baidu.com
```

  
开刀试试水：  

```
nslookup -type=txt baidu.com 
```

  
或者  

```
dig -t txt baidu.com 
```

  
如果看到
```
-all
```

  
，说明百度安全意识还可以，咱们换一家。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK706OWg1qonZoicEmuRUmgd04c074fT95e9XClOGdvS2NmJ3ngibMkWSAA/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7icJ66tjibEDRRNlmS0TjDWlpd83tJFQb1NcPJJGDI1OzhpU5mOsoNU4g/640?wx_fmt=jpeg "")  
### 四、SPF解析错误？天上掉馅饼！  
  
复制SPF配置记录，扔到这个网站检测：https://www.kitterman.com/spf/validate.html  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK79M6xnfFKk4eQrxZPOicHSW55KIVsicXqV3LA1EiaEL3icQuvNfRibUTuNIg/640?wx_fmt=jpeg "")  
  
如果提示“spf解析配置正确”，那就没办法了。但如果报错，比如下面这个：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7ZWq8LjMCTuX9Ie8yYDxUPySeTdsylkIsxfdtWTjb9iaich3B5Exe5MicA/640?wx_fmt=jpeg "")  
  
多个IP段，只有开头用了ipv4，语法错误！整个SPF记录直接失效！  
### 五、Swaks出击，邮件轰炸！  
  
Kali自带的
```
swaks
```

  
，伪造邮件的神器！  

```
swaks --body &#34;helloword&#34; --header &#34;Subject:testT&#34; -t 你的邮箱 -f test@baidu.com 
```

- 
```
body
```

  
：邮件内容  
  
- 
```
Subject
```

  
：邮件标题  
  
- 
```
-t
```

  
：目标邮箱  
  
- 
```
-f
```

  
：伪造的发件人  
  
**注意：**  
 伪造的发件人别太离谱，否则直接进垃圾箱。  
  
先搞个临时邮箱：http://24mail.chacuo.net/  
  
然后开搞！  

```
swaks --body &#34;【2024年8月1日】 检测到您教务系统长时间未修改密码，请及时修改密码确保账户安全 手机管家@163.com 【该邮件自动监测请勿回复】&#34; --header &#34;Subject:vivo&#34; -t vioxzs43016@chacuo.net -f customers@alexz.com 
```

  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7WrYFVPOqQttMVibQ8WaT0iaJqnIYdHEa56zlV3aic30TIjhDwZykaZpgA/640?wx_fmt=jpeg "")  
  
如果标题和内容再走心一点，钓鱼成功率绝对up！  
### 六、总结：SPF，邮件安全的阿喀琉斯之踵！  
  
SPF配置不当，等于给黑客开了后门。绕过策略就藏在SPF记录里，就看你能不能发现了！  
  
**0x3 Sourcemap泄露：前端代码任你扒？**  
### 一、什么是Sourcemap？JS代码的“裸奔”？  
  
如果你在网站上看到
```
.js.map
```

  
结尾的文件，那就要小心了！这玩意儿是Webpack打包的副产品，有了它，你可以把压缩混淆后的JS代码，还原成原始代码！  
  
这就像扒了JS的衣服，API接口、敏感信息，一览无余！  
### 二、Shuji：一键还原，简单粗暴！  

```
npm install --global shuji 
```


```
shuji app.js.map -o desfile 
```

  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7XrmMEzzS2dD9YwczpudcWFkhvfa4AVXPx3D3WVWPL3Zoqn20icNLqow/640?wx_fmt=jpeg "")  
  
还原后的代码，慢慢分析吧！说不定能找到未授权访问漏洞！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK72z5qp2mUBIibUceIAa4p6DI9fUibjVD6S4h1gEGY5AAYu0tsgOvvG3Bw/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7Zm8pyAAzCHgmMqCXdaNdHLQd7oicANMOPcTbWvnoqR9w3hYIv7GSpnQ/640?wx_fmt=jpeg "")  
### 三、油猴脚本：自动搜索，懒人必备！  
  
https://greasyfork.org/zh-CN/scripts/447335-sourcemap-searcher  
  
装上这个脚本，F12控制台输入
```
sms()
```

  
，自动检测网页有没有Sourcemap泄露！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7D6DLyjGU39N1qUz4KZUs75NXvyEoicfib3UWUIIBvS0l4D3I4IwVtZkA/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK75ruk2O9qmXf39ILmI9uYM9ECuJqGTE6EBwVs446Ics2ANOJLW1O9fw/640?wx_fmt=jpeg "")  
### 四、SRC报告怎么写？  
1. **漏洞危害：**  
 Sourcemap泄露原始代码，可能导致API泄露、未授权访问等。  
  
1. **漏洞复现：**  
 详细描述如何下载、反编译Sourcemap文件，以及发现了哪些敏感信息。  
  
1. **修复建议：**  
 删除服务器上的
```
.js.map
```

  
文件。  
  
**0x4 JSONP劫持：跨域的甜蜜陷阱？**  
### 一、JSONP：过时的跨域方案？  
  
JSONP，一种古老的跨域通信方法，通过
```
<script>
```

  
标签加载数据。简单来说，就是带
```
callback
```

  
参数的JSON。  
  
**注意：**  
 现在主流都用CORS了，JSONP基本被淘汰了。  
  
**工具：**  
 Burp插件
```
jsonphunter
```

  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7qI0WZLqhcEh5wicqwMuRiaQj9gomtwibeiaBHPgAa7eFMbpicARV0bpNf0Q/640?wx_fmt=jpeg "")  
### 二、JSONP劫持的条件：  
1. **返回content-type为text/html**  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7nLJ7A3zevdJ7GOPujaF9MZlHBmxupt29LlJ2iaWJTJeic8vunmWJekBA/640?wx_fmt=jpeg "")  
1. **callback参数可控**  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7q3g4MfE5lAibSjONicCF8H1Prnf38EF3Fe6aRN92cibfw3GCOJObf6bUA/640?wx_fmt=jpeg "")  
  
**工具下载：**
```
https://github.com/p1g3/JSONP-Hunter
```

  
  
**参考文章：**
```
https://zone.huoxian.cn/d/318-burpjsonpcors
```

  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7F5MZBUA9GJnEdbwNV4RT00wic0ibDNtxbC2rQVtSIeym1JNFHtZUSgKw/640?wx_fmt=jpeg "")  
  
**0x5 验证码：形同虚设的安全屏障？**  
### 一、验证码直接泄露？这都2024年了！  
  
修改密码的接口，验证码直接在返回包里？这安全水平，我也是醉了！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7icRFq4oQl8ia0Lgib6tAfTCWJt7hZcicRvcwiawebiaVspVkSL5djLbbRe0g/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7I8jaFQmQIT4rM6KdGpxJrEEdpKZQiaYqFqrQ1ubnibWebptv60a8hx1w/640?wx_fmt=jpeg "")  
### 二、验证码字段可以删除？  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK717wE3DP6vUBtceFEt8jZYBGaXC8Zc2KODOIwwVt1ak2yAMC1fXw5sw/640?wx_fmt=jpeg "")  
  
把
```
type
```

  
改成0，删掉
```
validCode
```

  
，短信轰炸走起！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7q534cRhIElEvTrSy3sEBETcKtEDpddZL0kJkicY5meTO8Veias8POlVA/640?wx_fmt=jpeg "")  
### 三、验证码永不过期？  
  
验证码无限复用，直接爆破密码！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7r1Pa8AFAX92PUpKhJLxZ2dO85f3ibjyo0PDm4HhkO23vkEe3yda1uxQ/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7wKe5xM5QYmiaq0YVicJxuGiclnmFRQnnJkwoiamf2rduqq9aBq7ntL3c6Q/640?wx_fmt=jpeg "")  
### 四、验证码DoS？  
  
修改
```
height
```

  
、
```
width
```

  
参数，让服务器返回超大验证码，直接把网站搞崩！  
  
**0x6 短信轰炸/验证码爆破：别让羊毛党钻了空子！**  
### 一、短信轰炸：  
  
注册页面，挂代理，抓包！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7cSkEuP1GwhHB009aJjmRpeibWKibeftVibwSWbJG3W9BoWcocz2gqiby5w/640?wx_fmt=jpeg "")  
  
发现短信发送过于频繁？用
```
@
```

  
、空格、
```
+86
```

  
、逗号绕过！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7oYWsEt6aYOjR3GHkFYlHgoQhf3GVZhKGDQAd5v10Q0qTPAGVhuV1Kg/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7nqa5NhEWflw8VqemP3LxsOmCa8Of3JU6kNic1yMeqahgwGhiczIvsgNw/640?wx_fmt=jpeg "")  
  
用Burp爆破，一分钟轰炸几十条！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7PIQOdricA096wOTHRiaRllz6TZoEhHV4NvXssN3qrsMNG84AJ2NTTwCA/640?wx_fmt=jpeg "")  
### 二、验证码爆破：  
  
四位数验证码？Burp直接爆破！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK70azjHZmy7cTEeckSW4TDLtmrHIRju9xvZ9EFWWcic9ly3DZ6Q2uzCqA/640?wx_fmt=jpeg "")  
### 三、修复方案：  
1. 验证码绑定手机号  
  
1. 限制验证码发送频率  
  
1. 增加验证码有效期  
  
1. 加强验证码复杂度  
  
1. 限制相同IP地址或设备的访问频率  
  
**0x7 任意用户注册：你的账号，我的账号！**  
  
注册页面，随便输入一个手机号，抓包！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7ewbXIR9IncQ1Yx09WAxOjWsAWvZ75MSMmCldPkibf2iaBnWcCTqvVtCw/640?wx_fmt=jpeg "")  
  
爆破验证码！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7c9P8eEb8dibrBPdUGU9ktajPqOYESNybyN6Tcvb6asWqC3iaZtkvdYAg/640?wx_fmt=jpeg "")  
  
注册成功！别人的账号，变成你的了！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7Q01nJiaAibFVRA3XhL4autOVPP8tuEu3qyb6gV0dFNXeyI3QwUCg9w5Q/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7u0W7usKQbSkqiaop3ekLTyXqFHGqwfbqWxicSVBvv0uU028E5iaZAxRgQ/640?wx_fmt=jpeg "")  
  
**0x8 云存储：被遗忘的角落？**  
### 一、AK/SK：云安全的命门！  
  
认清各大云厂商的
```
Access Key
```

  
特征：  
- **阿里云：**
```
LTAI
```

  
开头  
  
- **腾讯云：**
```
AKID
```

  
开头  
  
### 二、OSS存储桶：你的数据，我的地盘！  
  
泄漏的AK/SK，可以直接接管OSS存储桶！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK768Wdey9QaLyfHGuUYNXltfm7td3FUNdQjxfqHSAZouY1KfhJyfztGQ/640?wx_fmt=jpeg "")  
  
在配置文件里找到AK/SK，直接登录！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7AbfzL5wjiaWBFkKPicJGZAf73meTBRCqia1Rr5PEPbzKalX6CIQE3KuGw/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7ib6bRPHfyTticUhUNibYAkhAxgEyNWmYOMWK3aBLyOhOqwmvmNr68us5w/640?wx_fmt=jpeg "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7envvrr72gbibL5C0pqVoo7UAmgpJic2iaELTfQ6jjWiboGrZ5M3Og5cPxw/640?wx_fmt=jpeg "")  
  
**工具：**  
- 阿里云OSS Browser：https://github.com/aliyun/oss-browser  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7QYE27XticEQP4p8WhoJDSocJJIXkaoxn30wyRQXuhOuw0YZHnCibwW2g/640?wx_fmt=jpeg "")  
  
输入AK/SK，连接成功！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT619ibeZVGgxdFreIBrtQbK7kgLicD3x5AUl28hEMXQRQpjW0vJn6Be9OmwmtScsgPacOFuyNCicgPIg/640?wx_fmt=jpeg "")  
  
里面的数据，随便你玩了！  
1. **黑客/网络安全学习包**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkUGiakynth3MRTicLcHaV4MAvjubiaIicUx4ZrMxuSdSicjzT5HfEAzJy782g/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkU7VZiaRU6vdoIQC9ToNyrFNvkWmp92gn3R2RWyGVEiaxjTlDjic3dPsW6g/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**资料目录**  
  
  
**282G**  
《**网络安全/黑客技术入门学习大礼包**  
》，可以**扫描下方二维码免费领取**  
！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT4Zy8efCHagq54hvWttN7A4N5KvFOGmvfiaMJ8yTWJjx3dsmfCPMG5RKqacW5TnZKrPatrickn8pRcw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
1.成长路线图&学习规划  
  
要学习一门新的技术，作为新手一定要**先学习成长路线图**  
，**方向不对，努力白费**  
。  
  
对于从来没有接触过网络安全的同学，我们帮你准备了详细的学习成长路线图&学习规划。可以说是最科学最系统的学习路线，大家跟着这个大的方向学习准没问题。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/7O8nPRxfRT70xf5ibc31iaUicWicOzXOWCDCiazCkl1qd40fUnL9MRSp7FUciadf9d1iaTU5cm7qWmVymY246v6BNWibLA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/evTLxnBbHv6fa8BCJ5052WLSGZjTIfEDgymVV6FeniaFszgpka15xzMolFmtXDdiaaDJMwXSqTQgRgBicvbYv4tNw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
2.视频教程  
  
网上虽然也有很多的学习资源，但基本上都残缺不全的，这是  
我们和网安大厂360共同研发的网安视频教程，之前都是  
内部资源，专业方面绝对可以秒杀国内99%的机构和个人教学！  
全网独一份，你不可能在网上找到这么专业的教程。  
  
内容涵盖了入门必备的操作系统、计算机网络和编程语言等初级知识，而且包含了中级的各种渗透技术，并且还有后期的CTF对抗、区块链安全等高阶技术。  
  
总共200多节视频，200多G的资源，不用担心学不全。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/7O8nPRxfRT70xf5ibc31iaUicWicOzXOWCDCr4b7vAFPEvHhR7qVkt4qwOHyEpmxZUHD7IffRmBVmtSMQs8nY89h7w/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
3.SRC&黑客文籍  
  
大家最喜欢也是最关心的  
**SRC技术文籍&黑客技术**  
也有收录  
  
**SRC技术文籍：**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dkY8ctWgyFKc2oWZY3ibCDm5lMpjofvtGCicHTLibsOF8b841UOfozGsdjDvJKiaFgibdTunKlgC9kzrTQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**黑客资料由于是敏感资源，这里不能直接展示哦！**  
  
4.护网行动资料  
  
其中关于  
**HW护网行动，也准备了对应的资料，这些内容可相当于比赛的金手指！**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnaPKJSI9dNKiaR4vaJf0hqApKNbJeZnCpsQSElEicDrlAMLkRXHoyKN8A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
5.黑客必读书单  
  
****  
6.面试题合集  
  
当你自学到这里，你就要开始  
**思考找工作**  
的事情了，而工作绕不开的就是  
**真题和面试题。**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnXxPNhSSySbwUMEWOicYYS62D1UOQExv0cYuVQ68gk2uFF2xJ4TPmRHA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**更多内容为防止和谐，可以扫描获取~**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnGktIUCicPreibR6b3sx1Qu0CsCZP0sZtCP4RHlMdxXuE4icCFSoL2yyBg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
朋友们需要全套共  
**282G**  
的《**网络安全/黑客技术入门学习大礼包**  
》，可以**扫描下方二维码免费领取**  
！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT4Zy8efCHagq54hvWttN7A4N5KvFOGmvfiaMJ8yTWJjx3dsmfCPMG5RKqacW5TnZKrPatrickn8pRcw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  

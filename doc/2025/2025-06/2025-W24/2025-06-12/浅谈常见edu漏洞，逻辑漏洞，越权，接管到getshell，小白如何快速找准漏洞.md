#  浅谈常见edu漏洞，逻辑漏洞，越权，接管到getshell，小白如何快速找准漏洞  
点击关注👉  马哥网络安全   2025-06-12 09:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAk1nlByTOFiahZKGHekfZGC1V0p6QaXc4CnbPBMZQuFGAnW00CX43Xk9JXONUTxeqYxActf31UiajMg/640?wx_fmt=png&from=appmsg "")  
  
之前闲来无事承接了一个高校的渗透测试，测试过程中没有什么复杂的漏洞，是一些基础的edu常见漏洞，适合基础学习，于是整理一下和师傅们分享。  
  
今年对某高校进行了渗透测试，发现了一些比较经典的漏洞，写一下和师傅们一起分享。  
## 1.教务系统登录处短信轰炸  
  
![11).png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAknsWs030QWqQzribpqz7fqAEdDZR6hlhu7MuHUONibPafmqt3gBS9bVupKW3icYxibjxYteVSooBDs8A/640?wx_fmt=png&from=appmsg "")  
  
  
学校的教务系统登录处，发现有一个手机验证码认证  
  
![kappfra2).png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAknsWs030QWqQzribpqz7fqAvL5J9O1oapWQvT5PWGjiaw4etU8dmbzC54eN6UK40JxAibfxDYFPSV7w/640?wx_fmt=png&from=appmsg "")  
  
  
这里会发送一个验证码  
  
正常来说，每发送一次短信验证码，这个校验码就会自动更新一次，然后会报错：“验证码错误”。  
  
但是这里抓包之后，发现能抓到两个数据包  
  
![attach-1e1244475c6dff0e2087e23915db3711aab85810.png](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAknsWs030QWqQzribpqz7fqAxuIpkw1EC9htjyDVfBMWL4T6lLoNphZUUa5ANQY68oLd1GL71Qlib8A/640?wx_fmt=png&from=appmsg "")  
  
  
这是第一个数据包，可以发现是对验证码的验证，我们把第一个数据包通过之后，拿到第二个数据包：  
  
  
![3).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahwJfYmn5ibS4wouTuOribYNWBPib3hWicstCdY2kbO0oYm7EDIuib5ZW2kMQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到我们的手机号出现在了第二个数据包中  
  
我们点击放到repeater，然后点击send，可以发现一直发送：  
  
  
![111.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibah5Ox2QTFqdM8JLI74rhWpiaiagMjWmtXrHd2jC4hXWKWiaPlXdlZGdh4Rw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**原理**  
：正常来说校验码的验证和发送短信应该是在同一个数据包中，这里不严谨的设置，将校验码的验证和发送短信的数据包分成了两个，我们输入正常的验证码，通过第一个验证的数据包，拦截第二个发送短信的验证码，即可实现短信轰炸。  
  
这里分享一下短信轰炸的几种绕过方式：  
#### 1.手机号前面加空格进行绕过  
  
这是挖某专属src时遇到的  
  
  
![213122.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahicUlibdJU16lsAbH0gnVE82uPa8u5REwoC6NHrKiauHicuSK8HOygAZZuQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
account为手机号，正常情况下，一个手机号短时间内只能发送一条验证码。  
  
在account中的手机号前面每加一个空格可以突破限制进行多发一次验证码，  
  
  
![attach-d5386ba03170c8b2e6603e5c0ad7bc221338a481.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahAsurvmIfGvx3oJvbYoaRc1Eicl4ogH42r7SFjxzp5b5yh8u123tRFzw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
burp设置两个载荷  
  
第一个载荷用于填充空格，设置为50（这样设置，一个手机号就可以发送成功50条短信）  
  
第二个载荷用于循环遍历手机号，可以设置遍历10万甚至更多的手机号  
#### 2.加字母等垃圾字符绕过或者+86  
#### 3.伪造XF头  
## 2.校内某实训平台任意用户注册、任意用户登录、修改任意用户密码、验证码爆破  
  
  
![5(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahXwQKnPPUY5gwlc66emKLg9Dd5TRSGRe7wfCby3ibSUibEO6RzEgsIsnQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这是校内某实训平台，我们先点击注册功能点。  
  
![111P(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahrSdKISFjh2uPygFbvcyHJLxdECb1ibtIc4KU3pguNFSyDyleqpYNSGA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
我们点击获取验证码，然后进行抓包：  
  
  
![12312GR(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibah6KRbOZfBwyOicGchRx1oQtxjBucIJrAq6RHRtjK2HTw7jI8y3vicUTAQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到手机号被编在了url里，我们这里使用“,”去拼接手机号，这样就可以把验证码同时发送给两个手机号，并且收到的验证码相同。好比我知道你的手机号，拿你手机号去注册，我根本不需要知道你的验证码，因为验证码也会发到我手机上。  
  
  
![1233213123zCywpV(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahpKXQSwk9ZgLgfXyqPco97FXkAN4ofQSiarzzduwuLg56ZPdVPEdOClQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![123321(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahYL5OOU7bLWphiaVncgkeRqIZTXFgAmK9bAmHNUUicCC8lcULWVZib3UxA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
修改密码功能点也是相同，我这里不进行过多赘述  
#### 验证码爆破  
  
  
![ka12332132123123)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahGDpNiboJ359VSnBacsh6rPqO4gwTtUSdOY32OoQ3V6HVWzQF1oASoTA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
正常发送验证码，然后在填写验证码的地方，随意输入四位数  
  
  
![attach-f9667d233ce6573b5439c68f327ddd189343fee5.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahkgxlyhIK5BLVfzFjdcy2qrFcbh1SW2saSdMeGKdCfZVU9CDfOjUP5A/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![3213121322131)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahhkavdpmaDN7q1Xhu93Lh8jyZ3PKNG7BwsAo5OYKX5qb7qTwibw729qg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到在7710的时候，长度不一样，成功登录进去了。  
  
**修复建议：**  
：对验证码输入次数进行限制  
## 3.越权查看所有学生和教职工个人信息，数万条记录  
  
  
![2222.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahVEbrlv6vcl1MTF1LruYnJEJWphx5fIgMUAjcv5p9cfyuN7gj0P7ztg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
教务系统个人中心处有一个查看最近登陆记录的功能点，发现右上角有个查询，我们抓包尝试：  
  
![1322222)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibah6skJApJYrqVTHEbR8SNicf27bibWWdmf111fEiciax95l8MLTKQ7m5grbw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到这里可以看到我们的登陆情况，我们尝试去修改value的值，看看能不能直接越权查看别人的登录信息。但是发现无论修改成什么都会提示登录信息错误。  
  
修改成0、1、-1都不可以，但经过我的尝试发现，只有一个值可以，那就是null！  
  
我们让value=null  
  
  
![31232213Vq(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahiaLtyT4LnguIa1FEiaknFD4yiaRQmLsPbHpD8vlgppkQ6wpiaaZXMONaSQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
但是登录的记录明显有点少，而且观察发现好像都是登录失败的记录，这时我发现有个name字段，我把userid改成*：  
  
  
![123312(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibaht7uVD0AfiaOcCF1nCvj7kUgdSJlzwzu1KNaBiaEVxHyGn48j8CxoV4yg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
拿下所有学生和教职工的个人信息，包括姓名、手机号、身份证号、学号、教职工编号、登录ip等  
  
## 4.教务系统绕过手机验证码换绑手机号  
  
![12332132(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahCV6DnggvEmPniavxhF2iasuj8P5ibbmnoCkQc05ia4StVQvju2xE9mwYjQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
也是这个教务系统，安全中心有一个换绑手机号的功能点，我们点击发送验证码  
  
  
![3333.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahr9ib1KPxwAmNkL6rD8CF8VaibSuEf4psSz2D08Xj2G8DTRDg0dzXuMYg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这里可以看到是修改195开头的那个手机号，然后我们forward  
  
![123312(1111)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibah39iaP5ICM3yicEG98dEE5PjRVyicM4oQzOfCaweZ4d4Xqn2mhVhBDPxgw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
之后弹出一个验证码，我们输入验证码点击确定  
  
![1231232.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibah1afkgAHZ2eZMSl1GcyKOtjtxicwicKyqdEibFJjWZQECDKCrDbxyVMhXA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这里的验证码就做的很好，和发送短信的验证码数据包放在一起了，杜绝了短信轰炸。但是我们这里把195开头的手机号修改成我自己的手机号。  
  
  
![1312BtK(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahMf2licua92PnROnd64ccSxfx5vCCRhMcomqtx6fYcUwpM8mEPJ4qxRA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
成功让自己的手机号收到验证码，以为皆大欢喜了，结果。  
  
![1111e(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahPsGGTRGllibuE9RRC6zMs9B9Yglcjd8eT8uyK72rVQczQK4B94qEicibw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
显示验证码错误，这是为什么呢？  
  
我们继续审一下错误的数据包，也就是我们抓输入完短信验证码，点“下一步”的那个数据包  
  
  
![111.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahw7nIwvMfMiaN8AMqdiaCcZMDf6b0XTNd3sXy1Hl3adQJVFItsXojxA4A/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到居然在“下一步”的地方，对手机号又进行了一次验证，我们将这里的phone改成我自己的手机号，然后forward  
  
  
![211221O(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahZXyEoU8TiaDughnvutIOr56ZEcFjsQdpM64OLFHEbmofC4cIaBkt6PA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
成功到达绑定新手机的界面，成功绕过了验证码认证，可以换绑任意用户的手机号。  
## 5.校内某平台druid未授权访问，导致泄露用户session，可以实现任意用户接管  
  
  
![111Bc(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahOnARMU917ftU3XASXUHibgfURg7E3sNswUCUqHiaoddribuZnTCJMD5Vg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这是校内的一个实习平台，url为“https://xxx.edu.cn/shixi/”  
  
然后之前读文章读到了一个druid的未授权拼接，/ / druid /  
 /  
  
于是尝试拼接 ：“https://xxx.edu.cn/shixi/druid/index.html”  
  
  
![2221)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahX0ichwQeo2x70s7MASe70JSmY7IqBoJVa1aLehnwdBVHEpFeibRBGqVA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到是有druid的未授权访问，这里会泄露很多东西，比如数据库信息，数据库查询语句、访问记录等等。我们这里搞一下session。  
  
可以看到有一个session监控：  
  
  
![3333hPXD(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahrA5QYqHXevjdmIFfiakicW5c5QftJrcgW2SayqRt2l95Chn9wK5wgh9Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到这里有登录过系统的用户的session，我们要做的就是把session收集起来。这里我有个比较好用的方法，可以ctrl+a复制全页，然后粘贴到excel里，然后选中session列，就可以快速的把session复制到txt里了。  
  
  
![44444Zc(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahgJJkewFaLu1wP0JYuSXmCOgOicQs4VAaUrRtH6x9xZARZCicMTDggdbw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到我们把session这样收集到了txt里，然后打开yakit  
  
把txt导入到yakit的pyload里，然后去抓一下登录窗口的数据包：  
  
  
![5555tPEr(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahjaCKibLw7tNlCiadDc9TRGP0umvkibm9MZzq3UPiaBzzBjkaqQbh5d07Vw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到cookie有个jessionid，我们把他的值设置成标签，然后去拼接刚才的session的payload去批量访问：  
  
  
![666666(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahIDn33dOC4P1wvYIqHQEWyUYufq2fo8CPtRKzkbz0qu2HBV7FSFv45w/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到有很多200成功访问的，也有一些无法访问的，无法访问的原因主要是因为session是具有时效性的，长时间后这个session可能就会失效，但是只要源源不断的访问这个系统，我们就可以源源不断的盗取新的session。  
  
我们找一个200正常访问的数据包，把里面的session复制下来。  
  
  
![77777A(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahZ33HS8EKXyBwzZ2zFAG4CtvlXpxQcFyXAibNjBQx44Jn1K4EbQ0PkIg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
然后回到网页，打开f12里的存储，替换里面的jsessionid  
  
  
![1231231.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibah2bcH8gZm2sLjXQm3frbF0HCcZWdaY8aVFn09ibhvlgTWgTwYKFItWQw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
然后刷新页面：  
  
  
![1111111).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahB8ibLOiby8mXiaGRzKTfqkZBrmh12tMCt5mia3ncIpe0cKQQ5zkLlVrgAA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以发现直接接管了别人的账号，登录进了系统。  
  
## 6.内部系统存在sql注入导致rce  
  
  
![333.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahqILaiaSEgzjqpoDmu57kkxXbVK4Elib2luicFWjhZBzs4mxNvBCpkiaqJg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
学校新出的一个平台，还是挺重要第一个平台，负责校内事务和档案的，应该还是个通用，很多学校都购买了这个平台。  
  
我在那个平台抓包的时候，这个数据包偶然出现在我的burp里，我一看，居然直接把sql语句写出来了，这不就可以直接利用了吗？  
  
  
![1233121)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahUyV7z2UNubA1TV04H6XjBJaW6VDdiby5vmgeCUheLGRguFksSlgrP1Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
直接执行select user，可以看到右边直接进行回显了。那个user字段的内容就是回显的。  
  
后来我写报告的时候，怎么找也找不到这个包在哪抓的，没办法，只能转化思路去找js接口。  
  
![123321Vi(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibah1mjSj1ORJs4xTUG2yNx3rOg9F4viasiaiboG176UFxicR44xa5dBibicDrTg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
可以看到这个data里有sql:t  
  
成功找到了这个接口，然后还有意外收获！  
  
  
![1111)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahNg1aaZicMqG9nLMWaCta6iaBDd0tqeXBLqKrDT2CYxHVYRicpVImZFxxA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![222bqB(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahLvRPYibnZZxBOwtdDfkH8qBwRUaGKVPYb6yM13gRAcDJKXcx1CL4VHw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
找到了近400个接口，这400个接口基本上都和上面的一样，直接写出了sql的语句，都可能存在sql注入！  
  
那么多接口，第一想法就是爬出来测一下未授权和越权。  
  
然后写了个爬虫python脚本去爬js  
```
import requests  import re  \# #proxy={'https':'127.0.0.1:8080'}  \# url=""  \# headers = {  \#     'cookie':'',  \#     'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',  \#     'Username':'',  \#     'Accept':'\*/\*',  \#     'Te':'',  \#     'Priority':'u=',  \#     'Sec-Fetch-User':'',  \#     'Sec-Fetch-Site':'',  \#     'Sec-Fetch-Mode':'',  \#     'Sec-Fetch-Dest':'',  \#     'Upgrade-Insecure-Requests':'',  \#     'Referer':'',  \#     'From':'dzj-pc'  \# }  \# def get\_html(url):  \#     res = requests.get(url = url,verify=False,headers=headers,allow\_redirects=False)  \#     # return res.content  \# #  \# html = get\_html(url = url)  \# print(html.decode("utf-8"))
```  
  
爬出来之后，使用正则去检索我们所需要的东西：  
```
file = open('C:/Users/xxx/Desktop/111.txt','r')  lines = file.read()  apis=re.findall("url:\\"(.\*?)\\"",lines)  for api in apis:  if'?' in api:  print(api.split("?")\[0\])  else:  print(api)
```  
  
. 表示除\n \r 之外的任意单个字符  
  
* 匹配零次或者多次  
  
? 指定为非贪婪模式  
  
然后我们将收集到的api，放到burp里去批量访问  
  
  
![12(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahrPr7jMwfibJ5l1IzGOKruibrzcbmqMuneGWYOAJUFr7XuX42OXzSLzIg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
但是没有跑出来，应该是没有未授权漏洞，做了全局验证，逐个删除cookie字段，但还是不行，没有cookie就被深信服的设备拦住了。  
  
那我们回到最开始的sql注入，该如何扩大危害呢？  
  
首先我们要判断数据库类型，于是我继续看js  
  
  
![122121GO(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahGIvx50ibKPEvnm2DUFu6akIm3OByogicWMLnMX9lGOeRmPTgEluM3BoA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
一开始看到了from dual，我以为是oracle数据库，然后尝试了oracle数据的sql语法，发现总是报错。  
  
后来再翻js数据包的时候，发现了这个包：  
  
  
![11111g(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibah9f1uKr1394X6M36vMRhHAaw8X413l0tcDiabe0v7cAzZhkiciaHB9lVlQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
这个数据包不仅直接暴露了usr_bsp，重要的是告诉了我们这个是postgresql数据库，这个数据库不太了解，我去百度了一下sql语法。发现他和mysql的语法差不多。  
```
select table_name from information_schema.tables where table_schema=''
```  
  
  
![1111111)(1).png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTToE7wDnEMVBBaibfVsDDsibahrMJbtnougaf0NeiaNknXicUEdXomoQ0dS4hyQKUKpYg36Lv6bXf3ria7Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
成功注入。然后在征得校方同意后，可以使用postgresql数据库的集成利用工具直接进行rce。  
  
至此，渗透告一段落。  
  
注：严禁未拿到授权就进行渗透测试  
  
  
文章首发：奇安信攻防社区（  
侵删）  
  
https://forum.butian.net/share/4291  
  
****  
**文末福利**  
##   
## 现在已经步入2025年了，不少小伙伴在考虑入行学习网络安全。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAmTHoVHrG8PppyYU8FpGmLJDLOPiax3pqwnq9hFjDSMH4cpYptL3h071PkP0jkoR5ib2Ksfia8VFnicmQ/640?wx_fmt=png&from=appmsg "")  
  
为了帮助大家早日习得网络安全核心知识，快速入行网络安全圈，**给大家整理了一套【2025最新网安资料】**  
**网络安全工程师****必备技能资料包**  
（文末一键领取）**，内容有多详实丰富看下图！**  
  
**Web安全**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFBODrmsTGnPTOibdIT9B5eFLTHVIgWzYafxGAesmYnfzrz52xwV3Bjhw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**渗透测试**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFVKWl2cLRTq7x9haKJerUZNO0YMhiaO8ibN1jjV0qxNLEvRKMfR90eNjQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全面试题**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFgrmaDLaYT1yV5lst9tKC72QrYjd5I8IN7kcOZIZSfQJJz8MdX6a1uA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**代码审计**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFxmUkTNP1iagssZL5zkjID8hibpZsRCj1OnEb4x7ZYWqpiaymSjc8O7vSQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**HVV文档**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFMD4XeWiaQgOBDgFjkQRogf6djmGx3YRcCCSLYGMY1e4DQejgibv7fffQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**红队笔记**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkcvc41LgmeFn1B18QpgBZFVZS1mB4MKAo4FoMBGyVSzq38ZXEKJCjZVaTsFtLE7tIJ3zbRWF5xeA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**入门视频**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/O9D0kmTL9EgxtiaXGtk7loXV41e8AXiaORJMhqFbrtcfHvJWTia6ME2oSI9msVYJu79uCicb7foufuibEHaVg32XnWw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NUwbCdTuQQxsJibSZGyA8akP9TVyJfPcpJ4uIZJDj3akRUfv6cNbnksGJQsibq1aH8iaGDic7TvOaSwNGXLdQ8PC9A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**以上所有资料获取请扫码**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkwcjtOtVXODCkPibWO4Py9FP1ESE26vHHMLwfyYA6zWj96VL7AsPYcyvHL43536JMIDNWibIdicAjRw/640?wx_fmt=png&from=appmsg "")  
  
识别上方二维码  
  
备注：2025安全合集  
  
100%免费领取  
  
（是  
扫码领取  
，不是在公众号后台回复，  
别看错了哦）  
  
  
  

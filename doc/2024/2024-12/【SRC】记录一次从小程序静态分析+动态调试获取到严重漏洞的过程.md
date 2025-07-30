#  【SRC】记录一次从小程序静态分析+动态调试获取到严重漏洞的过程   
 TtTeam   2024-12-18 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
原文首发在：奇安信攻防社区  
‍  
‍  
‍  
‍  
  
https://forum.butian.net/share/3832  
# 前言  
  
本文记录了最近的一次src漏洞挖掘，并成功获取到严重漏洞的过程，漏洞本身就是几个接口的组合利用，但是其中小程序的代码的分析审计过程比较有趣，遂记录一下和大家分享。  
# 准备工作  
  
本文涉及到小程序的静态分析、动态调试、签名算法逆向、自动化签名计算等方面，很多技术在网上都有比较详细的文章，我就不在深入赘述，这里只记录我在分析过程中用到的技术和方法。  
## 获取小程序源码  
  
获取小程序的源码比较简单，直接在微信-设置-文件管理-打开文件夹  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944iaiazvJnu7JPyKMGJkxZvktjy1n7t9icwefeT6KJg5g3og1a6GIJnvib6w/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
会自动打开文件目录  
```
C:\Users\Administrator\Documents\WeChat Files\AppId

```  
  
这里我们需要跳到小程序的目录  
```
/WeChat Files/Applet/{wxid}/{n}/

```  
  
会看到一个__APP__.wxapkg，这个就是小程序的打包程序，需要对该文件进行解密，即可获取到小程序源码，解密脚本我使用的是https://github.com/zhuweiyou/wxapkg直接把文件拖到exe程序的图标上便可以自动解密  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN29441NcVuTTTLNqFrCvnHKDtqPGoxhwQQlGv5Tnl19XCfFmIwiaMHQibYNPg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
解密后会在当前目录保存解包后的文件。  
## 开启Devtools  
  
强制开启Devtools我用的是https://github.com/JaveleyQAQ/WeChatOpenDevTools-Python这个项目。对应使用的微信版本是WeChatSetup-3.9.10.19微信的历史版本可以在https://github.com/tom-snow/wechat-windows-versions/tags下载。这里需要注意一下的是，如果电脑上安装了高版本的微信，需要先卸载掉，再安装低版本，否则hook的时候会失败。并且hook有风险，建议使用小号在虚拟机里运行。程序的运行很简单，退出微信后执行  
```
WeChatOpenDevTools-Python.exe -all

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944WLtLv3OdP0rQ70GEQs98tDEeA6jLQQWictUP7JaEsIZfcRJPcDL2NQg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
会自动弹出微信，登录后打开小程序即可hook成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944sp3y4tluXIcNXLnnT55kg0DhWuiaJjnwoAzTKOqaGdK6BibN4VRDpTicg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944RMGOGtjH79lmgCKCIicg8jmQGbBjLhibWnHptOGDJJricPW3hicfN3QeUA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 小程序抓包  
  
小程序抓包我使用的是proxifier+burp  
  
在peoxifier中新建代理服务器，ip和端口对应burp的监听端口，协议选择https  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN29445mEwbzY4oYHArbJkPfDQtK1MUNsvYIwQxUoLASL4eQOOWTucsKhicog/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
然后新建代理规则。应用程序选择  
```
WeChatApp.exe;WechatBrowser.exe;WeChatAppEx.exe

```  
  
动作选择拦截  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944EHiandlML8D23RCwBntInHGPFNxz1caWEVmMMog8o4q1E4cdvRKIOiaQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
即可实现小程序的抓包  
## 自动计算签名  
  
前面的准备工作已经基本完成，可以实现对小程序的分析了，这个步骤并不是分析小程序所必须的步骤，只是在这个目标中，使用了sign值来校验数据包，所以我们在修改了数据包后，需要使用自动计算签名的脚本进行自动签名。自动签名我用的是mitmproxy，支持python代码编写，可控性高下载地址：https://www.mitmproxy.org/使用方法如下：  
```
mitmdump -s xx.py -p 7777

```  
  
用于加载一个代理脚本，并监听7777端口，然后我们在burp中把数据包中转到7777端口，即可实现mitmproxy自动对数据包进行签名。burp设置如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944kC5zft8UemDUibYhk6RPw7D4wTwBticB8ZdEWINuccdslTOFypAw2J9Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
然后再burp中发送数据包进行测试，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944W9n1ws40AlIstC7CL0hibdicqJkSDBZ97olB2nVgVib8mxb9Jl30JOQcA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
看到终端中有数据再跑了，说明配置成功，这里需要特别说明一下，在使用编译好的exe程序运行python程序时，可能会出现ModuleNotFoundError: No module named 'Crypto'找不到库的情况，即使是最新版也有可能出现，这是一个bug，使用pip3重新安装mitmproxy即可解决  
```
pip3 install mitmproxy

```  
  
至此，准备工作完成，开始分析小程序  
# 代码分析  
## 数据包分析  
  
在小程序分析过程中，我喜欢先抓包，浏览一下大概功能并看一下数据包的接口，大部分的小程序都是host+api接口+uri接口的形式，我们直接看数据包，可以免去我们找host和api接口的步骤，直接拼接提取出来的url即可。这次的目标是一个客服系统，直接点进去小程序，提示没有对应的客服，然后一篇空白，什么功能都没有，那么看一下他的数据包，  
```
POST /wxapi/Customer/Acc HTTP/1.1
Host: 
Content-Length: 37
Wxversion: 3.9.12
Mobilemodel: microsoft
Clientplatform: windows
Sdkversion: 3.5.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090c0f)XWEB/11275
Minprogram: v1.9.9
Content-Type: application/json
Xweb_xhr: 1
X-App: mgwx
T: 1728436146712
Systemversion: Windows 7 x64
Sign: 1e02db58edb4f1e0710f7d9b3da9e39d0af98ffe
Accept: */*Sec-Fetch-Site: cross-siteSec-Fetch-Mode: corsSec-Fetch-Dest: emptyReferer: https://servicewechat.com/wxf7xxx/78/page-frame.htmlAccept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Connection: close{"UserID":"14979"}
```  
  
有个code，随便修改一下，提示鉴权失败，仔细观察数据包有个sign，那么很有可能就是利用的sign来校验数据包，我们需要分析一下sign的算法。  
## sign算法分析  
  
打开devtools一般在appcontext下的no domain中存储的是小程序的js代码![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944adUFz26ibII0qZrwicLJRDOPwzicNIR9Kcg5MiaqHcbgLnAwI3TLU0m5rg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
分别打开这几个js，查找sign关键字定位到这个地方![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944NNWOSjXQQJpbashVKWFxBcSIDgVrB9LMyGGY3s70gdKFgZgMskgNHQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
两个处理逻辑，一个get的，一个其他，需要分别分析。先看get的，  
```
            var g = (new Date).getTime();
            if (s.t = g,
            "get" == r.toLowerCase()) {
                s.requrl = n;
                var c = n + t.globalData.key + g
                  , m = e.SHA1(c).toString();
                s.sign = m

```  
  
n就是requrl，var g = (new Date).getTime();就是时间戳  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944svgQiamKBLWZ5PuW5eXItcH81fw0m51aiasoyzlibUVZdCenTRdKpCOOg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
还差一个t.globalData.key，全局搜索globalData。在32486行找到了key  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944uaibd3t6dEbaziaTK9pTvLRa1Dnk4mkiaZx5RmmROL1f644FB7H24qVaA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
将url+key+g拼接后进行sha1就得到了sign  
  
然后分析其他类型的sign计算  
```
 c = JSON.stringify(o) + t.globalData.key + g,
                m = e.SHA1(c).toString();
                s.sign = m

```  
  
get传的是url+key+g，而这个传的是json格式化之后的o，往上找o在哪里定义的，发现o是直接传参传进来的，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944nIn6HgJF2slPWwuMJzia9KwawiafApxLhWxrYia38vP0TEn7XdzsWlOFw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
这样再往上去找函数调用的话不如动态调试来的方便，于是在32185行打上断点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944f5kLib1nTiaBQmHWicBEf3TDeddYj3GqMCTRWicAR9CSLrTDEOv13SBpfA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
找一个post功能的点，提交一下，便会停在断点上  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944bibibgd320Vibp0kNicXJKUyV6iaV3VK5q7CvCmDQK10eQFeWWU9cktlzMQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
这里便可以看到动态传进来的值，把拼接后的c复制出来：  
```
{"sessionId":"jS9NZxxx","encryptedData":"xxx","iv":"xxx"}tiixxx1728443242572

```  
  
和最后发出去的数据包对比一下，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944ksj4KaK2ibvAlnzQxDHVibUgN5H9mLWc2ykqGQ0jAtsRwqA6wzl5dsPg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
很明显o是传入的data数据，至此sign的算法分析完毕，mitmproxy脚本也就直接可以写出来了，代码有点渣，能用就行  
```
import datetime  
import hashlib  
from mitmproxy import ctx  
import json  

# 获取当前时间  
now = datetime.datetime.now()  

timestamp_ms_precise = int(now.timestamp() * 1000)  
key="tiihxxxx=="  

def request(flow):  
    # 获取请求对象  
    request = flow.request  
    # # 实例化输出类  
    # info = ctx.log.info    # # 打印请求的url    # info(request.url)    # # 打印请求方法    # info(request.method)    # # 打印host头    # info(request.host)    # # 打印请求端口    # info(str(request.port))    # # 打印所有请求头部    # info(str(request.headers))    # # 打印cookie头    # info(str(request.cookies))  
    if request.method == 'POST':  
        data=(request.get_text())  
        print(data)  
        n=data  
        #n = json.dumps(data).replace(": \"", ":\"")  
        print(n)  
        T = 1728192063292  
        c = n + key + str(T)  
        print(c)  
        encoded_data = c.encode('utf-8')  
        # 创建一个sha1哈希对象  
        sha1 = hashlib.sha1()  
        # 更新哈希对象（可以多次调用update()来添加数据）  
        sha1.update(encoded\_data)  
        # 获取十六进制表示的哈希值  
        hex_digest = sha1.hexdigest()  
        Sign = hex_digest  
        print(Sign)  
        request.headers["Sign"] = Sign  
        request.headers["T"] = "1728192063292"  
    else:  
        n=request.url  
        print(n)  
        T = 1728208280365  
        c=n + key + str(T)  
        print(c)  
        encoded_data = c.encode('utf-8')  
        # 创建一个sha1哈希对象  
        sha1 = hashlib.sha1()  
        # 更新哈希对象（可以多次调用update()来添加数据）  
        sha1.update(encoded\_data)  
        # 获取十六进制表示的哈希值  
        hex_digest = sha1.hexdigest()  
        Sign = hex_digest  
        print(Sign)  
        request.headers["Sign"] = Sign  
        request.headers["T"] = "1728208280365"  
        request.headers["Requrl"] = n

```  
## 接口分析（漏洞挖掘）  
  
解决了sign的校验问题，就开始分析程序接口了在静态分析的源码中提取出来几十个接口，挨个进行测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944NpszmgAtxMjZItkNrfD4VejGoGPXIVKL2KAbick1A25QgZywn6bJovw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
经过多次测试，发现该客服系统使用的websocket协议进行的聊天，抓到的数据包如下：  
```
GET /websocket?appId=mgb7xxx&token=juukgLAxxx&sdkVer=5.6.1&pid=&apiVer=normal&platform=MiniProgram&protocolVer=3 HTTP/1.1
Host: wsproxy.xxx.com
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) XWEB/8555
Upgrade: websocket
Origin: https://wsproxy.xxx.com
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Sec-WebSocket-Key: Z7s5axxx==


```  
  
这个数据包之后就会直接从http协议切换到websocket协议，而这个数据包中的appId和token是由客户端直接发送给服务器的，所以这两个值要么是js计算出来的，要么是服务器返回的数据，先搜一下前端的js代码，发现appid是写死的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944eVHCicVuOiatZTdkdOCjtCwLUCaDjHomrkgEU4amL9CmrHpNoHFAzewA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
token在js中没有相关算法，基本就可以确定是服务器返回的数据了，在burp的proxy history中搜索token字符串，看一下是哪个包返回的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN2944Dmwl1oviaWozRoxbo34bKyWwBvxGhh5xveEftJInPOF79ktPdibc0kXA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
找到了接口，发送到repeater尝试修改userid，发现仍然会返回token，说明这里没有身份验证，可直接接管任意用户的聊天会话。写个python利用websocket库切入websocket会话，成功接管会话内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTpdfujJpIyXgEMnFMxN294433yarlYABZ6YGmZ6OWsiaRQDeBiamfpicpwHgkQuf0iaoXGqd0AjfUEL7A/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
至此漏洞已成。顺带补充一下src中客服聊天系统的危害描述：1、泄露客服与客户的聊天记录，能参与聊天的都是高意向客户，客户的购买意向、联系方式均属于核心商业机密，接管会话可循环遍历所有会话，窃取机密信息。2、websocket无身份验证，可冒充客服对客户发起钓鱼，极大的损害企业形象。  
  
最终，该漏洞给了严重。  
  
  
发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  

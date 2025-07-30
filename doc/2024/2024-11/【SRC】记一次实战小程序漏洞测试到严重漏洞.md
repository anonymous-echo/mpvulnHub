#  【SRC】记一次实战小程序漏洞测试到严重漏洞   
禅师  Z2O安全攻防   2024-11-02 21:48  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
# 前言  
  
本文记录了最近的一次src漏洞挖掘，并成功获取到严重漏洞的过程，漏洞本身就是几个接口的组合利用，但是其中小程序的代码的分析审计过程比较有趣，遂记录一下和大家分享。  
# 准备工作  
  
本文涉及到小程序的静态分析、动态调试、签名算法逆向、自动化签名计算等方面，很多技术在网上都有比较详细的文章，我就不在深入赘述，这里只记录我在分析过程中用到的技术和方法。  
## 获取小程序源码  
  
获取小程序的源码比较简单，直接在微信-设置-文件管理-打开文件夹  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1TldUakGicgJYkm0LichPkhQHE5eChx7iaHfxMbSENVwKxwaSmZoFFcPwg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
会自动打开文件目录  
```
C:\Users\Administrator\Documents\WeChat Files\AppId
```  
  
这里我们需要跳到小程序的目录  
```
/WeChat Files/Applet/{wxid}/{n}/
```  
  
会看到一个__APP__.wxapkg，这个就是小程序的打包程序，需要对该文件进行解密，即可获取到小程序源码，解密脚本我使用的是https://github.com/zhuweiyou/wxapkg 直接把文件拖到exe程序的图标上便可以自动解密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1qHYylh8hUxDOZneDmV6fODGCImvnwBsyl5zw8h2JIOY4NKiaDicic7QmQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
解密后会在当前目录保存解包后的文件。  
## 开启Devtools  
  
强制开启Devtools我用的是https://github.com/JaveleyQAQ/WeChatOpenDevTools-Python这个项目。对应使用的微信版本是WeChatSetup-3.9.10.19 微信的历史版本可以在https://github.com/tom-snow/wechat-windows-versions/tags下载。这里需要注意一下的是，如果电脑上安装了高版本的微信，需要先卸载掉，再安装低版本，否则hook的时候会失败。并且hook有风险，建议使用小号在虚拟机里运行。程序的运行很简单，退出微信后执行  
```
WeChatOpenDevTools-Python.exe -all
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn16z9HRsrImjibFjIODx3qPam4ttFxfOEmBtv33x1UKyctsFck75eXH6w/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
会自动弹出微信，登录后打开小程序即可hook成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1HtHiauGFackcVTo6h1OLzAdkHCVA1X1trb6zPLj5WWPQiaK65mKgDLUA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1WZaaRRZ0RbYNRpUoTWnfhFNSgK3q2HpnwVPEjVY1jOjibgQJHhDB7OA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
## 小程序抓包  
  
小程序抓包我使用的是proxifier+burp  
  
在peoxifier中新建代理服务器，ip和端口对应burp的监听端口，协议选择https  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1vj3ZntSRwFERbFmr2PibalwJEwiaZEVnsefRicdVkMfd6PxaG12Klukrg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
然后新建代理规则。应用程序选择  
```
WeChatApp.exe;WechatBrowser.exe;WeChatAppEx.exe
```  
  
动作选择拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1HyDO4IiaBKKFwt9NPKjSntOFY6bCqBtiavpuyVOR0NgXjNGswdsVjmpw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
即可实现小程序的抓包  
## 自动计算签名  
  
前面的准备工作已经基本完成，可以实现对小程序的分析了，这个步骤并不是分析小程序所必须的步骤，只是在这个目标中，使用了sign值来校验数据包，所以我们在修改了数据包后，需要使用自动计算签名的脚本进行自动签名。自动签名我用的是mitmproxy，支持python代码编写，可控性高 下载地址：https://www.mitmproxy.org/ 使用方法如下：  
```
mitmdump -s xx.py -p 7777
```  
  
用于加载一个代理脚本，并监听7777端口，然后我们在burp中把数据包中转到7777端口，即可实现mitmproxy自动对数据包进行签名。burp设置如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1alT8DkLibnTJVqsqTe5D2yDFhWLKibrbWKBSEu9A2gxzPCkMn7zianECA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
然后再burp中发送数据包进行测试，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn172I6EHFB7Kp05Hnt9GNpzoibrGefzGT1EO7hc2x7Cz7M8H6yCgZNk0g/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
看到终端中有数据再跑了，说明配置成功， 这里需要特别说明一下，在使用编译好的exe程序运行python程序时，可能会出现ModuleNotFoundError: No module named 'Crypto'  
找不到库的情况，即使是最新版也有可能出现，这是一个bug，使用pip3重新安装mitmproxy即可解决  
```
pip3 install mitmproxy
```  
  
至此，准备工作完成，开始分析小程序  
# 代码分析  
## 数据包分析  
  
在小程序分析过程中，我喜欢先抓包，浏览一下大概功能并看一下数据包的接口，大部分的小程序都是host+api接口+uri接口的形式，我们直接看数据包，可以免去我们找host和api接口的步骤，直接拼接提取出来的url即可。这次的目标是一个客服系统，直接点进去小程序，提示没有对应的客服，然后一篇空白，什么功能都没有，那么看一下他的数据包，  
```
POST /wxapi/Customer/Acc HTTP/1.1
Host:
Content-Length:37
Wxversion:3.9.12
Mobilemodel: microsoft
Clientplatform: windows
Sdkversion:3.5.8
User-Agent:Mozilla/5.0(Windows NT 10.0;Win64; x64)AppleWebKit/537.36(KHTML, like Gecko)Chrome/122.0.0.0Safari/537.36MicroMessenger/7.0.20.1781(0x6700143B)NetType/WIFI MiniProgramEnv/WindowsWindowsWechat/WMPF WindowsWechat(0x63090c0f)XWEB/11275
Minprogram: v1.9.9
Content-Type: application/json
Xweb_xhr:1
X-App: mgwx
T:1728436146712
Systemversion:Windows7 x64
Sign:1e02db58edb4f1e0710f7d9b3da9e39d0af98ffe
Accept:*/*Sec-Fetch-Site: cross-siteSec-Fetch-Mode: corsSec-Fetch-Dest: emptyReferer: https://servicewechat.com/wxf7xxx/78/page-frame.htmlAccept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Connection: close{"UserID":"14979"}
```  
  
有个code，随便修改一下，提示鉴权失败，仔细观察数据包有个sign，那么很有可能就是利用的sign来校验数据包，我们需要分析一下sign的算法。  
## sign算法分析  
  
打开devtools 一般在appcontext下的no domain中存储的是小程序的js代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1ibKtpO8IE144E6udZSMUyYz3LCPlzBTQYpONucW3eIUNVOcFTMibMqow/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
分别打开这几个js，查找sign关键字 定位到这个地方  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1Qeb6CQAmiaDL0ZraV4JZqc4l1p1RcoLrQHG22MCtSns1CsibtsLtADcA/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
两个处理逻辑，一个get的，一个其他，需要分别分析。先看get的，  
```
            var g =(newDate).getTime();
if(s.t= g,
"get"== r.toLowerCase()){
                s.requrl= n;
var c = n + t.globalData.key+ g
, m = e.SHA1(c).toString();
                s.sign= m
```  
  
n就是requrl， var g = (new Date).getTime();就是时间戳  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1ricwHs83SZ9JMy6SicaGGw8picHpSDHXwGkiaZiaUjgfdLD66p5yZG2rsdg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
还差一个t.globalData.key  
，全局搜索globalData  
。在32486行找到了key  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1Lqs6veuHcROCVdqV3CnCauiaSsf57ZWBOibv10hv8qIR2niaIR1AXaVHw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
将url+key+g拼接后进行sha1就得到了sign  
  
然后分析其他类型的sign计算  
```
 c = JSON.stringify(o) + t.globalData.key + g,
                m = e.SHA1(c).toString();
                s.sign = m
```  
  
get传的是url+key+g，而这个传的是json格式化之后的o，往上找o在哪里定义的，发现o是直接传参传进来的，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn10ZtrziaKK7y0EuscCoKdjkdPt89Xdq51FeqjfjEibxibG9Q8dtsmIl2icw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这样再往上去找函数调用的话不如动态调试来的方便，于是在32185行打上断点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1kiajic0Igo8xaP1MnJZPg09AxzicQKL97Hia8XvIA4lnnicLyFS0NUqAicicg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
找一个post功能的点，提交一下，便会停在断点上  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1pib7lAETsWL5UgWhJqUibUskwrkoxIr7JeNN6jO7n8LVicuibqhhbhCmjw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
这里便可以看到动态传进来的值，把拼接后的c复制出来：  
```
{"sessionId":"jS9NZxxx","encryptedData":"xxx","iv":"xxx"}tiixxx1728443242572
```  
  
和最后发出去的数据包对比一下，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1ZTib98S5xiaeH2IAPjNN2libuf1sNZx7H2BrhaM99WPickm9iaYFCVbIugg/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
很明显o是传入的data数据，至此sign的算法分析完毕，mitmproxy脚本也就直接可以写出来了，代码有点渣，能用就行  
```
import datetime  
import hashlib  
from mitmproxy import ctx  
import json  

# 获取当前时间  
now = datetime.datetime.now()

timestamp_ms_precise =int(now.timestamp()*1000)
key="tiihxxxx=="

defrequest(flow):
# 获取请求对象  
    request = flow.request  
# # 实例化输出类  
# info = ctx.log.info    # # 打印请求的url    # info(request.url)    # # 打印请求方法    # info(request.method)    # # 打印host头    # info(request.host)    # # 打印请求端口    # info(str(request.port))    # # 打印所有请求头部    # info(str(request.headers))    # # 打印cookie头    # info(str(request.cookies))  
if request.method =='POST':
        data=(request.get_text())
print(data)
        n=data  
#n = json.dumps(data).replace(": \"", ":\"")  
print(n)
        T =1728192063292
        c = n + key +str(T)
print(c)
        encoded_data = c.encode('utf-8')
# 创建一个sha1哈希对象  
        sha1 = hashlib.sha1()
# 更新哈希对象（可以多次调用update()来添加数据）  
        sha1.update(encoded\_data)
# 获取十六进制表示的哈希值  
        hex_digest = sha1.hexdigest()
Sign= hex_digest  
print(Sign)
        request.headers["Sign"]=Sign
        request.headers["T"]="1728192063292"
else:
        n=request.url  
print(n)
        T =1728208280365
        c=n + key +str(T)
print(c)
        encoded_data = c.encode('utf-8')
# 创建一个sha1哈希对象  
        sha1 = hashlib.sha1()
# 更新哈希对象（可以多次调用update()来添加数据）  
        sha1.update(encoded\_data)
# 获取十六进制表示的哈希值  
        hex_digest = sha1.hexdigest()
Sign= hex_digest  
print(Sign)
        request.headers["Sign"]=Sign
        request.headers["T"]="1728208280365"
        request.headers["Requrl"]= n
```  
## 接口分析（漏洞挖掘）  
  
解决了sign的校验问题，就开始分析程序接口了 在静态分析的源码中提取出来几十个接口，挨个进行测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1ia3WGEyic6yIHvIa2p2bbw9WZRaYjbjiaFPZicLroujSNpJAicZgXrQez1g/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
经过多次测试，发现该客服系统使用的websocket协议进行的聊天，抓到的数据包如下：  
```
GET /websocket?appId=mgb7xxx&token=juukgLAxxx&sdkVer=5.6.1&pid=&apiVer=normal&platform=MiniProgram&protocolVer=3 HTTP/1.1
Host: wsproxy.xxx.com
Connection:Upgrade
Pragma:no-cache
Cache-Control:no-cache
User-Agent:Mozilla/5.0(Windows NT 10.0;Win64; x64)AppleWebKit/537.36(KHTML, like Gecko)Chrome/107.0.0.0Safari/537.36MicroMessenger/7.0.20.1781(0x6700143B)NetType/WIFI MiniProgramEnv/WindowsWindowsWechat/WMPF WindowsWechat(0x63090a13) XWEB/8555
Upgrade: websocket
Origin: https://wsproxy.xxx.com
Sec-WebSocket-Version:13
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Sec-WebSocket-Key: Z7s5axxx==
```  
  
这个数据包之后就会直接从http协议切换到websocket协议，而这个数据包中的appId和token是由客户端直接发送给服务器的，所以这两个值要么是js计算出来的，要么是服务器返回的数据，先搜一下前端的js代码，发现appid是写死的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1YMUK32uIYQpE4yfbosGXyjsaXXibFSjUjia0d5RvZ6ZdBH8xEahPgprQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
token在js中没有相关算法，基本就可以确定是服务器返回的数据了，在burp的proxy history中搜索token字符串，看一下是哪个包返回的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1YTUibZlmgsLZGCjN0KR1h5cy1x0OSgkKAhrAdwRnhjZw8ybicjMVatkw/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
找到了接口，发送到repeater 尝试修改userid，发现仍然会返回token，说明这里没有身份验证，可直接接管任意用户的聊天会话。写个python利用websocket库切入websocket会话，成功接管会话内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYekdedxhoZOibIzr8Rb2bn1vsCsTV2SxBCL8gwmHcvw9vRwI9JZ8O4lNVIWtmqUnoCLxj1W03xZmQ/640?wx_fmt=png&from=appmsg "null")  
  
image.png  
  
至此漏洞已成。顺带补充一下src中客服聊天系统的危害描述：1、泄露客服与客户的聊天记录，能参与聊天的都是高意向客户，客户的购买意向、联系方式均属于核心商业机密，接管会话可循环遍历所有会话，窃取机密信息。2、websocket无身份验证，可冒充客服对客户发起钓鱼，极大的损害企业形象。  
  
最终，该漏洞给了严重。  
  
原文链接：https://forum.butian.net/share/3832  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  

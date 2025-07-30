#  利用Android WebView漏洞   
Max_hhg译  乌雲安全   2024-02-13 08:01  
  
什么是WebView？  
  
  
WebView类是Android的View类的扩展，允许您将网页显示为活动布局的一部分。它不包含完整开发的Web浏览器的任何功能，如导航控件或地址栏。默认情况下，WebView只是显示一个网页。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8xbmrdu9ktmI3KSZeAc16zic7YFQSTyEC59etWw5ktwLN1PTmnOy9h9w/640?wx_fmt=png&from=appmsg "")  
  
Twitter使用WebView加载网站。  
  
为了进行测试，我们将使用易受攻击的  
WebView应用程序（https://github.com/t4kemyh4nd/vulnwebview）  
来学习如何手动利用Android应用程序中的WebView漏洞。登录凭据是用户名：**vuln**和密码：**webview**（以防需要使用）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF89NoMtYYjwdjla9ThedmP4TJVIqhkYXrQjfYht1tbmgia8vCgVfMiaujA/640?wx_fmt=png&from=appmsg "")  
  
**易受攻击的WebView应用程序**  
##   
## WebViews是可导出的  
  
  
在介绍漏洞之前，我们需要确保WebView是我们目标应用程序的一部分。  
  
  
由于WebViews是应用程序中的活动的一部分，我们需要对apk进行反编译，查看AndroidManifest.xml文件和应用程序的Activity，以检查是否存在易受攻击的WebView。  
  
  
让我们首先将我们的应用程序加载到  
Jadx  
反编译器中，以分析清单和活动。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8UKWU9EfFQnhibnh4azHibMjogWOoKhLvfuZ9z3vvjiaZ28coicfrZvVnLg/640?wx_fmt=png&from=appmsg "")  
  
反编译工具  
  
  
现在，我们将查看哪些组件是**导出**的。  
  
  
我们可以得出结论，一个组件可以通过两种方式来导出：  
  
◆如果组件明确声明了“**exported=true**”属性；  
  
◆如果组件具有意图过滤器且没有“**exported=false**”属性。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8cZ6D6Knwqibicph2vNd2mPXb4icpibaIBKWCzQzakcyLqkkEAM9Z5T4JGQ/640?wx_fmt=png&from=appmsg "")  
  
activities exported  
  
一些组件如**SupportWebView**、**RegistrationWebView**被明确导出，而**MainActivity**是通过指定意图过滤器来导出的，这表明该应用程序正在使用WebViews。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF82fyjCwt3MrBicIq4mciaxE6yicCuOibvkzSuV0DNqv3gBj3aaaAvgqzfUA/640?wx_fmt=png&from=appmsg "")  
  
confirming with  
  
我们可以看到loadWebView函数，它通过从intent中获取字符串来加载URL。![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8IVeDhbdhL3hZy3L5M23sJRYCxo8iaoYuF5PXKicWVolwx3fYeuWJ7fKg/640?wx_fmt=png&from=appmsg "")  
  
webview code  
  
因此，第三方应用程序可以通过向该组件发送带有URL字符串的意图来利用这种行为，而目标应用程序将接受并执行该意图，因为该组件已被导出。也就是说，第三方应用程序可以访问目标应用程序中的WebView组件。  
  
## 利用  
  
  
我们将使用ADB发送一个意图到该组件，这个intent将在应用程序的上下文中打开攻击者提供的恶意网页。  
  
  
```
```  
  
  
  
使用adb shell在设备上启动唯一的shell，使用am（活动管理器）start命令，-n参数指定组件名称，--es参数后跟URL作为额外的字符串。  
  
  
因此，我们的adb命令将如下所示：  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8ozvbyWyO3xJQJNicia5zSicZJBlfGE1L5x7EveVhTrW4u5zsE6j49QTWA/640?wx_fmt=png&from=appmsg "")  
  
发送intent到webviews  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8o4uvdZz3AS6gqiabHUdGibcMsWOxX8YNpr3vrekVAzVOqpZQQ3yVdRog/640?wx_fmt=png&from=appmsg "")  
  
webview加载了攻击者的url  
##   
## 为webview启用setAllowUniversalAccessFromFileURLs  
  
  
开发人员可以配置的另一个设置是允许在文件方案URL的上下文中运行的JavaScript访问来自任何源的内容，包括其他文件方案URL。  
  
  
该设置会移除所有同源策略的限制，允许WebView从文件中向Web发出请求，这通常是不可能的。也就是说，攻击者可以使用JavaScript读取本地文件，并将其发送到攻击者控制的域名上。  
  
  
如果WebView被导出，这种行为可能非常危险，因为它可以允许攻击者读取可能对应用程序来说是私有的任意文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF89ibNqxyhRZ9FlMMoibOxE7aliaXjgbOFSefiabUNt1yzCNlW154vXtxfDg/640?wx_fmt=png&from=appmsg "")  
  
setAllowUniversalAccessFromFileURLs  
##   
## 利用  
  
  
现在让我们看看如何利用上述应用程序中使用的这个设置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8JiciaSsicGWKxwjGptn09FELS7U06eI7ayqxxnx2rrur506F5uVC5298w/640?wx_fmt=png&from=appmsg "")  
  
  
现在，让我们为漏洞中讨论的JavaScript漏洞创建利用程序。  
  
  
我已经使用了我的Burp Collaborator链接来获取内容，您可以使用您方便的任何链接。  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8CdmX1MfHFDMN8L0Mq1b4O4JcQfGyWOR8LmWTEtlDfUyjoaJbHkMtVw/640?wx_fmt=png&from=appmsg "")  
  
任意文件读取漏洞  
  
请将上述代码添加到sauafu.html文件中，并使用adb将该文件移动到sdcard。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8nxdtp5f3icUTzuL4MOq7EticF9m4CNySib5yNQDRuPS3FH68icB8mdNwsA/640?wx_fmt=png&from=appmsg "")  
  
将exploit推入设备  
  
利用程序加载本地文件的内容并将其返回给攻击者的URL。  
  
  
现在运行带有利用文件的intent。  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8cD1o0TWiaFnM0ye6N1xHOFK5gUXxafYN7Ru7jToshEEpwsRzH7NRnPg/640?wx_fmt=png&from=appmsg "")  
  
intent启动  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8nqMCRwgdsHBXfwChkRKe2IxAjt20wFclxiase3pznf1IDXczcxPIztQ/640?wx_fmt=png&from=appmsg "")  
  
空注册页面  
  
现在我们应该已经在Burp Collaborator或您使用的其他工具中收到了以Base64编码的文件内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8KHc451HZibDKqeCAYEYzewdO4aePsRkq7oN9pjrh46MPE7JiaUwxAQdQ/640?wx_fmt=png&from=appmsg "")  
  
利用poc  
  
我们可以在右侧窗口框中看到以Base64编码接收到的文件内容的解码结果。  
  
## 启用JavaScript并为WebView提供接口  
  
  
开发人员可以通过添加此配置来启用WebView中的JavaScript。  
  
  
```
```  
  
  
  
添加此配置将在网页的JavaScript和应用程序的客户端Java代码之间创建一个接口。也就是说，网页的JavaScript可以访问和注入应用程序的Java代码。  
  
  
```
```  
  
  
  
如果这个活动被导出，那么这可能是危险的，允许攻击者进行许多攻击，包括XSS攻击和从应用程序中窃取令牌。  
  
  
**利用**  
  
  
针对这种情况的利用，我们不能使用上述相同的WebView，因为它没有使用接口。因此，我们将使用另一个使用了接口的WebView。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8t4sM6k86RMjx8lUYJyzEf9pTPH0XuvH5OJujmqUV0rlH5rtqsJJqDw/640?wx_fmt=png&from=appmsg "")  
  
support webview  
  
我们可以使用SupportWebView，您可以看到JavaScript已启用，并且使用了名为"**Android**"的接口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF80Pm7dUic64ZZPB1ibckyRUhXX8r7icmIlv8757FHTKRTrgTZIuPo5R44Q/640?wx_fmt=png&from=appmsg "")  
  
接口声明  
  
  
```
```  
  
  
  
该脚本通过从名为**Android**的接口中的getUserToken()方法生成令牌并将其写入。  
  
  
从Apache服务器托管此脚本，并将端口80连接到ngrok以获取HTTPS链接（不能使用HTTP链接）。  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8zp97xub8icOrX8qQgSF5qjh2vpwKljicrQR7tyTC3EJqQPLRjhanQzYA/640?wx_fmt=png&from=appmsg "")  
  
intent  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8nfEOzzj3247cuzE0WYIGWWUdnEoBOTEM2ZUtfgR313wVdY6hGhjBhQ/640?wx_fmt=png&from=appmsg "")  
  
token窃取  
  
我们可以通过替换文档来显示XSS警报，用您喜欢的XSS有效负载在上面的javascript代码中编写一行代码。  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8rHdoZSnod34UaV9VS2w69KHmvyib1jFiarvklsqYPjwpVAJHx2rUoE1Q/640?wx_fmt=png&from=appmsg "")  
  
XSS Alert.  
  
我们已经涵盖了与WebViews相关的4个漏洞：  
  
◆导出的WebView（WebView劫持）  
  
◆启用WebView的文件访问（文件窃取）  
  
◆使用setJavaScriptEnabled（XSS）  
  
◆JavaScript接口（令牌窃取）  
  
  
原文地址：  
https://medium.com/mobis3c/exploiting-android-webview-vulnerabilities-e2bcff780892  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GstpDu7iaH5qk61bgepbXF8Wn83HbuOYiaOzxlDCMcaC8uyERibq4tx8zCV6U8voj3YKkKrzZGicbKNA/640?wx_fmt=png&from=appmsg "")  
  
  
**看雪ID：Max_hhg**  
  
https://bbs.kanxue.com/user-home-876202.htm  
  
*本文为看雪论坛优秀文章，由 Max_hhg 翻译，转载请注明来自看雪社区  
  
**扫码加入免费知识星球**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/bMyibjv83iavz4HGqCKLjLNTvZDP4lOhNJzhHqZFxwpzjOYKFVYRbXqjJY6Hqibuk0C7LQlFW32aASG5r41BuaPCg/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  

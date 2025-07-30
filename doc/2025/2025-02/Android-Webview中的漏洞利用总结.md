#  Android-Webview中的漏洞利用总结   
NEURON  SAINTSEC   2025-02-17 02:00  
  
```
```  
  
  
**什么是 WebView？**  
  
Android内置webkit内核的高性能浏览器,而WebView则是在这个基础上进行封装后的一个 控件,  
WebView直译网页视图,我们可以简单的看作一个可以嵌套到界面上的一个浏览器控件。  
也就是说，我们可以直接在app中拉起一个网页，这样方便快捷，同时也可以减少开  
发量，当然也会  
存在安全问题。  
  
**webview的使用方式**  
```
```  
  
我们使用下面这段代码来启动一个网页：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRibLwfpa66Q37sRxgYKrXj5NvlyMcmSJRrfzqN1lAGLynibXrm02yFBOPVeRCeFJ7RlBMjYxnzYYdQ/640?wx_fmt=png "")  
  
  
  
**WebView 白名单绕过**  
  
要使用webview加载资源，那么总会有一些要过滤的情况，如果校验不完整，则会导致加载恶意的资源。  
  
在这之前，我们先来看一下URL的格式和URi的一些接口。  
```
```  
  
**常见的校验方式与绕过方式**  
```
```  
  
前两个很容易理解，简单说一下第三个和第四个绕过方式。  
  
第三个：在上面我们说了getAuthority获取的是<user>:<password>@<host>:<port>这一部分,如果网站没有user，password的校验，则这一部分会被忽略，写与不写不影响网站访问。所以我们将校验的关键词写在这一部分就可以绕过了。  
  
第四个：因为这一校验方式中存在.com，所以不容易绕过，但是我们仍然可以申请一个新的域名，只要包含或者以baidu.com结尾就可以绕过了。  
  
更多有趣的绕过可以参考：《一文彻底搞懂安卓WebView白名单校验》。  
  
  
**通过 XSS 窃取 Cookie**  
  
在app中加载exp.html：  
```
```  
  
在Android中，使用WebView加载网站时，当在网站停留20~40秒时，网站的Cookie就会保存在/data/data/com.example.test/app_webview/Cookies文件下。  
  
而下面这段代码可以将整个exp.html的内容发送到指定的地址：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRibLwfpa66Q37sRxgYKrXj5c6N5JDXVktCQBHEicAnr0xR1wGjbSiaIrjhw8vts65r1jmClZXtFN7YQ/640?wx_fmt=png "")  
  
假如我们把这段代码插入到Cookies文件中，并且让这段xss执行，那么就可以将Cookies文件中的所有数据都拿到。  
  
由此得出两个问题：  
```
```  
  
我们先保留问题，继续往下看，进入漏洞复现环节。  
  
  
**漏洞利用**  
  
我们使用ByteCtf中的easydroid题目案例进行讲解。  
  
MainActivity中的代码:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRibLwfpa66Q37sRxgYKrXj5xorBTVhHtx71ibfgDPs4WsVa4uPibOx9EQdzPOPFI9AS41ibNnbbwepAA/640?wx_fmt=png "")  
  
可以得到信息：加载网站，对URL进行校验，可以执行JavaScript。  
  
**shouldOverrideUrlLoading接口**  
  
该接口主要是给WebView提供时机，可以拦截URL做一些其他操作。  
  
该接口的返回值是关键，True（拦截WebView加载Url，选择浏览器打开），False（允许WebView直接加载Url）  
  
在这里是对URL进行拦截并解析，然后使用startActivity来启动Intent。  
  
TestActivity中的代码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRibLwfpa66Q37sRxgYKrXj5eOTxDGIlWmN5iaYvjAuxo5vEmJBWAonfOHsnuBz3WMNjcjZZbKPRmpA/640?wx_fmt=png "")  
  
获取数据，使用webview加载。  
  
代码很简短，我们整理思路，来理清攻击链。  
```
```  
  
理清思路后，我们来看一下攻击代码：  
```
```  
  
整个漏洞利用流程：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRibLwfpa66Q37sRxgYKrXj5MDnYyBN2vsxKCO5zcibwcbt3dzDYtJiaBSN3F15jHnJbvRUVuW9ckfhQ/640?wx_fmt=png "")  
  
首先创建了符号链接，然后过URL校验，访问我们的服务器http://192.168.43.164/easydroid.html:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRibLwfpa66Q37sRxgYKrXj5ggLTD53rqkZxVGpAnFKeibvtIqV7JaSCRI70GH1kb8FbOEWpFrHicgHQ/640?wx_fmt=png "")  
  
通过Intent重定向，首先加载exp.html来设置cookie，然后再加载symlink.html，将所要Cookies内容返回给我们的服务器。最终达到窃取Cookies的目的。注意，这里要保证setAllowFileAccess(true)，API 29以下默认为true，否则会利用失败。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRibLwfpa66Q37sRxgYKrXj5hML4yyGOwGicc3l1CgCOYBPkQvlu8kibp7AwM6qgtuuUMAOGMMZtlwKw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRibLwfpa66Q37sRxgYKrXj5N4xnKGFzormVYTXuBpVNBDyYnVvOicyZJhmB4Eibx2ob2TCiak2iccQJrQ/640?wx_fmt=png "")  
  
  
  

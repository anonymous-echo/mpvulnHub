#  如何使用AI进行漏洞挖掘？完结！   
原创 _7ingLian  偏远酒馆   2025-02-14 06:54  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpYmfRrkHqtZOoLY55mXZWJ16u05arbB1jib4WwY60DN8u3RHWfgYZ3SsSfawBzxkwzjPyb1WibH0og/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
往期文章：  
  
[如何用AI进行漏洞挖掘(一)](https://mp.weixin.qq.com/s?__biz=MzkwMDMwNDgwNQ==&mid=2247485465&idx=1&sn=b348ed780a826686146d0f3c31972d62&scene=21#wechat_redirect)  
  
  
[如何用AI进行漏洞挖掘(二)](https://mp.weixin.qq.com/s?__biz=MzkwMDMwNDgwNQ==&mid=2247485642&idx=1&sn=317337ad87d8d251fcf5450748bf9ba8&scene=21#wechat_redirect)  
  
  
  
--->目录<---  
  
0x01——前言  
  
0x02——  
使用**AI进行漏洞挖掘的思路**  
  
0x03——  
编写burp插件  
  
0x04——  
burp数据包传给AI进行分析  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span textstyle="" style="background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">0x01、</span></span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 0.544px;text-decoration: none solid rgb(255, 255, 255);visibility: visible;"><span leaf=""><span textstyle="" style="background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">前言</span></span></span></span></strong></span></strong></span></td></tr></tbody></table>  
--->  
目前漏洞挖掘方向的AI交互开发已经接近完成。后面只剩一些调整与优化。  
  
关于本次的开发的目的，主要是为了提升渗透测试的效率。  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">0x02、</span><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);font-weight: bold;">使用</span></span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">AI进行漏洞挖掘的思路</span></span></strong></strong></section></td></tr></tbody></table>  
  
--->  
  
**我这里是有三个页面(三个功能)：**  
  
**1.对单个代码文件的分析；**  
  
**2.对整个框架文件夹的分析；**  
  
**3.对接burp，实时分析数据包，找出漏洞。**  
  
****  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">0x03、</span><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);font-weight: bold;">编写burp插件</span></span></section></td></tr></tbody></table>  
  
--->  
  
这里burp插件的功能很简单，它只负责将HTTP history的数据包保存到指定的文件夹。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpicVsNNtJHsU2T1Rps7WScN0CYDf2ic10YFvbk9gJXoceYOSiccmwW8HRnZicZ864ibiaPojU3mHYW1KIQ/640?wx_fmt=png&from=appmsg "")  
  
使用的时候注意过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpicVsNNtJHsU2T1Rps7WScN7oqZTIS91192ZIv41yiaBGaR0sXic4Jgbs2mJztHKkiaVm43Ryg3B9ySA/640?wx_fmt=png&from=appmsg "")  
  
本插件的兼容版本是Jython 2.7.x  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpicVsNNtJHsU2T1Rps7WScNiat5lCqMXiarkwib3XSqw0aibmqGVwoDjI1ic8Ulof1hibhVbCMMVSFzK9bg/640?wx_fmt=png&from=appmsg "")  
  
插件源码，可根据自身情况自行修改：  
```
# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IHttpListener
from java.io import File
from java.text import SimpleDateFormat
from java.util import Date
import time
import hashlib
import urlparse

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("Auto Save HTTP History with In-Scope Filter")
        callbacks.registerHttpListener(self)

        self.save_directory = File("Z:/burp_history_xmls/")
        if not self.save_directory.exists():
            self.save_directory.mkdirs()

        self.saved_requests = set()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.isInScope(messageInfo):
            return

        request = messageInfo.getRequest()
        response = messageInfo.getResponse()

        status_code = self.getStatusCode(response)

        request_hash = self.getRequestHash(request)

        if request_hash in self.saved_requests:
            return
        else:
            self.saved_requests.add(request_hash)

        timestamp = self.getTimestamp()

        file_name = "response_" + timestamp + "_status_" + str(status_code) + ".txt"
        file_path = File(self.save_directory, file_name)

        with open(file_path.getAbsolutePath(), "wb") as file:
            file.write(request)
            file.write(b"\r\n\r\n")
            file.write(response)

    def getTimestamp(self):
        current_time = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
        return current_time

    def isInScope(self, messageInfo):
        return self.callbacks.isInScope(messageInfo.getUrl())

    def getStatusCode(self, response):
        if response is None:
            return None
        response_headers = self.callbacks.getHelpers().analyzeResponse(response).getHeaders()
        if response_headers:
            status_line = response_headers[0]
            status_code = status_line.split(" ")[1]
            return status_code
        return None

    def getRequestHash(self, request):
        return hashlib.sha256(request).hexdigest()

```  
  
数据包存储路径自行修改：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpicVsNNtJHsU2T1Rps7WScN47dSqaKwmEw8xV1Vo3icrnX1GDFBzoZAm0tcyTotqRAiaxOry97qds3A/640?wx_fmt=png&from=appmsg "")  
  
插件加载，插件加载成功没有成功提示，没报错那就是成功(-.-)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpicVsNNtJHsU2T1Rps7WScNcGOP4V3ibwXcnEfJDx2LuAPJ716Iz8YkDHsbe77yE4kNJ1tZvznmbQg/640?wx_fmt=png&from=appmsg "")  
  
效果如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpicVsNNtJHsU2T1Rps7WScNWdAUJfpznHBcWMMW3NKglJdMF6MxTsOYJ7QrFhicMOymUDS7UFibv26g/640?wx_fmt=png&from=appmsg "")  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">0x04、</span><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);font-weight: bold;">burp数据包传给AI进行分析</span></span></section></td></tr></tbody></table>  
  
--->  
  
当burp有新数据包更新后，插件都会实时保存到指定目录，当AI大模型检测到有数据包更新时，会自动进行分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpicVsNNtJHsU2T1Rps7WScNApp9MgGeH8CPyugEr6c7JOjfqLD7vJSO2Ky8tT1s0AvRgY975dke6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpicVsNNtJHsU2T1Rps7WScNTyiayeO7ZPFiclvra4oiaVUTHYruPQ1hw0xvVqOx2ibrrCl5WOazQ639fQ/640?wx_fmt=png&from=appmsg "")  
  
end  
  

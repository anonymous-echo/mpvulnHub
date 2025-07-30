#  发包工具大升级：poc   
WaY  Yak Project   2023-07-27 17:36  
  
****  
**在近期，我们对poc标准库进行了一波升级，在保留了原来功能的基础上，新增了许多有用功能，现在牛牛带着大家一起来看看。**  
****  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnkqgz7oRUB4Q6yGbofrQJAYax3jtA875e2fVFcChGGMuib2ibyAiajVvLNEDfVlz4iaCiaPyE4UktGX1Nn38Ra2QIA/640?wx_fmt=png "")  
  
允许更广泛的输入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DN1y5bx3tA0fvOsWiaE4KCpicGDGvK8CZjpoaqjhp6iaa7NZM1udzQnqicbKp2mVyk6R0CSpHvBO1D8ROYhm64mYgQ/640?wx_fmt=png "")  
  
  
在之前，**poc.HTTP**  
的第一个参数是  
**[ ]byte**  
，也就意味着我们没法直接把一个构造好的请求结构体直接发出，但是在升级之后，我们就可以这么做了：  
```
preq = http.NewRequest("GET", "https://pie.dev/get")~
rsp, req = poc.HTTP(preq)~
printf("%s", rsp)
```  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnkqgz7oRUB4Q6yGbofrQJAYax3jtA875e2fVFcChGGMuib2ibyAiajVvLNEDfVlz4iaCiaPyE4UktGX1Nn38Ra2QIA/640?wx_fmt=png "")  
  
poc.BuildReqeust  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DN1y5bx3tA0fvOsWiaE4KCpicGDGvK8CZjpoaqjhp6iaa7NZM1udzQnqicbKp2mVyk6R0CSpHvBO1D8ROYhm64mYgQ/640?wx_fmt=png "")  
  
  
这是poc标准库新增的一个工具函数，经常在构建请求时使用，一个简单的例子如下：  
```
packet = `GET /post HTTP/1.1Host: pie.dev`
// 修改请求方法为POST，并添加body
packet = poc.BuildRequest(packet, poc.replaceMethod("POST"), poc.replaceBody('a=1&b=2', false))
```  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnkqgz7oRUB4Q6yGbofrQJAYax3jtA875e2fVFcChGGMuib2ibyAiajVvLNEDfVlz4iaCiaPyE4UktGX1Nn38Ra2QIA/640?wx_fmt=png "")  
  
## poc.HTTPEx  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DN1y5bx3tA0fvOsWiaE4KCpicGDGvK8CZjpoaqjhp6iaa7NZM1udzQnqicbKp2mVyk6R0CSpHvBO1D8ROYhm64mYgQ/640?wx_fmt=png "")  
  
  
在以前，我们使用  
**poc.HTTP**  
时返回三个值**：**  
**responseRaw, requestRaw, error**  
，也就是原始响应报文，原始请求报文和错误，这在某些情况下是不够用的，我们可能还需要更多的信息，比如：服务器响应时间，服务器的URL...  
  
发现了这个缺陷之后，我们为poc标准库添加了一个新的函数：  
**poc.HTTPEx**  
，这个函数的参数与原有的  
**poc.HTTP**  
一样，但是返回值不一样：  
***Response, *Request, error**  
，也即是响应结构体，请求结构体和错误，通过返回结构体，我们可以获取到这次请求的更多信息。  
  
举一个简单的例子，响应结构体的结构如下：  
```
type LowhttpResponse struct {
 RawPacket          []byte
 RedirectRawPackets [][]byte
 PortIsOpen         bool
 TraceInfo          *LowhttpTraceInfo
 Url                string
 RemoteAddr         string
 Proxy              string
 Https              bool
 Http2              bool
 RawRequest         []byte
 Source             string
 RuntimeId          string
 FromPlugin         string
}

```  
  
想要拿到原始响应报文，我们只需要访问  
**response.RawPacket**  
即可，同时，我们也可以通过访问  
**response.RedirectRawPackets**  
追踪重定向期间的所有响应报文，访问  
**response.TraceInfo.GetServerDurationMS()**  
获得服务器响应时间（连接建立到客户端收到第一个字节的时间间隔）。  
  
更多的结构体信息可以通过查看yaklang源码或者使用  
**desc(response)**  
来获得。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnkqgz7oRUB4Q6yGbofrQJAYax3jtA875e2fVFcChGGMuib2ibyAiajVvLNEDfVlz4iaCiaPyE4UktGX1Nn38Ra2QIA/640?wx_fmt=png "")  
  
Packet Helper  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DN1y5bx3tA0fvOsWiaE4KCpicGDGvK8CZjpoaqjhp6iaa7NZM1udzQnqicbKp2mVyk6R0CSpHvBO1D8ROYhm64mYgQ/640?wx_fmt=png "")  
  
```
// 新提供的Packet Helper
poc.ReplaceHTTPPacketMethod
poc.ReplaceHTTPPacketFirstLine
poc.ReplaceHTTPPacketHeader
poc.ReplaceHTTPPacketBody
poc.ReplaceHTTPPacketCookie
poc.ReplaceHTTPPacketHost
poc.ReplaceHTTPPacketBasicAuth
poc.ReplaceAllHTTPPacketQueryParams
poc.ReplaceAllHTTPPacketPostParams
poc.ReplaceHTTPPacketQueryParam
poc.ReplaceHTTPPacketPostParam
poc.ReplaceHTTPPacketPath
poc.AppendHTTPPacketHeader
poc.AppendHTTPPacketCookie
poc.AppendHTTPPacketQueryParam
poc.AppendHTTPPacketPostParam
poc.AppendHTTPPacketPath
poc.AppendHTTPPacketFormEncoded
poc.AppendHTTPPacketUploadFile
poc.DeleteHTTPPacketHeader
poc.DeleteHTTPPacketCookie
poc.DeleteHTTPPacketQueryParam
poc.DeleteHTTPPacketPostParam
poc.DeleteHTTPPacketForm

// 可用于poc options的Packet Helper
poc.replaceFirstLine
poc.replaceMethod
poc.replaceHeader
poc.replaceHost
poc.replaceBasicAuth
poc.replaceCookie
poc.replaceBody
poc.replaceAllQueryParams
poc.replaceAllPostParams
poc.replaceQueryParam
poc.replacePostParam
poc.replacePath
poc.appendHeader
poc.appendCookie
poc.appendQueryParam
poc.appendPostParam
poc.appendPath
poc.appendFormEncoded
poc.appendUploadFile
poc.deleteHeader
poc.deleteCookie
poc.deleteQueryParam
poc.deletePostParam
poc.deleteForm

```  
### 1、修改请求方法  
```
// 将请求方法改为POST，并增加body
rsp, req = poc.HTTP(`GET /post HTTP/1.1Host: pie.dev`, poc.replaceMethod("POST"), poc.replaceBody('a=1&b=2', false))~
printf("%s", rsp)

```  
### 2、修改path  
```
// 将path改为get
rsp, req = poc.HTTP(`GET /post HTTP/1.1Host: pie.dev`, poc.replacePath("/get"))~
printf("%s", rsp)

```  
### 3、修改Host  
```
// 将Host改为pie.dev
rsp, req = poc.HTTP(`GET /get HTTP/1.1Host: baidu.com`, poc.replaceHost("pie.dev"))~
printf("%s", rsp)

```  
### 4、修改所有GET参数  
```
rsp, req = poc.HTTP(`GET /get?a=1&b=2 HTTP/1.1Host: pie.dev`, poc.replaceAllQueryParams({"a":"3", "b":"4"}))~
printf("%s", rsp)

```  
### 5、增加一个form表单，上传文件  
```
// 新增一个form，上传文件，poc.appendUploadFile 第一个参数为fieldName，第二个参数为fileName，第三个参数为文件内容，第四个参数为contentType
rsp, req = poc.HTTP(`POST /post HTTP/1.1Host: pie.devContent-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW------WebKitFormBoundary7MA4YWxkTrZu0gWContent-Disposition: form-data; name="submit"true------WebKitFormBoundary7MA4YWxkTrZu0gW--`, poc.appendUploadFile("file", "upload.php", "<?php phpinfo();?>", "image/png"))~
printf("%s", rsp)
```  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnkqgz7oRUB4Q6yGbofrQJAYax3jtA875e2fVFcChGGMuib2ibyAiajVvLNEDfVlz4iaCiaPyE4UktGX1Nn38Ra2QIA/640?wx_fmt=png "")  
  
获取报文信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DN1y5bx3tA0fvOsWiaE4KCpicGDGvK8CZjpoaqjhp6iaa7NZM1udzQnqicbKp2mVyk6R0CSpHvBO1D8ROYhm64mYgQ/640?wx_fmt=png "")  
  
  
poc标准库提供的新函数也可以用于获取请求/响应报文信息。  
```
poc.GetAllHTTPPacketQueryParams
poc.GetAllHTTPPacketPostParams
poc.GetHTTPPacketQueryParam
poc.GetHTTPPacketPostParam
poc.GetHTTPPacketCookieValues
poc.GetHTTPPacketCookieFirst
poc.GetHTTPPacketCookie
poc.GetHTTPPacketContentType
poc.GetHTTPPacketCookies
poc.GetHTTPPacketCookiesFull
poc.GetHTTPPacketHeaders
poc.GetHTTPPacketHeadersFull
poc.GetHTTPPacketHeader
poc.GetHTTPPacketBody
poc.GetHTTPPacketFirstLine
poc.GetStatusCodeFromResponse

```  
### 1、获取所有请求参数  
```
packet = `GET /get?a=1&b=2 HTTP/1.1Host: pie.dev`
dump(poc.GetAllHTTPPacketQueryParams(packet))
/*(map[string]string) (len=2) { (string) (len=1) "b": (string) (len=1) "2", (string) (len=1) "a": (string) (len=1) "1"}*/

```  
### 2、获取所有请求头  
```
packet = `POST /post HTTP/1.1Host: pie.devContent-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW------WebKitFormBoundary7MA4YWxkTrZu0gWContent-Disposition: form-data; name="submit"true------WebKitFormBoundary7MA4YWxkTrZu0gW--`
dump(poc.GetHTTPPacketHeaders(packet))
/*(map[string]string) (len=2) { (string) (len=12) "Content-Type": (string) (len=67) "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW", (string) (len=4) "Host": (string) (len=7) "pie.dev"}*/

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnkqgz7oRUB4Q6yGbofrQJAYax3jtA875e2fVFcChGGMuib2ibyAiajVvLNEDfVlz4iaCiaPyE4UktGX1Nn38Ra2QIA/640?wx_fmt=png "")  
  
使用场景  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DN1y5bx3tA0fvOsWiaE4KCpicGDGvK8CZjpoaqjhp6iaa7NZM1udzQnqicbKp2mVyk6R0CSpHvBO1D8ROYhm64mYgQ/640?wx_fmt=png "")  
  
  
修改后的poc标准库可以支持更多场景，最常见的一个莫过于是热加载的时候了，例如对每个webfuzzer发出的请求都增加一个请求头（在热加载代码中写入）：  
```
beforeRequest= func(origin) {
    origin = poc.BuildRequest(origin, 
                              poc.appendHeader("CustomHeader", "111"),
                              poc.appendHeader("CustomHeader2", "222"),
    )
    return origin
}
```  
  
  
YAK官方资源  
  
  
YAK 语言官方教程：  
https://yaklang.com/docs/intro/Yakit 视频教程：  
https://space.bilibili.com/437503777Github下载地址：  
https://github.com/yaklang/yakitYakit官网下载地址：  
https://yaklang.com/Yakit安装文档：  
https://yaklang.com/products/download_and_installYakit使用文档：  
https://yaklang.com/products/intro/常见问题速查：  
https://yaklang.com/products/FAQ  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZc6nLOagqic2nNou7bAeMlkj1CKwGWMGSiaeBCN9r5JBz87nQDSDFyRsPhWia09n3icgcNQicS7bK3qv8Q/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
长按识别添加工作人员  
  
开启Yakit进阶之旅  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZd5I4ODHXemJjyvkNsibDkHnZ8vdsyzNdD4cHMUrxkHvibUAibvLpJPHGhYWXSKS1iciaib4ETGibYG8tagw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  

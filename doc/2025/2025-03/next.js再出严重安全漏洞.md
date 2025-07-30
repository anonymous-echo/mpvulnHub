#  next.js再出严重安全漏洞   
原创 pippybear  安全无界   2025-03-25 23:12  
  
受影响资产  
  
    依赖next.js进行身份验证或安全检查的应用程序。  
  
漏洞利用方式  
  
该漏洞可通过添加  
x-middleware-subrequest: middleware  
标头来绕过  
 Next.js 的  
身份验证检查。  
  
漏洞编号  
  
CVE-2025-29927  
  
漏洞原理  
  
这里稍稍引用大佬的原文内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gQeIUpJ33ahELVn3EV5yrUXXR9XTX7VkWIWJQNDKmFGghd5DRibibYIIgGT5iao9RnbpZV4qGORqSQkg/640?wx_fmt=png&from=appmsg "")  
  
主要的漏洞原因就是这段标圈的代码会取  
header  
头  
x-middleware-subrequest  
的值，然后使用  
:  
进行分割，最后问题在于只要校验这个请求头内容里面包含  
middlewareInfo.name  
就无视next.js的认证直接  
bypass  
。  
  
这里的  
middlewareInfo.name  
即中间件所在的路径。  
  
在  
12.2  
版本之前，中间件文件的命名为  
_middleware.ts，  
在之后的版本则为  
middleware.ts  
，因此可能的  
payload  
包含：  
```
x-middleware-subrequest: pages/_middleware
x-middleware-subrequest: middleware
x-middleware-subrequest: src/middleware
......
```  
  
而在较新的版本中，代码逻辑相比之前稍稍有些许变化，看以下这段  
代码  
，可以看到需要进行  
5  
次分割。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gQeIUpJ33ahELVn3EV5yrUXVgks0E1Jo8q1ZhRRWD0zVprS4veHKm8JC8ZwtJlGSOULbIs9okskzw/640?wx_fmt=png&from=appmsg "")  
  
因此在较新版本里面  
payload  
为:  
```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware
.....
```  
  
漏洞复现  
  
如下，内部刚好有一个使用next.js进行身份验证的应用，直接访问可以看到，无法认证，授权不通过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gQeIUpJ33ahELVn3EV5yrUXvsGZRp5icicGwS1Ff0FUNeT3bia6ic7UM5L4UTiazyiawbmDpoSwkfnP7spQ/640?wx_fmt=png&from=appmsg "")  
  
使用payload绕过认证，如下，直接访问认证后的应用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ib9b5DLqe7gQeIUpJ33ahELVn3EV5yrUXxBWFCYCqiaRFhDaDdiafT1ibStvGPDT3vfoualHia9n0laglMGVDkRnXRA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  

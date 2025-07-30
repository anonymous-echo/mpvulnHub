#  实战 | 记一次无聊闲逛到某设备RCE   
原创 Conan  小黑说安全   2024-05-09 06:00  
  
## 0x01 前言  
##   
  
无聊刷吐司，看到一个投稿文章，不让看，但可以看到fofa语句。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKEUYWMFALPKHWbMkEo5ZpkwqK2wK46hQq6bKMHFFcLLN7ruUj5t47Jg/640?wx_fmt=png&from=appmsg "")  
## 0x02 漏洞分析       
  
小挖一下，  
很快黑盒到任意文件读取，但黑哥说不是前台rce都不算洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKvLTyRjOnfM6iaiaYQfjEtMI3kib1ZdE15ibx3dfIomRlicElKwo1UaeYnIg/640?wx_fmt=png&from=appmsg "")  
  
扩大利用，读了一堆乱七八糟，都没啥用。  
设  
备的后台管理是thinkphp没有rce，  
想获取web绝对路径，跑了web日志，各种尝试报错都不行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKpvmqIeYqGSELd80j0jm5s7ys216msRnficqkTbnIZsMmU5bnYVWnlFQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmK7oLrQTcQaJPNToiasYWwpgY41GNfEZFiaCTSdLxKWLlxgicicZkuQeRa5g/640?wx_fmt=png&from=appmsg "")  
  
最后看到响应头是lighttpd。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKjUxHRdTG5qyZQfXUC6VDEA4kmhXMFDkXn1oibKnuoowmh2mouosCrLA/640?wx_fmt=png&from=appmsg "")  
  
简单一百度。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKg3ibeZFWpiaOtv06tMvqewXdpOlH45CVLeGHeMsoFJFjusOz88cjGcQA/640?wx_fmt=png&from=appmsg "")  
  
原来是/etc/lighttpd/lighttpd.conf，读之。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKva3awebiadWJjx80mBu5K4VomH5hUkricNGLibwlXVYYgcxDmGylUialtA/640?wx_fmt=png&from=appmsg "")  
  
拿到web路径 /usr/local/boa/www/，  
期间读了thinkphp的dat  
abase.php，全网没有对外开放的mysql，  
application下读了一点啥用也没有，不多bb了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKwWKk0EaXbqIngaeHDibWhibCybzqicVQiacgDxQXwaeAs76vLykicmFEOIg/640?wx_fmt=png&from=appmsg "")  
  
换路，准备从设备入手，抓了一下登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKEpk4SBER82CHsVYDwpp6S5epulImDCmujZnLoMfzsmP71FLnp8MbYg/640?wx_fmt=png&from=appmsg "")  
  
不是cgibin 而是这种什么/main/xxx，  
尝试了一下，还真读到了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKtYQmwQgvg4VKiafiaxicXt9ySVa5Q1qVFuHciaE5Tds7Wibicz450xMXsKeQ/640?wx_fmt=png&from=appmsg "")  
  
  
丢ida，一眼sink。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKiaGI8fv8Bq4WEeenCLNu5rAkKI3ALtzG62UfZkxDKIE6icnkrkzqDobg/640?wx_fmt=png&from=appmsg "")  
  
参数可控。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKZbKUYqgEH1QQmPCibzyib2RNs02viaTiat4WGBwLx5eDDCExh8WgmcWX6w/640?wx_fmt=png&from=appmsg "")  
  
控制v5值为219进入sink点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKP03b9hCkaB9oPhficNak5xDubNribf97dWw3Re7ibibHlpuUmX33hoOghA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmKqUx3m96qSic9XmYaibib5M1udCQmncgt4ibp7UM2yibPOy7rUgaibhe2NYsg/640?wx_fmt=png&from=appmsg "")  
  
构造请求，成功rce。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zZrDr2DM8Oe3Aia1vHL5YtTz9DhKIBmK2kg8CnNxX5JENX2ugLqicbKcCibTzz55ic9TfCGHpia0X2V9yq4ybp3ibTQ/640?wx_fmt=png&from=appmsg "")  
  
相关详情会放到圈子里。  
## 0x03 小密圈‍‍‍‍‍‍‍‍  
## 最后送你一张优惠券，欢迎加入小密圈，好朋友。  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9zZrDr2DM8OY7uNzsr858s78YRSdYgsMzRDjQ4QT25A0ibr9QFNpBuF1PsCibmCpFBMBVb2Iibbt7le3IZZLKSdBQ/640?wx_fmt=jpeg&from=appmsg "")  
  

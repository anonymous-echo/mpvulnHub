#  某单位软件供应商黑盒下的0day挖掘   
 黑白之道   2025-04-22 01:23  
  
很久没更新内容了，最近做项目中，遇到了比较有意思的站，某事业单位的软件商，整体来说，开发的系统挺安全的。  
  
需渗透的网站，挺多的，不过有几个网站用的是同一个供应商，于是就开始了一系列的迷之操作。  
  
刚打开bp，由于没有关闭被动扫描，然后403了  
  
使用热点，更换IP后，关闭被动扫描  
  
开局一张图，登录框都省了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZKDYfu3toHXbgLFp4JQyYvZYA3jkDX0bfYRuib4sSFUCebHsS4iaglVBc6K6OrLNQJT1zU0bCxqS7Q/640?wx_fmt=png&from=appmsg "")  
  
查看源代码  
  
很好，vue框架，使用了webpack打包，打开js文件，输入.map，下载map文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZKDYfu3toHXbgLFp4JQyYvyY2S10eCJS4C37EkmysgTfm1ibLexr8loWFtCuib2kF8y0RXbLsQBQDA/640?wx_fmt=png&from=appmsg "")  
  
还原html文件  
```
reverse-sourcemap app.js -o app
```  
  
打开config.js,发现几处接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZKDYfu3toHXbgLFp4JQyYvBAwNuLuiaGaOISJCDElAcMZQM7dOGwX53rp3OrC9ot54hFI25dOrv1A/640?wx_fmt=png&from=appmsg "")  
  
有个下载接口，如果添加一个upload，是否为404  
  
于是，访问upload接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZKDYfu3toHXbgLFp4JQyYvz9eC1XtbgfbMzpmbWdaz5T0vA7QwIPSwBsNKTJ0STw2RniaWnCKiciarA/640?wx_fmt=png&from=appmsg "")  
  
很好，有戏  
  
构造上传包  
```
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFdxsjbQA396EznNW
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: close
Content-Length: 879

------WebKitFormBoundaryFdxsjbQA396EznNW
Content-Disposition: form-data; name="file"; filename="1.png"
Content-Type: images/png


------WebKitFormBoundaryFdxsjbQA396EznNW--
```  
  
经测试，jsp/jspx无法上传，html无法上传，显示403  
  
但可上传，pdf，xml，svg  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZKDYfu3toHXbgLFp4JQyYve9BLLS4n1BRQicyMAR6wsUBWyibN4ia5yUic94UNsXxDZyYScXcY1GtHUQ/640?wx_fmt=png&from=appmsg "")  
  
返回了一串字符，不出意外就是文件的随机ID值  
  
那么如何去访问pdf？  
  
是否存在预览接口（preview）  
  
是否存在查看接口（show）  
  
是否存在访问接口（getFile）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZKDYfu3toHXbgLFp4JQyYvXsVTPsURZUlG2Kscf9pdQ3pl7EibIH7PkrGMo9IV9pOG79r55k6osuA/640?wx_fmt=png&from=appmsg "")  
  
那么 带着疑问 去看另外两个网站。  
  
另外一个网站，接口信息更全面，所以失败的原因找到了，需要二级目录才可以  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZKDYfu3toHXbgLFp4JQyYvejjY4wROic55yjX27SvVT6kmhq3vSMibI39NxyeazxHYKZ6nO3DDwFdw/640?wx_fmt=png&from=appmsg "")  
  
尝试访问文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQZKDYfu3toHXbgLFp4JQyYvNRib9Bt7jonRLrAgtQvNRg0hT9fvzjIMyxaicChzOJJSYFXdROZZWhFA/640?wx_fmt=png&from=appmsg "")  
  
虽然不是很牛逼的洞，但也可以提升洞察的能力。  
  
渗透 慢工出细活，切勿急躁。  
  
  
  
  
  
  
  
  
  
  
  
  

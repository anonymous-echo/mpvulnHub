#  渗透测试-从下载漏洞到前端加解密+签名校验拿下sql注入  
原创 有恒  有恒安全   2025-06-13 02:59  
  
前言  
  
在一次渗透中，通过下载漏洞获取源码，审计出sql注入漏洞，也是在朋友的帮助下通过js逆向出加密密钥与签名算法，成功拿下sql注入  
  
  
漏洞挖掘  
  
在响应包中，下载路径部分是base64编码的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQdHa8F2UggGmTmzqesibibqpTsON6HPoF1VgJ4d6msIbz48YgXD2mTUMw/640?wx_fmt=png&from=appmsg "")  
  
通过解密可知为服务器的绝对路径，那么就存在文件下载漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQzWYG0icZiaNVXlOItEkx0SH3f1UZfLicHxLxFqUA5tJ5TmF3ZXxTAMjGA/640?wx_fmt=png&from=appmsg "")  
  
通过下载历史命令  
/root/.bash_history  
，得知源码路径，成功下载到源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9y9p7EDaBdk3HZxrusopsPvhlhY5sh5ic6qCj1pwZG3VzicZQ8JBko9Idjt2CTjpbRwOED4mibJVPKw/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞审计  
  
该sql语句存在参数替换，存在sql注入漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQLxK6PG2Qko3uiaoDo3eAoqOej61UpjHIGjbicPJj4Gvhvc4m9CksLvPA/640?wx_fmt=png&from=appmsg "")  
  
通过接口进行构造参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQQqofekV80qoZdvlwVyZ8ibJ8HZZ8GvoWPzBIbZtlH9VMxEds00Uzzicg/640?wx_fmt=png&from=appmsg "")  
  
但是失败了，原因是存在参数加密与sign签名校验  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQnCF9IKnZXOGdJhibtGqrSYwrbYhfO6vvyl0NYz08bM0Tico7jtLWPndw/640?wx_fmt=png&from=appmsg "")  
  
（正常的数据包）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQfhXzNZvPiaASyzMFWgKfpFZZHZ0JFNpHHO73wHJdhhYH6xMF4Ww8KAg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1Uib9y9p7EDaBdk3HZxrusopsPSeWYBeSBmFfp9SB0bxD6uEzDK2SOa1IGfmk9MEILn24kodOpFRTW5A/640?wx_fmt=png&from=appmsg "")  
  
目前有两种主要思路：一种是通过前端 JS 逆向工程，还原出加密密钥和 sign 签名逻辑；另一种则是通过后端断点调试来分析请求参数。但由于这套代码无法在本地运行，我选择了第一种方案  
  
js调试  
  
这部分可以看我朋友的文章，讲得  
比较  
细，同时文章中还提供了可以尝试通过其他手段与sqlmap联动利用的思路。  
  
```
https://jielun.site/2025/06/12/%E8%AE%B0%E4%B8%80%E6%AC%A1%E5%8A%A0%E8%A7%A3%E5%AF%86+%E7%AD%BE%E5%90%8D%E6%A0%A1%E9%AA%8C+%E7%BC%96%E5%86%99flask%E8%81%94%E5%8A%A8sqlmap%E7%9A%84%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95/
```  
  
  
通过搜索encrypt，找到加密方法，通过断点得知密钥的数组  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQYymqliaftqNXO7vLu6KxXdWoHUNnKGTPc9rqcuFnC1yz9bUw1JT6emg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQeuibDjUNn88WV4kn3sezI2O4fBpYS58Fo3WPouxeWKtjogMhIZdQtQw/640?wx_fmt=png&from=appmsg "")  
  
进行数组转明文：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQoMDmRKEadiaKfqcpGcRe21Nsiatib9G46vFWhlaUrx4ibGtN3QTEnibdILQ/640?wx_fmt=png&from=appmsg "")  
  
接下来分析签名校验：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQCSeErxAiamPn56PzlyzKmjiccgf4tJibSkfz4s7ia0FId5icDPdBU4otGeQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQAtYyUr3lgicNsIDnU4m9z7HGEZTX8uAVsS5v8mCGhcibAx7VXn9cOEVg/640?wx_fmt=png&from=appmsg "")  
  
此处是先获取所有请求参数中的值，将其拼接成arr  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQIOjiaTnIhtPMJGq8EkEN9FAPhaQKkL3up0f31VvxoiaIjvYAgeRYcohQ/640?wx_fmt=png&from=appmsg "")  
  
  
注意后面有两个时间戳，两者不一致，一个是前（timerandom）一个是后（signTime）  
  
整理得到具体步骤：  
1. 加密参数：将每个参数值使用AES-ECB加密（PKCS7填充）并Base64编码  
  
1. 生成签名：  
  
a. 按固定顺序拼接加密后的参数值  
  
b. 添加一前一后时间戳（timerandom）（signTime）  
  
c. 计算整个字符串的MD5  
  
d. 构造JSON字符串：{"md5": md5值, "signTime": 时间戳}  
  
e. 使用相同的AES密钥加密该JSON字符串得到签名  
  
1. 构造HTTP请求头，包含签名和其他必要字段  
  
1. 发送请求并输出响应  
  
漏洞利用  
  
使用朋友编写的脚本，对equTypes参数进行注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQNlET11KehyDVsKPFLTciaMQNHEzUyRbDjILnibHa6KDPGJLpZKgJDWJA/640?wx_fmt=png&from=appmsg "")  
  
再根据系统源码中的sql语句来编写注入payload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQ2VQOUX7ic6uwvSoYqyphokSScXEQjjaUicr21kd9pnFZtNqJbjZBIBFg/640?wx_fmt=png&from=appmsg "")  
  
由于该注入点存在放大延时的效果，所以这里写的是0.01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQNhehNeReVcOeBOAY3lVzZlF3RtIbscibomKSxibtxqElWQia2n17RiaUkg/640?wx_fmt=png&from=appmsg "")  
  
证明存在sql注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fp1zrrz1UibiclibNHBwZ9eDAFyF8lHcCCQwyPiboRsNBelba30YFIJmAKFPPrn5ejJibLnO2sTLfRicXYdXQebaricIQ/640?wx_fmt=png&from=appmsg "")  
  

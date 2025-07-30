#  本想分析rce还出了一个sql注入   
原创 Ambition  进击安全   2024-09-07 10:00  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
**一、前言******  
  
      
在凌晨自己准备铲一把睡觉的时候，一位师傅联系我让我分析一个漏洞，于是自己一顿操作打开了代码编辑器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83QysEhpU4clvCCrBHaTicmibcBPYS4ECVzPwW0scQC4BIB9icqU0OYKYa8yhw/640?wx_fmt=png&from=appmsg "")  
  
**二、漏洞分析**  
  
      
这个师傅已经给我发了相关的POC，我们根据POC可以进行顺藤摸瓜的分析，这边载入源码进行查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83QysKYAA1hNGnmEr9nsJnrjRGDAUF5cEqWZxj0hJymK4UZH4SP9ibennTGw/640?wx_fmt=png&from=appmsg "")  
  
其实这种源码可以i直接看出来，并非使用框架的方式进行开发，直接直文件访问形式即可，方便我们进行直接定位漏洞代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83Qys0p4y35G5S9ibCsia5F1F2Y0gUntoG09mexEgOGAAKTwgticNa7Z0JjhNw/640?wx_fmt=png&from=appmsg "")  
  
在文件的开头可以发现，进行接收了两个参数分别为callee以及roomid连个参数，我们看看具体哪个参数存在漏洞。  
  
```
GET /api/xxxx/xxxxx.php?callee=1&roomid=`whoami>xxxx.txt`
```  
  
  
roomid存在漏洞我们定位过去。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83Qys3w0oDw7hWa84nBbUa28HlgbsInnDAiaWcFRPGS0BqgRVzN6jVGCzxFA/640?wx_fmt=png&from=appmsg "")  
  
可以看到判断我们参数roomid是否为空，并且然后进行查询了一个sql语句（还是PDO的方式），根据结果进行执行将我们的参数roomid进行赋值，这里因为参数result如果大于0的化我们的本身参数会被污染掉，所以这里sql查询的结果应当不会大于0。  
  
（这里不进行验证了因为本身漏洞以及存在当false继续向下看代码）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83Qys3L1z9J3ia4a7whUzBrRDTveOgLSP5O9UHVd9BwtCuXn4ficSQs4jibjAA/640?wx_fmt=png&from=appmsg "")  
  
在代码当中发现上述IF语句均与session相关，而我们又没有相关的session操作，所以基本都会选择else执行，刚好我们的conf_cmd在当中包含了我们可控的roomid参数值，导致间接conf_cmd可控。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83QysNKqRsiasiaEokQbkpxUMTwtoAFn6S0yaicy6cC9xQ1TwkTT1L60VelaeA/640?wx_fmt=png&from=appmsg "")  
  
最终发现传递到了方法cmd_async方法当中，跟入方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83QysAaPMKhibse5ObBhOzogiaOswORicc2Fz4s512pOAtwyBD4Cg099bnsiavQ/640?wx_fmt=png&from=appmsg "")  
  
直接拼接到了执行命令exec当中导致了rce的产生。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83QysAyPn8g4IWGTsvoLn8O2Diba3IN8STDMGaJKzJBJLaRvRdMoBnFlFnVw/640?wx_fmt=png&from=appmsg "")  
  
**三、SQL注入分析**  
  
分析完准备简单看两眼睡觉，结果发现了注入，我们全局搜索可控点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83QysC5eUj1PECfq79rGk4T4LFEwVia5p0dCSstOayhAqKbFickicicCtnZcLicQ/640?wx_fmt=png&from=appmsg "")  
  
发现在这套源码当中存在相关的可控，构造数据包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83QysqMoe7Evw3uRqyMqdHdUmpWNUXoZq8BbVq6iaLAGFNJibbnDziaQ7oxMQw/640?wx_fmt=png&from=appmsg "")  
  
直接使用工具一把梭！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWDvJHtaSaoSI1XH5x83QysgMTSKlDd0icdHXOxCNVbFpARdThXXb0UBOgIxEQYn3eZUFIzlXCpicDw/640?wx_fmt=png&from=appmsg "")  
  
打完收工！（睡觉睡觉）  
  
**四、完结**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
  

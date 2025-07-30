> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTQ5MTAzMA==&mid=2247484493&idx=1&sn=b3f52bcf88286af6436326c213aec8df

#  sql注入绕过雷池WAF测试  
 天黑说嘿话   2025-07-01 01:43  
  
**前言**  
  
雷池 waf 相信大家都不陌生了，  
作为一款业界领先的 Web 应用防火墙，  
针对于扫描器流量的防护效果毋庸置疑，今天我们主要来测试一下对于手工sql注入的防护效果  
  
**社区版部署教程**  
  
配置最低要求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nIx8A9u7z23DKQT1t526xZlYhibcqp8z0tZiblu8ALMJa34q79tbL3Ccjf7AnsFbZx22IcAm4t5eBw/640?wx_fmt=png&from=appmsg "")  
  
满足配置要求后，直接一条命令即可安装  

```
bash -c &#34;$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/manager.sh)&#34;
```

  
我这里是在本地安装  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nIx8A9u7z23DKQT1t526xZOBmEttyQqH6MX7ficN9QuEibCCYEYWBz97oxfoHFBQm8UlseSxsmt6icQ/640?wx_fmt=png&from=appmsg "")  
  
等待安装成功，直接浏览器登录管理后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8XEJkHKPOBW4XSvm1TuVdaVGIIs70as2aQNBibXPXEPbZJiaeSg0TjvNA/640?wx_fmt=png&from=appmsg "")  
  
防护应用功能里面填入需要保护的网站，也就是我们的靶场路径，端口为8080，域名这里有就正常填写，没有就不用管，点击提交即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d80PjO7gkrfeibZpK2hTqlTCqWibuxacibOP1Eq1btvyhiabGPTdibunicqkkg/640?wx_fmt=png&from=appmsg "")  
  
攻击防护里面可以设置防护强度，这里默认就是平衡防护  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8kDe7BIVwIWv11YWlUfS53DhRnDuFvMeFetmf6bick5PSHeBVjghicW0g/640?wx_fmt=png&from=appmsg "")  
  
本机访问雷池waf服务器的ip+端口，成功访问，如果你是服务器部署的waf，记得放通相关端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8oBicUxhgkWw1wibdH2YWnbwLgbkD10oHw8slKZCctMkLiagccgSKk64zg/640?wx_fmt=png&from=appmsg "")  
  
随便来个payload测试，触发了waf规则  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8pcXPiciabz24GsfiauYIUR8BfHFMBAJnqIwJbDXC5XpqyqF4Q5iaPJbiayQ/640?wx_fmt=png&from=appmsg "")  
  
雷池waf后台可以看到详细的日志  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64lRzJIlNoJxp18m780ju8d8FY0iacMU9P0VTqrummbREwK8ep60r6buWSBY0tAVlqZ6mbAU7e2vfZA/640?wx_fmt=png&from=appmsg "")  
  
  
**sql注入测试**  
  
单引号报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCtQJS2V6AlQUrZZAEcMzHatawJKs6SXfNCv6sWMvrSfbJ4E9aDmTUbg/640?wx_fmt=png&from=appmsg "")  
  
两个正常  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCUMHk7dUVRPT4q5mJDr7Tp1shavZHVDTTSAYCacaF4PQoCMYu5uAGgg/640?wx_fmt=png&from=appmsg "")  
  
使用我最常用的判断paylaod：  
'OR+'a'='a'+OR+'a'='b，  
直接被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCJ0eujQ4lc9eXbjDG8iaMjcV5AdFtPjP4mrfWicZlibY9EKk3iafWqFhgPw/640?wx_fmt=png&from=appmsg "")  
  
将等于号替换成like，依然被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCxm6GbwSjOP6WK8tibic47Tooq87y2XWv6XYSfcTC7DyrfvB29aKX0Iibg/640?wx_fmt=png&from=appmsg "")  
  
这里使用 || 绕过or，cot是余切函数，成功执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCficmUXTXuWzytrtvsicgoYqXNe9JxsnCfhW5YRTZ01EZn4pMTUUQcf8A/640?wx_fmt=png&from=appmsg "")  
  
cot(0)则是分母为0无意义，也可以说是无穷大，导致数据库报错，减号运算符也可以用，我们下一步就是寻找可以使用的截取字符串函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeC1kic3iaGvM27JysFtqkv2tYsXpE1iaS4gib9Yz2wOia8ZiakHknjmQCcfHjg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCo48j73YCfnw6oAdl2TMJlgo15bdAVekScSUC3XjK1WlAuWlALUoxcA/640?wx_fmt=png&from=appmsg "")  
  
使用length函数直接被拦截，使用like也是被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCHAKMYO6clA7kRbnVWFiaOCnibo5Gn0a8jlT0qt9nquew6r5uib89Qqhaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCv8A3DyvqveBbsV33UuCUJfibStnKpqibLZlRiaoWFmanaH2rL5SGVdpfg/640?wx_fmt=png&from=appmsg "")  
  
拿出  
以前经常  
用的  
的  
position  
函数依然被过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCSeXoSAF6FP09QsktyicN8BUIAbDOTFODsu7GibMfA2jI9xialvya6cfiag/640?wx_fmt=png&from=appmsg "")  
  
这里尝试垃  
圾字符依然被拦截，其他知  
道的函数都试了，都被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCOuGj8232le7Mnny6BMdogZCG4jIodIGb7mmDib4M0ibuBPOib91rEPzlw/640?wx_fmt=png&from=appmsg "")  
  
测试一下 order by 语句后面的注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCAqG4Jic5MzBsDZffibPsJSmR4fAeveannY6cYqyQ9HjpzXVs0SYYC54g/640?wx_fmt=png&from=appmsg "")  
  
直接使用if函数，当1=1时返回按照id的逆序排序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCsS1RkF1YusRd2esdyH3djiarDvY6hNjpCPow5y0jKyzYyXEEw4JCXHw/640?wx_fmt=png&from=appmsg "")  
  
当条件不等时，可以看到是正序的排序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCEd09RLSrvrn11nBHvjwYxKco8Sdn8tyVLFRhWicVzHDINGc3Qh4DEqg/640?wx_fmt=png&from=appmsg "")  
  
这里使用最简单的截取函数直接被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCU368fgn4WA9CpBgQoibjYwZZe5liaMXskCwSU9R2IbZzvqj7EtpdibQIQ/640?wx_fmt=png&from=appmsg "")  
  
这里使用我之前喜欢用的  
position函数，成功执行了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCA8e0ibjwl4sJr85dKjj8usTVeMxWDzHm90xYn8kibR9F7RRicWs1x1BibQ/640?wx_fmt=png&from=appmsg "")  
  
position('sql'+in+'postgresql') 返回的  
是8，控  
制后面为8，返回按照id排序的结果，逻辑没问题  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCIRVWJv9EKgAGb2hDtyuibeaeKrdNUPAZeXfS0BrcIV7QexCM1BwyMPA/640?wx_fmt=png&from=appmsg "")  
  
尝试注入user()直接失败  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeC3PPJAJa8SIKcSWJuZWpaTRZaFzpuMibkbskA4fNGeEqLGpSE1OdZjIQ/640?wx_fmt=png&from=appmsg "")  
  
这里尝试注入版本，发现可行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCUlaXC6bohNsWlPPev6bMq9QNblW00Sbe1kd7UV87XqeuG88ABt1X6w/640?wx_fmt=png&from=appmsg "")  
  
这里等于1的时候排序方式变了，说明第一位为5，可以注出来当前数据库版本，但是没什么用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCIZpbYud5hFQsZcdDkMrqyy7QM0krqYHnruib6W2mSwv2MKtzrRoIXuA/640?wx_fmt=png&from=appmsg "")  
  
继续尝试注入数据库，直接被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nvUWEcXlxHx9qEtMqJrKeCCdV9icUpy45wtNhbDXwiawnlcSklnibpTjBuay6IkDSLkFXjzrPlrH85g/640?wx_fmt=png&from=appmsg "")  
  
其他尝试内联注释、并发、参数污染、大小写、分块传输均失败  
  
**总结**  
  
总结来说雷池waf对于sql注入拦  
截还是挺完美的，能测出来有sql注入，但是很难再进行下一步，因为它并不是单纯的针对某些关键词的过滤，而是有着独特  
智能语义分析+ai驱动  
技术，  
对未知攻击的防御能力远超依赖规则的产品  
。  
  
**官方交流群**  
  
官网：  
https://waf-ce.chaitin.cn  
  
官方社区：  
ttps://rivers.chaitin.cn/discussio  
n  
  
帮助文档：  
https://docs.waf-ce.chaitin.cn/zh/home  
  
社区版微信交流群，有任何问题进群交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64nIx8A9u7z23DKQT1t526xZv5uSKib9nWBLelm4hT82TQ9kibcAgy3c0JaMicNaWDySfn0zDWjZOTgCA/640?wx_fmt=png&from=appmsg "")  
  

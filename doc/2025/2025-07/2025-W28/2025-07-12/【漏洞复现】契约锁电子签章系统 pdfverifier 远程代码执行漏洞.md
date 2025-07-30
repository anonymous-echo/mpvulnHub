> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNTYxNDAwNQ==&mid=2247484920&idx=1&sn=adfe24d7cee65a50ea24cc4d8f7be624

#  【漏洞复现】契约锁电子签章系统 pdfverifier 远程代码执行漏洞  
原创 PokerSec  PokerSec   2025-07-12 10:00  
  
**先关注，不迷路.**  
> 我步入丛林，因为我希望生活得有意义，我希望活得深刻，并汲取生命中所有的精华。——《瓦尔登湖》  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 漏洞介绍  
  
契约锁，是一个电子签章及印章管控平台，提供的电子文件具有与纸质文件一样的法律效力。契约锁存在任意文件写入漏洞。由于存在解析差异导致契约锁对zip检测的安全机制可以被绕过，未经过身份验证的攻击者可以利用该漏洞写入任意文件。  
## 影响范围  
  
契约锁4.3.8-5.x.x 并且补丁版本 < 2.1.8  
  
契约锁4.0.x-4.3.7 并且补丁版本 < 1.3.8  
## 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJLcBwqCLAkS1kaLWkLoC16n5dL3INibyVibFgXZs76OUImiaBnmopXq5ZH1MW5LkGA1D2WrfwHXcibrTQ/640?wx_fmt=png&from=appmsg "")  
  
  
POC:  
  
(这微信页面直接复制代码格式会乱，可以浏览器打开复制)  
  

```
/pdfverifier
/api/pdfverifier
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJLcBwqCLAkS1kaLWkLoC16nia1to1aTLnloYbISYQiaveuR3EhofOvuHETossb4GAp1KHhzIvqojldw/640?wx_fmt=png&from=appmsg "")  
  
## 漏洞分析  
  

```
qiyuesuo\privapp.jar!\BOOT-INF\classes\com\qiyuesuo\config\PrivappConfigurer.class
```

  
  

```
privapp.jar
```

  
中
```
PrivappConfigurer
```

  
类中包含了允许直接访问的路径。  
  
其中包含了本次漏洞的路由  

```
/pdfverifier*
/pdfverifier/**
```

  
找到
```
qiyuesuo\privapp.jar!\BOOT-INF\classes\com\qiyuesuo\api\PdfVerifierController.class
```

  
路由地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJLcBwqCLAkS1kaLWkLoC16nSD8WDiarQkjTLolJ1ia5PKd4K86AOp42N9jUd1NupVsGkFJLHTdJ0o2Q/640?wx_fmt=png&from=appmsg "")  
  
读取文件，会判断是否为.ofd文件，通过
```
getFileTypeByStream
```

  
通过读取文件头来判断文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJLcBwqCLAkS1kaLWkLoC16nukTTsHJHgXAEpYlp5picOwaXLnXhKq8PRSicqBRQibTzcZx8P2AbRHCnA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJLcBwqCLAkS1kaLWkLoC16nQNBteyIkufbuGqiaLicCk5ReGQBFlZsRcibeyFr9yLKS5qe6fibV6fibQFA/640?wx_fmt=png&from=appmsg "")  
  
跟进
```
verify
```

  
函数进行签名校验，这里还会进行ofd文件判断，首先进行zip解压缩操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJLcBwqCLAkS1kaLWkLoC16npR4JcBqjljI1XApHylPxMkKsP5NYtOe0vLnibIzXkStrjBmugpv9xQg/640?wx_fmt=png&from=appmsg "")  
  
Zip 解压缩,这里存在目录穿越导致文件上传或覆盖  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJLcBwqCLAkS1kaLWkLoC16nEo5uSZ10vIVNLibqdXaPJiclqdY8X8nZ4s6T7pbT8gSAh5HSYtnbRI1A/640?wx_fmt=png&from=appmsg "")  
## 修复意见  
  
契约锁官方已发布安全补丁，请及时更新安全补丁：下载地址：  
  
https://www.qiyuesuo.com/more/security/servicepack  
  
  
  
  
如有侵权，请及时联系删除。  
  
  
  
  
  

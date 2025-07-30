#  一次0Day漏洞Rce审计流程   
 WK安全   2025-03-08 20:36  
  
******免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
  
**一、前言**  
  
****  
本次仅仅是记录一下自己审计一个相关0day漏洞rce的过程，并无指纹，poc，以及其余信息，看poc、指纹什么的师傅可以滑走啦。（本文会厚马）  
  
**二、分析流程**  
  
****  
再一次无意间发现一套源码，并且为最新版本，自己尝试拉去到本地进行审计。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV6jHoC9V3bLicvicDmUfIY0BFqSobPiat4UPdzNFBibdBjiaickLSJauKFPckW1xR5tfiap1Z3SOubM6b7Q/640?wx_fmt=png&from=appmsg "")  
  
    通过分析发现会包含一个文件，调用其中的x方法进行鉴权，如果调用了其中的x方法那么会进行监测是否登录，如果未登录则进行跳转登录页面，这里使用自己开发的小工具快速筛选相关没有鉴权方法的文件。  
  
经过监测，发现其中一个文件夹下xxx/xxx/xxxk.php当中不包含鉴权方法，进行分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV6jHoC9V3bLicvicDmUfIY0BTwYSWibS1nBWRhPou4ib6g83bJYzXFj9M4icpX7N7UhicvkC6kZSTWoWiaQ/640?wx_fmt=png&from=appmsg "")  
  
是我草率了，原来是两套鉴权，其中方法http_authorization也是一种鉴权方式，这里成功绕过，但是不看如何绕过了，我们来查看这个rce。  
  
在获取到参数ips之后传递到了方法filter当中进行过滤。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV6jHoC9V3bLicvicDmUfIY0BicnWR0YvzyGR7hcK0CY9rEAgQl45L0nRtZhUyAHiaTj32KBJTQ5Caqew/640?wx_fmt=png&from=appmsg "")  
  
这里没有过了到;很明显，继续往下走。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV6jHoC9V3bLicvicDmUfIY0BEibb3obht749dQjGZydJUgGZkWTjmhwib7hlI0zlmaLic27U5oiayxCI6A/640?wx_fmt=png&from=appmsg "")  
  
然后对于ip进行往下进行传递到cmd当中并且最后进行了执行，尝试进行验证。  
  
**三、漏洞验证**  
  
    尝试将回显放到dnslog当中进行回显。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhV6jHoC9V3bLicvicDmUfIY0B2PU7zCJ7iacQ3zviayt3AB3XCwz4u2Lppn0uSXicm3uicGHJdL5CsJkc5A/640?wx_fmt=png&from=appmsg "")  
  
可以看到成功进行rce并且带到dnslog当中，收工。  
  
对于过滤如何绕过大家可以给一个建议，这里只是可以带入dnslog当中，因为过滤了}以及|>没办法拿到shell如果大家有好办法成功绕过，可以给大家一个小红包hhhh。  
  
  

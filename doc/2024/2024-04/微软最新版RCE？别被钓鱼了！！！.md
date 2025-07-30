#  微软最新版RCE？别被钓鱼了！！！   
原创 pwjcw  剑外思归客   2024-04-26 11:47  
  
## 起因  
  
最近看到群组发了关于微软RCE的一个事情，是不是蜜罐先不说，但是微软的域名这就很奇怪了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TicIrTWp9rPXgtncbFhETu5b9ABQ15YDgCHghSonprXQG6C2MOicLXOmnibVO37nwYTdPRs7HpvDYPg/640?wx_fmt=png&from=appmsg "")  
  
## 经过  
  
于是微步上面查了一下域名，白名单，安全域名  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TicIrTWp9rPXgtncbFhETu5bulIYSky8fOowpCzLKlKlvLLDEiaaibibTBlfTCyQ3oibcDwHMbO91L6rg/640?wx_fmt=png&from=appmsg "")  
  
  
这一切好像都没有什么问题，然而关于这个域名的威胁情报却有一些，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TicIrTWp9rPXgtncbFhETu5iciaVpTNuCVcax44nCgTqlIQ2ia9DCJyg0GrROIeARwqBnyb7XYPscM0g/640?wx_fmt=png&from=appmsg "")  
  
  
事实上，早在2021年就暴漏过此域名被恶意使用的问题  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TicIrTWp9rPXgtncbFhETu5ZbdKKNCDxuy2L3XrlQv6AOoYMpcqibCvum2jjaEuuskZdJYcv5wwygw/640?wx_fmt=png&from=appmsg "")  
  
> “code.microsoft.com”。目前研究人员可以确认微软的基础设施没有受到攻击。事实上，未经授权的一方接管了悬空的子域“code.microsoft.com”并将其配置为解析到他们的 Cobalt Strike 主机。  
  
  
文章url：https://www.4hou.com/posts/7YQG  
  
由此看来，目前该域名出现RCE的漏洞，有很大的可能性和微软无关，  
#### 子域名是否被接管？  
  
为什么微软的域名能被恶意使用？此时不得不深入探讨这个问题  
  
假如说：  
  
我注册了一个域名a.com，  
  
并且我有另外一个域名且已绑定服务器test.ccc.com，  
  
我将123465.a.com解析到test.ccc.com,  
  
有一天test.ccc.com过期了，被一个恶意的攻击方抢注了，但是我的123465.a.com仍然还在解析到test.ccc.com  
  
问题不就来了，别人想在我的123465.a.com上面显示什么不就显示什么了？  
  
查看一下code.microsoft.com的解析记录，发现其被解析到了test4152ausjipqa.dynamitecdn.com.,指向的ip为：20.41.17.212和40.78.172.194  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TicIrTWp9rPXgtncbFhETu55icicXqwuibgEsAZP3MJ2nPtW2wbTmMKicMzTibMpibbhwAs5ia9NY2zOGaLQ/640?wx_fmt=png&from=appmsg "")  
  
  
至于test4152ausjipqa.dynamitecdn.com是何方神圣，有是否被接管，很难说清，因为其域名注册时间比较早，现在也并未过期.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9bOzaictich6TicIrTWp9rPXgtncbFhETu5WXV8vzrfm8goSE6rtP4MhVjfBJeEIOKpCBrY5NdB5PSF25kKSBBjww/640?wx_fmt=png&from=appmsg "")  
  
## 结尾  
  
种种原因的一切矛头都指向了test4152ausjipqa.dynamitecdn.com这个域名，而这个域名大概率不是微软的资产，是否是一个恶意的攻击者来钓微软账号的Cookie的呢？不得而知。  
  
以上均为个人分析与见解，如有不对，还望各位师傅多多指正！  
  

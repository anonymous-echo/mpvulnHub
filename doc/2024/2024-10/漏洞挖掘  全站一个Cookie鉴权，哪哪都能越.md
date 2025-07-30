#  漏洞挖掘 | 全站一个Cookie鉴权，哪哪都能越   
原创 zkaq - 满心欢喜  掌控安全EDU   2024-10-20 12:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  满心欢喜 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
某站的教师学习系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niaXPLniaUiaYYV56j1tbqLeiaia4SJic8UH6tCxCljJxvPiaJESBvAyqFkg16A/640?wx_fmt=png&from=appmsg "")  
  
img  
  
开局直接发现注册功能点，直接注（反正不是用我自己的信息，奉劝大家在挖漏洞的时候千万不要傻乎乎的拿着自己的手机号啥的去注册的）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niaRc2bagvbXIIZliaUpA0TYNJV56dF5mnyDRFMTMVFABMjqTTIsQrqTIA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
注册一个账号之后点击手机端功能点切换到手机端  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5nia3kIRM4sLDG3f8NoumCMUmTyzoibAXTWumVH2GOr7UhibKmf2SJ7Erm9Q/640?wx_fmt=png&from=appmsg "")  
  
img  
  
点击右上角的头像并拦截数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niap4QU6JoukrxGFX7iamR34FibtGFLxHC5AbmibwGMtD2BzyQnW8BQKD2Lw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
数据包这么大一坨 但是没关系我已经发现url上有id了 嘿嘿嘿难道又是id鉴权 将sharekeyid=2811改成2812 结果不行，直接给我封了 完犊子了，但我不甘心 哎突然眼睛一尖发现cookie中也有sharekeyid  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niagwOJxte3TnibUicOUGWbcSibflOX42oiaQ2rQFlODvVHh8l9TYYpjWrnyg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
但是也不能越权 我都想着放弃了，结果在AccountsIdentifier参数成功越权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niamUT7RsTE0OYOia3toOBKtql2LJmsfmLicKQVGfykOCDjpIO7dM0CpicCg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
直接遍历  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niaZoln27L3ribpFT2A2yJibkpEiac2n6brvYVo9WygrHR1JSrRoxzC2xmaA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
成功越权 哎转念一想，cookie中的鉴权那么该站其它功能点要是也用这个cookie是不是也能越权 不过要越也要越点有危害的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niaxnfLwO3WU8cfUpxoibITiaGs1Et7QicwPTLeTLvLbwib9n9OyicXZQ7mm3w/640?wx_fmt=png&from=appmsg "")  
  
img  
  
在个人管理中心-我的账户-基本信息抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niazGNvFw9TZpjQlQyftVLuzK7HQYFqtea0j4ib5uvCiavDCV5iclt6TTpHQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
爽了哈哈哈，都是用这个cookie鉴权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niaYmJHsB5YTQXHHbv5ZlIfufM5CLicGstKYmqLaYA5jiaYVG4qF16wNJdA/640?wx_fmt=png&from=appmsg "")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niahUsVPQ5qeqMhyQicZqiaSBIIq0wWV9oia8HM7JlSBES7xaEAPPLUWh71w/640?wx_fmt=png&from=appmsg "")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niaPMlbVicVjpdDb0beY1wibmPeBs0GNfXQhAwRs4O1M9icGd4icrkBZ1gv0g/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
直接高危拿下 该漏洞我已提交教育漏洞报告平台并已修复  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpa1t1nxlDPJIFtloUicZ5niavoicBibkZvoW8vskhMz5rOPDQ7VednoaeZoX8V3XO8Tg7RRZmT5y9UcA/640?wx_fmt=png&from=appmsg "null")  
  
img  
```
```  
  

#  某众测记录｜细心 = or ≠ 漏洞 ？   
 实战安全研究   2024-11-30 01:03  
  
群友投稿的文章  
  
"近时间参加了某众测活动，资产是真的难打  
  
RcyQJzSQDTJxz7RSO9hd3jHIdOHQm9c6Li22u8H3pSdPPcJLSAHphXyBpEsxa7zFAEt3kdJxGJQti3LWkV0ROBaGmE4qv5GQ3Cxtxa3FWDNqi4K2YTgEe6BbKswJHZTwn0RCpser8qVKvc980nVrBouuqch2lcFxHZjyB96KXcfUI8dyaNcRXq9KuPWSglbnqAGxWyCAkE0gWASVwmnPFvJDpkdvcyDc0cTGOjXS9ULvAxv6QlYvXLSP2Oqb9xbYouyYGyUWxl6SxW0Tl1z4Bj2hmyYC4aWTCmxuJ8o3kW3kzHRND9RLYtra9dPg0UX20xVmFk6wdFR1L2dMDUUMtkrIZhOOX081dph0hTiilwGZY7SgBCyoSzEAlqzZDmuhtZWQpvBgAQNcStu45tpK0DsuniXwM10Fh9NHHbjy5Ofp2hqAwzNBiCd4KuiBRPrQ1U1zZbUb97zmsamgOdLTgYijri29iPvzYi8atKFpedoxr5oT19LSQG8YyocwmK4v0yX9lOYPoyyFekhy02l9y4JiOTUc2YIPrNuf  
  
先对资产进行信息收集，发现一个链接，访问 error，怎么点都是 error  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbhx6FbrkCBALZkhkAPRESN16LtuhYQpuDC9n6IcqlyibqyfqH3Bru2DPDUkSfOibg7c1kkzfMZDGmQ/640?wx_fmt=png&from=appmsg "")  
  
  
于是就看看源码，找找接口，发现了几个接口，拼接还是 error。  
  
然后就目录扫描，发现了几个目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbhx6FbrkCBALZkhkAPRESNArRtpUCB9CBe6aMPl7DKjAIkvEU8tNon1s7e8iahPnHHic1zJ0XibdSZg/640?wx_fmt=png&from=appmsg "")  
  
  
访问 portal，是一个登录页面，是上面 error 的登录后台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbhx6FbrkCBALZkhkAPRESNia4fgf9XNOia3asRTWsxdUMrB6pZ8txOtwyMB0srTKnOXHLALwfb86Aw/640?wx_fmt=png&from=appmsg "")  
  
  
输入任意账号密码，抓包，测试sql 注入，登录绕过，均无果。  
  
然后接着查看源代码，找到了一个 services 接口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbhx6FbrkCBALZkhkAPRESNcMWic1Byty4RSWvsEU15bhFKrPlPyAuUULJWATm6tQDWXWYTJV89Mwg/640?wx_fmt=png&from=appmsg "")  
  
  
其中有个 upload 上传接口，只能上传图片，且返回路径为内网 IP，就没办法利用。  
  
然后就开始对各大接口进行目录扫描，最终只扫到了一个接口存在ueditor  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbhx6FbrkCBALZkhkAPRESNSQic6O6O8SLCbsNCXk2dknJwXRfKjjj6ZicpWqf4DL203YPia5bSn07Tg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbhx6FbrkCBALZkhkAPRESNDqyfvq7g2CS5NUzdIqyjy5tlJMYWRTLPW3PdcV3DdAL5IY0kQHP2ZA/640?wx_fmt=png&from=appmsg "")  
  
  
反射 xss +1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbhx6FbrkCBALZkhkAPRESNtfcvZO1X6RXLZZiaTfqp9oia5ucq1qlplDemTa7DOvEPAkHfm38bVHew/640?wx_fmt=png&from=appmsg "")  
  
  
然后替换action=uploadfile 为这个 ，就可以绕过图片，上传其他后缀的文件，xml，pdf  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbhx6FbrkCBALZkhkAPRESNJ87TTunb9HLSQYoJFFb8jxcGpuAGHkDjWGDB47KOnE36DfI1Ecsfng/640?wx_fmt=png&from=appmsg "")  
  
存储 xss +1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbhx6FbrkCBALZkhkAPRESNxWHxOcrek5a8dRScLoE8Mv29iaBLOV5sEyLFMr7eyiaic0F4iawfdtpt9g/640?wx_fmt=png&from=appmsg "")  
  
"  
  
  
  

#  一款简单好用的漏洞管理工具-miscan   
mifine666  鹏组安全   2024-11-09 11:49  
  
**由于微信公众号推送机制改变了，快来星标不再迷路，谢谢大家！**  
  
****  
**漏洞管理工具**  
  
漏洞管理工具，支持漏洞管理、漏洞扫描、发包测试功能。编写本工具的目的在于帮助安全人员更方便更高效的编写漏洞规则，以方便漏洞利用和漏洞验证。  
  
**关于工具的特殊规则**  
  
工具其实越简单越好，但为了方便使用，还是有以下几点规则需要了解。  
```
1、响应和响应头的匹配支持正则匹配。不会使用正则也没关系，可以直接匹配关键字，如果存在特殊字符，可点击转义特殊字符一键转义。

2、在响应包中可以使用 {{变量}} 来保存信息，方便后续的请求包使用。

3、需要发送字节流的数据请使用 b64decode{{base64编码后的数据}} 来替换，常见于反序列化，上传文件等场景。

4、需要使用dnslog检测的漏洞可以使用 {{dnslog}} 替换，工具支持自动替换并检测结果。
```  
  
**功能测试**  
  
**1、简单增加一个漏洞**  
  
在漏洞库中找一个进行测试****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92x9nHdNAzYxtETCLrsD3wg51LG9xsrTicAVibjb7653qcTWB8k92hGiadg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92tG6Y84ciaDmIAoQxOxc2s3NJANGibpxmOTzibxVp8ib4FkzTMl2mxjH8oQ/640?wx_fmt=png&from=appmsg "")  
  
填写好产品名称、漏洞名称，然后将请求包复制出来，粘贴到请求1中，响应包中可以使用正则匹配，点击保存即可  
  
https://www.jyshare.com/front-end/854/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92br22xCwXbqnCL8c6BuKqPBbAPibO86icX0bWJgKSb3pRFkQKHZqVG9Bw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92rotFurog17g5gmhV12uddJvSykPL2CamNLrb72OUn6G683ibJbcpkRg/640?wx_fmt=png&from=appmsg "")  
  
检测测试，可成功发现漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92j4JKdhRHgE9auqk7eibYIYPzWlSic2Mox0JugiaPbUYxcGQWhbucdsRhw/640?wx_fmt=png&from=appmsg "")  
  
**2、如果需要发送多个请求包**  
  
后面的请求需要使用到前一个响应包中的信息，  
例如下面这个蓝凌getLoginSessionId任意用户登录漏洞。  
  
1、获取sessionId，填入请求，在响应的地方匹配  
sessionId  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92Igq04Ms2HzIlev6hTtb2ArRbRibHT9HPzohcPpL9AYlUvIzI52QAJiaQ/640?wx_fmt=png&from=appmsg "")  
  
2、  
点击下一步，将sessionid添加到第二次的请求。然后获取返回cookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92TMXfHkj26fjVCFSYt8Owic1JajMUiauibr6AJSbYlbGfCM4iaN0qcua2pA/640?wx_fmt=png&from=appmsg "")  
  
3、点击下一步，  
将cookie替换访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92oYTV4pic6O3TPFHtN1eA0J7TeuZWYLBtxSUib28AZCWAn0FcIJKYNGlw/640?wx_fmt=png&from=appmsg "")  
  
**3、需要使用dnslog验证漏洞存在**  
  
将请求包复制到请求1中需要dnslog的地方用{{dnslog地址}}即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92MMc4c4IIiagaR8RRKDdhSnhnNa8PDWWvkZRkyIUud2pcibEeibPqFAZibg/640?wx_fmt=png&from=appmsg "")  
  
**4、发送的请求包中存在字节流的数据**  
  
将请求包复制到  
请求1  
中需要字节流的地方放入到b64decode{{中}}即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92BOiaUhZiafkicNlSK8lZq3HdbTq6aNcIoRl5PV0UBZYicicgsQmr5NEuU0w/640?wx_fmt=png&from=appmsg "")  
  
一套流程测试下来感觉还是非常的好用，爱用。  
  
工具点击**阅读原文**获取  
  
鹏组安全社区  
服务: 常态化更新漏洞情报、渗透技巧，开发Nday漏洞利用工具，提供空间测绘  
账号助力挖洞等等。  
  
👇点击下方链接查看详细介绍👇  
  
[鹏组安全社区VIP福利介绍V1.2版本-社区介绍](http://mp.weixin.qq.com/s?__biz=Mzg5NDU3NDA3OQ==&mid=2247490425&idx=1&sn=25a8d41abbf66fd731cd18d6d1c359f0&chksm=c01cd7e9f76b5eff49eaae3e20809e744b3ec40227169c54a203e1af6b867d42f7a2bdf988f1&scene=21#wechat_redirect)  
  
  
更多工具详看社区地址：  
https://comm.pgpsec.cn  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyN92OtiagxgUpDAeq8RbcPacH8L82CwLzHtvucDrP1RrgfzeUYY8cS4WHk8niap3jKZzys9wK5oHB9w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
渗透测试工具箱  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyNpkpFgujbn9mggiaJFKVwCUsIJSmTmdYeicjEeXI5D0BsnhVhoN1J0utVTh13scPl1BibVl0DL9aKmA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyNpkpFgujbn9mggiaJFKVwCUuQZTicZgpNYl9bNH5AZ9LS0lGDuqZbsXGL0256vJbbiaRysUuqaFThIw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
魔改开发的一些工具  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyNpkpFgujbn9mggiaJFKVwCU04KZia6diapxZaib8ksGpyCfQDoia1TVrnaf6AJn5pQe9OEYbVoN3Y5WHw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
社区中举办的活动列表  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyN92OtiagxgUpDAeq8RbcPacMia7NDpiagkVUILjzUYrd09EYq1aLRAibTRoszh0HrGfJEBibJIZibicBwsw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
免责声明  
  
由于传播、利用本公众号鹏组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号鹏组安全及作者不为  
此  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  

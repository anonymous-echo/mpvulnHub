#  一款简单好用的漏洞管理工具-miscan   
点击关注👉  马哥网络安全   2024-12-16 09:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAliaic0KIAYzx92YgY0Kbic1ByRdVrsvCicRzOUia0LOEP6Hc86gTVoSmWL3jMtEwpTqZoZV0DLABGSOLw/640?wx_fmt=png&from=appmsg "")  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92x9nHdNAzYxtETCLrsD3wg51LG9xsrTicAVibjb7653qcTWB8k92hGiadg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92tG6Y84ciaDmIAoQxOxc2s3NJANGibpxmOTzibxVp8ib4FkzTMl2mxjH8oQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
填写好产品名称、漏洞名称，然后将请求包复制出来，粘贴到请求1中，响应包中可以使用正则匹配，点击保存即可  
  
https://www.jyshare.com/front-end/854/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92br22xCwXbqnCL8c6BuKqPBbAPibO86icX0bWJgKSb3pRFkQKHZqVG9Bw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92rotFurog17g5gmhV12uddJvSykPL2CamNLrb72OUn6G683ibJbcpkRg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
检测测试，可成功发现漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92j4JKdhRHgE9auqk7eibYIYPzWlSic2Mox0JugiaPbUYxcGQWhbucdsRhw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**2、如果需要发送多个请求包**  
  
后面的请求需要使用到前一个响应包中的信息，  
例如下面这个蓝凌getLoginSessionId任意用户登录漏洞。  
  
1、获取sessionId，填入请求，在响应的地方匹配  
sessionId  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92Igq04Ms2HzIlev6hTtb2ArRbRibHT9HPzohcPpL9AYlUvIzI52QAJiaQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
2、  
点击下一步，将sessionid添加到第二次的请求。然后获取返回cookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92TMXfHkj26fjVCFSYt8Owic1JajMUiauibr6AJSbYlbGfCM4iaN0qcua2pA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
3、点击下一步，  
将cookie替换访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92oYTV4pic6O3TPFHtN1eA0J7TeuZWYLBtxSUib28AZCWAn0FcIJKYNGlw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**3、需要使用dnslog验证漏洞存在**  
  
将请求包复制到请求1中需要dnslog的地方用{{dnslog地址}}即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92MMc4c4IIiagaR8RRKDdhSnhnNa8PDWWvkZRkyIUud2pcibEeibPqFAZibg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**4、发送的请求包中存在字节流的数据**  
  
将请求包复制到  
请求1  
中需要字节流的地方放入到b64decode{{中}}即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyP3asA0uib1tvbudB4Jlics92BOiaUhZiafkicNlSK8lZq3HdbTq6aNcIoRl5PV0UBZYicicgsQmr5NEuU0w/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
一套流程测试下来感觉还是非常的好用，爱用。  
  
内容转自鹏组安全，如有侵权请联系删除  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaIicfo73Ma1vawibO9wLYILrhQIfwChvgOImKZkuNWI8GOooRxib2zV6HqibN8GUXECib6tPedP736qeiblicT5gTbstA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/utAMSQWh9sUWmzvbEqyVxYPkYu24CRrXIPaUiaibicvhTUX0icpbo8Ia1b5UpPLuibvVlQmiaocIsuPY2jE7jSHBae6w/640?wx_fmt=png "")  
  
END  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAlsibPLBWFYAlDhUsnJ5qH1jMtVdyXVoticG0Gjic6nrccpBRMUEwax9ndXjltibGyTR8ycDgLWU1p5Sg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAlofwuiaeZjBZnqGI4RmketSpUAfeg6Ubb9synTRvsicobTk4icRZaciaxkOrKZUnkr3Qr6OSEks1m8mQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaIicfo73Ma1uic9ZGkCFpwBiaw1YVt1l4Uibcibk8C6C52t27qBiaw37w5ko1SnjuyT011DBH2jjPQNnpcFMtAFLibGGQ/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  

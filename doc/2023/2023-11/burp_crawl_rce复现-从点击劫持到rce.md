#  burp_crawl_rce复现-从点击劫持到rce   
原创 kkk mr  漏洞推送   2023-11-07 23:24  
  
> 漏洞来源 https://hackerone.com/reports/1274695  
  
## 漏洞环境  
  
burpSuite 2021.7  
  
https://portswigger-cdn.net/burp/releases/download?product=pro&version=2021.7&type=jar  
  
  
poc文件见h1链接  
## 漏洞复现  
  
添加一个扫描任务，用于启动burp内置的无头chrome  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1f0FZGNemKliadkkEmQlhF8wP9bhzWx1HhIIPQE5aoJo5xlKbAGrbnR7v0o45d2hOSyckmaicQhyDGg/640?wx_fmt=png "null")  
  
启动以后用 python3 -m http.server启动一个http服务，然后用chrome打开burp.html  
  
打开以后会尝试 扫描本地的chrome的debug端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1f0FZGNemKliadkkEmQlhF8wjLHLYB2AUN8B77PoibsVAU1uDW6hTRicOajSL0wm2LbyEAtYAQdviaQkg/640?wx_fmt=png "null")  
  
扫描到了以后会创建一个iframe 地址是 http://127.0.0.1:49576/  
  
该页面的内容为，多个A链接:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1f0FZGNemKliadkkEmQlhF8wHLEEaCqEcwZ1Lmu0rXW1pTWSia5G1hwWqDhZQ7ic7icphv7941zXQ3A7A/640?wx_fmt=png "null")  
  
然后使用点击劫持，当点击CLICK ME以后实际上是点击 http://127.0.0.1:49576/下的 about:blank链接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1f0FZGNemKliadkkEmQlhF8wXEXzwI6bqzTBMZTdZnhQmscDP81cnWAxBiaTEic9lGm5dT2gTwYKJfeg/640?wx_fmt=png "null")  
  
iframe发生跳转,地址为  
  
https://chrome-devtools-frontend.appspot.com/serve_file/@4bb19460e8d88c3446b360b0df8fd991fee49c0b/inspector.html?ws=127.0.0.1:49576/devtools/page/9D8411A3AA381D422364000736AE56D9&remoteFrontend=true  
  
这个地址中包含最重要的 ws=127.0.0.1:49576/devtools/page/9D8411A3AA381D422364000736AE56D9这个地址可用于chrome调试  
  
那么这个时候，问题就是怎么拿到这个iframe中的地址了，因为这个同源策略，我们在top页面上只能拿到http://127.0.0.1:49576/这个地址，点击a连接跳转以后的https://chrome-devtools-frontend.appspot.com这个地址我们是拿不到的  
  
比如这个页面，我们在127上iframe到另一个域的网站，然后a链接跳转到7k7k，我们通过src拿到的还是127的地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1f0FZGNemKliadkkEmQlhF8wWN9EBWwMauWcGm3JX8ObgmbCABHgvjdv0YOMA8ZiaCTPvJQarH5MpYw/640?wx_fmt=png "null")  
  
如果想要拿到真实的src地址，就要同源，我再iframe一个7k7k,在这个iframe下就能拿到真实的src了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1f0FZGNemKliadkkEmQlhF8wK21IR1X4knjvemy9X7pL0AeOribQlia9ibWZjabdXPVywW8oSdFV3e57Q/640?wx_fmt=png "null")  
  
于是攻击者利用了appspot.com下的一个dom xss漏洞,新建一个iframe页面，然后把地址通过postmessage发送到top页面，得到了ws地址  
  
https://chrome-devtools-frontend.appspot.com/serve_rev/@191797/devtools.html?remoteFrontendUrl=javascript:top.postMessage(top.frames[1].location.href,"*")  
  
拿到这个地址以后，通过chrome-remote-interface就可以操作浏览器的行为了。配置文件下载路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1f0FZGNemKliadkkEmQlhF8w5KgiaeMhkuAIWK8cM450vybuqZyCJTjuEbvHVXSrniadc9PZNCHhWNjQ/640?wx_fmt=png "null")  
  
然后用blob协议发起文件下载请求，就能够实现任意文件写入了  
  
值得注意的是，这个作者实现mac rce的方式也是很有价值是通过，覆盖burp的vmoptions来实现的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/noZJ3Kqbu1f0FZGNemKliadkkEmQlhF8w4ZaGqIA5aswOGgjh8H2cCiaGrmUp2Tlic4DOLZj1zgqj33CxZqCMaLPg/640?wx_fmt=png "null")  
  
给jvm设置极小的内存，burp会迅速内存耗尽，触发了OnOutOfMemoryError选项导致命令执行。  
  
在这个案例中，一共使用了js扫描探测端口->点击劫持->dom xss->操纵浏览器实现任意文件写入->jvm rce。攻击链相当复杂，虽然实战中可利用可能性不大，但是相当具有参考价值。  
  
  

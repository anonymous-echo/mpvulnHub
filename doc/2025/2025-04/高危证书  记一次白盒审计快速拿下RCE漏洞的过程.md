#  高危证书 | 记一次白盒审计快速拿下RCE漏洞的过程   
 进击安全   2025-04-23 09:58  
  
```
免责声明
  由于传播、利用WK安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负
责，WK安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除
并致歉。谢谢！
```  
  
  
**0x01 前言**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgj8FLvRIaIp8LuV31j8SZpWDJUia04nl5VYsBy1GswAHXaed1DE1gic2y8QTb1Zx7YWibxatlkmKpHw/640?wx_fmt=gif&from=appmsg "")  
  
  
    上上个星期，有个佬给我发了一份Code，然后正好有空，拿出来看看(如果想沟通Code的师傅们，欢迎私信交流)![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIH5orJuA9Bkf8phqOGs2l17mRAUbBnOSaR2585ZZyJ2qIH4kJKAibBzCgyg3DtmQp7iaMbobia9LnLmw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**0x02 漏洞审计**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgj8FLvRIaIp8LuV31j8SZpWDJUia04nl5VYsBy1GswAHXaed1DE1gic2y8QTb1Zx7YWibxatlkmKpHw/640?wx_fmt=gif&from=appmsg "")  
  
  
    系统采用的是PHP语言编写的，直接导入到Phpstorm里面，先查看系统的整体结构  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIH5orJuA9Bkf8phqOGs2l17VnZw9ftAK9NdmCxUHJuOpicCN6HhkIqQuInJauOfJGnO0DI6OI61icxQ/640?wx_fmt=png&from=appmsg "")  
  
基本可以确定，并没有采用什么框架，每个文件都有可能是我们的"突破"点，当然还需要去进一步分析，接下来看一下鉴权情况。先去查看index.php入口文件  
  
整个index.php文件就是进行引入各种配置文件、初始化一些参数等等。当时看这个Code时，临近下班了，也没去细致查看index.php里面具体是干什么了，通过查看多个文件，发现鉴权是通过这段代码进行控制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIH5orJuA9Bkf8phqOGs2l17gIm2L32Iibvo64Sd8tt3vQxK8ibTXJv1InlicVj3zFzRwfuCiaH7pRxSPA/640?wx_fmt=png&from=appmsg "")  
  
那我们就直接把不包含有这段代码的Php文件进行过滤出来，不就是无需鉴权的文件了，然后再这些无需鉴权的文件内去匹配危险函数关键字。  
  
这里采用下面这个语法进行过滤  
  
也是直接搜索出来了一堆  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIH5orJuA9Bkf8phqOGs2l17VJA4TJzVXPRveMiaM0TNmvxznxWAsksJzcd3dic1T4zJxEwtzbPer4hg/640?wx_fmt=png&from=appmsg "")  
  
额额.... 实在看不下去，在一堆东西，继续缩小搜索范围，在进行了几次范围的缩小之后，成功定位到一处  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIH5orJuA9Bkf8phqOGs2l17siabCiblFbFUY2QNlqJ6O867X8r1kxlg8DGzooAh8fh76iaPkpiafHicjBg/640?wx_fmt=png&from=appmsg "")  
  
舒服了 直接进行拼接，尼玛！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIH5orJuA9Bkf8phqOGs2l17Mia3je9QkHn55fNWuhznw9O7ibEOmMSZHNIJkicB6Mb4F9vNvJR9UYz6g/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞复现**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgj8FLvRIaIp8LuV31j8SZpWDJUia04nl5VYsBy1GswAHXaed1DE1gic2y8QTb1Zx7YWibxatlkmKpHw/640?wx_fmt=gif&from=appmsg "")  
  
  
直接拼接了$ping_host 参数，然后又用了popen对$cmd进行命令执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIH5orJuA9Bkf8phqOGs2l17KY8yyOP3s7YJGC8s38dib4qCIgT0CMzLjVsWf75wxchZ0RE3DU6hRKQ/640?wx_fmt=png&from=appmsg "")  
  
访问成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIH5orJuA9Bkf8phqOGs2l17CFoI5Cu7UzBJkAR7pk6zcvC72C0KWtiaiaxm5Evs85Xb7WAbB8QXQSow/640?wx_fmt=png&from=appmsg "")  
  
交流、代码审计培训等  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgj8FLvRIaIp8LuV31j8SZpWDJUia04nl5VYsBy1GswAHXaed1DE1gic2y8QTb1Zx7YWibxatlkmKpHw/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  

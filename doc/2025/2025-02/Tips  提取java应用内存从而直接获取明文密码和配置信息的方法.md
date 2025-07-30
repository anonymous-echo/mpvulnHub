#  Tips | 提取java应用内存从而直接获取明文密码和配置信息的方法   
 sec0nd安全   2025-02-16 09:30  
  
很久没发文章了，最近时间零零散散的。新开一个栏目，平时打项目时在网上发现的或者自己捣鼓出来的小技巧专门丢到这个栏目里。这个栏目的每篇文章的格式可能不会很严谨，文章内容也不会很长，主要是分享一些实用小技巧。  
  
平时在做渗透的时候，偶尔会遇到一些java应用的配置文件做了加密，常见的有druid、jasypt对数据库连接字符串的保护，这些比较经典的加密已经有仙贝写好了脚本，有一些现成的工具可以直接解密。但是有些情况下我们可能遇到开发者自定义的一些很复杂的加解密逻辑，我们当然可以深入代码，手搓出解密脚本，但是比较耗费精力，笔者近期就在实战中遇到一个类似的情况，最后使用本文中提到的姿势解决了。  
  
这种情况下，有没有什么比较高效的提取明文配置信息的方法呢？这让人想到一个经典的攻击场景，目标存在heapdump泄露，我们拿到heapdump文件之后，就有各种办法直接提取出敏感信息。这个heapdump其实就是目标应用的内存文件，如果我们有办法获取到指定java进程的heapdump文件，那么就可以很方便的获取各种明文信息了。这也是本文的核心思路（其实对于java开发也是老生常谈的一些知识点啦）  
  
  
①通过JavaPassDump进行提取  
```
https://github.com/corener/JavaPassDump
```  
  
如果你已经获取了目标java应用的webshell，并且目标支持解析JSP，那么可以试试上面的项目，其中有一个DumpHeap.jsp文件，在web环境上传这个jsp文件并访问，即可生成当前web环境的heapdump文件，随后我们就可以有各种方法进行分析了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgYAvFSZBjIK7wTTOAibXKJvI0zyZzl16aibK0pGibPnd7xBLxiaqqDa83L2Ke50gG0DggMoA47Z4m07mw/640?wx_fmt=png&from=appmsg "")  
  
  
②通过jmap进行提取  
  
有些时候我们并不能拿到一个允许执行JSP的java环境，大多数时候，项目被打包为jar包，我们可能是通过各种漏洞反弹shell or 打内存马，甚至是通过非java项目的漏洞打上的服务器，这种有命令行的情况又该怎么从内存中提取信息呢？  
  
首先可以使用jmap，jmap是java自带的工具，只需要提供java进程的pid，就可以保存其内存里的信息。  
  
首先执行ps aux （linux环境），找到目标java进程pid  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgYAvFSZBjIK7wTTOAibXKJvIsYt06LzE9KrkVpd0iawIJYaCp1DojZXKFz7QJZSHtCI0Gj2DjfKagYw/640?wx_fmt=png&from=appmsg "")  
  
然后运行下面的命令进行导出：  
```
jmap -dump:format=b,file=文件名 [pid]
```  
  
例如：  
```
jmap -dump:live,format=b,file=/tmp/heap.hprof 2241017
```  
  
不过，较高版本的java似乎没有jmap  
  
  
③通过jcmd进行提取  
  
首先运行一下jcmd，如果存在，那么你可以看到当前正在运行的java应用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgYAvFSZBjIK7wTTOAibXKJvIFzkib2r02PLH7CY8hA8QbOHNyLYTPqhJfr6ojF7hWDjyib3yskr5wfrg/640?wx_fmt=png&from=appmsg "")  
  
最左边的一堆数字就是pid，很方便，不过这里出于保密要求还是打码安排上，使用下面的命令导出  
```
jcmd <pid> GC.heap_dump <path>
```  
  
例如：  
```
jcmd 2241017 GC.heap_dump /tmp/test/heapdump
```  
  
然后用很多工具都可以分析这个heapdump了，例如JDumpSpider、heapdump_tool等等，就和/actuator/heapdump泄露的打法是一样的，这里面基本都是明文信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2A06BE6JXgYAvFSZBjIK7wTTOAibXKJvIyBtfdPH1Z92ZlxxGfKrv9L7Ftrperr2bicwy1jKTicgqlbda3iahiaWMdQ/640?wx_fmt=png&from=appmsg "")  
  

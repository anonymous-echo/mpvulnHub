#  aiohttp路径遍历漏洞分析(XCE-2024-1472)   
 船山信安   2024-11-18 01:18  
  
# 前言  
  
微步发的漏洞通告**aiohttp**存在路径遍历漏洞，**fofa**搜了一下资产，确实挺多的，因为**poc**没有公布，所以并不知道漏洞的详情，但是见了这么多的路径遍历，基本上都不会产生什么变化，最多就是转换下编码的问题，比如说**GlassFish**出现的**UTF8**超长编码导致的任意文件读取等等，于是就来简单分析下，顺便学习一下aiohttp处理请求的一些流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nD6GyeSIooMfro34oGQR4bEfcPFnT3ODf3ibyCs8dyJ0XY4VV5MfwRQQ/640?wx_fmt=png&from=appmsg "")  
# 关于aiohttp  
  
之前并没有使用过**aiohttp** 进行一些开发的操作，所以对这个框架的处理源代码并不熟悉，但是应该与async这类异步的东西有关系。  
  
aiohttp 是一个基于异步的 Python Web 开发框架，可用于编写基于 asyncio 的异步网络应用程序。它提供了对 HTTP 客户端和服务器的支持，使得编写高效的异步 Web 服务变得更加简单。  
  
aiohttp 基于 Python 3.5+ 的 asyncio 模块，使用异步的方式处理网络请求和响应，从而实现高并发的网络通信。它支持 WebSocket、HTTP/1.1 和 HTTP/2 协议，并提供了丰富而灵活的 API，使得开发者能够轻松地构建异步的 Web 应用程序。  
  
使用 aiohttp，开发者可以通过异步的方式处理并发请求、管理长连接、支持 WebSockets 等功能，同时享受到 Python 的简洁和易用性。它非常适合构建需要高性能、高并发的 Web 服务，尤其适用于 I/O 密集型的应用场景。  
## 源码对比  
  
从aiohttp源码 里面对比一下版本，大致能够知道开发者修复的东西，这里修复的版本后是3.9.2之后，所以这里拿了3.9.1与3.9.2对比找修改的地方，最终是在urlDispatcher即URL的分发和处理模块找到了异常，开发者更改了条件判断语句的方式，并且原先的joinpath改成了os.path.normpath，os.path.normpath有一个优点就是会消除掉路径中的.或..分隔符，返回规范化的路径，这里原先的代码应该就是漏洞的产生点，也就是与follow_symlinks参数有关。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nxQjgh2O0c9HLVdNq9iaj7TDUGHMoz8HOfne4ZmQgMthmDUUgx6kQzWQ/640?wx_fmt=png&from=appmsg "")  
  
关于follow_symlinks:  
  
在 **aiohttp** 中，follow_symlinks 参数用于指定是否应该跟随符号链接。符号链接是一种特殊的文件类型，它是文件系统中的一个指向另一个文件或目录的链接。当 follow_symlinks 参数设置为 True 时，**aiohttp** 会跟随符号链接来访问目标文件或目录；当设置为 False 时，**aiohttp** 不会跟随符号链接而是直接访问链接本身。  
  
用例子来说就是，比如有下面的这样一段代码：  
```
```  
> 比如说这个例子如果在static文件夹里面创建一个link的符号链接，指向另一个文件夹，那么就可以通过/static/link访问符号链接指向的静态文件，也就是另一个文件夹中的静态文件。  
  
# 漏洞分析  
  
看上面的改的代码修复方式，应该就是最简单的../穿越的形式，通过**fofa**找资产来进行测试的时候，验证到确实是这样的，当访问一些静态文件的时候，可以通过目录穿越的形式进行文件的读取。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nFKDcNfSeVG9JZdeuOsjQBSccMia1jmmiaFceaDKgLVNpn7YtrJ8hkPOQ/640?wx_fmt=png&from=appmsg "")  
  
尝试在本地起环境，因为是与静态文件以及follow_symlinks有关系，所以应该是在设置静态文件的访问路径的时候通过add_static函数造成的。  
```
```  
  
程序就五行代码，在这里打断点访问静态文件肯定是没反应的，所以只能在处理源代码里面打断点，首先简单分析下在启动程序时add_static的操作，它会到web_urldispatcher#StaticResource静态资源类中根据参数配置一些静态资源。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30n5ACskHC2KnxfDEtC7IMeDuIjP7wAO7d6PwA4VE8j9FKsJIkTuwzbhg/640?wx_fmt=png&from=appmsg "")  
> 首先根据你写的路径创建一个Path类，就是指明静态资源的文件夹路径，然后判断路径是否以~开头，对linux系统中用户目录做特殊处理，然后判断路径是否是目录，是否为空，最终将foolow_symlinks、chunk_size等赋值进去，chunk_size是返回静态文件时分块的大小，最终配置路由和处理器，只允许GET或HEAD请求，这里的_hadler是静态资源的处理器，即StaticResource._handle  
  
  
创建完成staticResouce类后，通过register_resource对静态资源进行注册。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nkgkVSAv7nMR60G6OrFo0iaL5FAvialBDa10FKwPzQGQCoX4nsRXYfcWA/640?wx_fmt=png&from=appmsg "")  
  
在register_resource方法中，判断资源类型是否是动态资源(指的是通过请求响应动态生成的一些页面等资源)，再判断注册的路由是否是不可用的路由中，下面再通过是否赋值了name等特殊处理，最终是将资源加到了_resources列表里面完成了add_static  
  
下面是漏洞请求触发的具体流程：  
  
首先发起请求后，会进入到_handler，判断是否有线程循环，是否是debug模式后，会来到UrlDispacher类的resolve对路由请求进行处理，获取到请求的method后，遍历前面的资源列表获取resource，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nexcU8YpGjW2OaU84uYDNGNEia9vfrLo7bdw72rNh0XcTkg89pv4DOVQ/640?wx_fmt=png&from=appmsg "")  
  
resource.resolve的处理逻辑也是十分简单，获取到请求的完整文件路径后，通过self_prefix也就是add_static时候写的/static，然后从完整路径中去除/static作为文件名，最终返回请求方法和一个UrlMappingMatchInfo类，这个类记录了请求的方法，文件名，要处理的handler，请求的路径等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30n5KbGmY41lm7CAG0uGbjDuRHepe5Dht6jpYGcflghh45o9B0c68Mmiaw/640?wx_fmt=png&from=appmsg "")  
  
当请求的前缀是正确的，并且方法也是允许的，返回一个有效的UrlMappingMatchInfo返回到_handler中，经过异常处理后，将应用程序对象添加到路由匹配信息，路由匹配信息用于存储与请求 URL 相关的路由信息，包括路由处理函数、路由参数等，当这些路由信息都准备完毕，通过freeze锁定路由信息，确保在后续的处理过程中信息不会被意外修改。再从请求头中获取Expect的信息，选择expect_handler 处理器处理(这里没有)，它就选择了UrlMappingMatchInfo中的StaticResource._handler进行处理。  
  
选择好了handler后，会通过判断是否有中间件，先做中间件的处理，这里没有就不看了，最终会使用选择到的处理器处理request请求。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nXYCYUdKR1EMFneSEPVqh2WuNianibqvhJw89tdUaA5dcMkk1q4dic8vtg/640?wx_fmt=png&from=appmsg "")  
  
来到处理器对应的方法后，会取出先前的文件名，然后创建Path类，Path类对判断系统，分出Windows系统或是其它系统，如果是Window系统，会调用_from_parts将文件名中的/都转换成\。然后会判断filename.anchor，这里的作用就是不允许http请求的静态资源文件名存在类似于网络共享路径或本地盘符路径的写法。![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nYNsRtVfD6mwdSEDCGr4D28zxwTfShT12v3micgFQ8xeNCVRsez2ibT8w/640?wx_fmt=png&from=appmsg "")  
  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nkSzPshlhG2z4SRWQy5RytIPhicCs1ytO9DK5OC41YnbYJp0TCsYB9UQ/640?wx_fmt=png&from=appmsg "")  
  
最终来到了漏洞的语句filepath = self._directory.joinpath(filename).resolve()中，在处理joinpath的时候，它会将filename以为\分开，分成驱动器，根，parts，同样也会将前面预先有的静态文件的绝对路径以同样的形式分开，一起传入到join_parsed_parts中。  
  
这里的以E:\\src\images\icon.jpg表示的话，drv=E： root=\\ parts=[E:\\,src,images,icon.jpg]，而filename请求文件名的drv2=空 root2=空 parts=图中所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30n0W141BRnU7YB2rmQa8FDTg2BQJuNhSCAibOibJB4ja9DbzKibmc3AT1ng/640?wx_fmt=png&from=appmsg "")  
  
在join_parsed_parts中，会进行条件判断(看下面)，我们的请求方式会来到第三个else，因为我们访问的静态资源取出的filename是相对路径，没有驱动器，也没有\\，最终返回的其实是 ('E:', '\\', ['E:\\', 'aiohttp', 'src', 'images', 'images', 'icon.jpg', '..', '..', 'data.db'])，其实前面的两个条件判断处理，也是为了最终返回的parts要是完整的绝对路径，但是没有对..进行处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nTWVAia4s2kDH03ULhRrEbQibUz0IHvC2GjrbwzljJ22oU0o2VTSP6quQ/640?wx_fmt=png&from=appmsg "")  
- 当 root2 不为空时，且 drv2 为空且 drv 不为空时，将 drv 保留，将 root2 作为新的根，并将第二个路径的部分连接起来，形成一个新的路径元组。  
  
- 当 drv2 不为空时，判断两个驱动器是否相同，如果相同，则认为第二个路径是相对于第一个路径的，将第一个路径的信息作为新路径的一部分，并将第二个路径的部分连接起来，形成一个新的路径元组。  
  
- 当以上条件不满足时，将第二个路径作为非锚定的路径（即普通路径）处理，将两个路径的部分连接起来，形成一个新的路径元组。  
  
返回了绝对路径的parts之后，来到resolve方法，resolve方法会通过os.path.realpath对self也就是刚才parts部分进行处理，规范化了路径，将两个..去掉，并把目录往前移了两位。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nFB2DHDyv5mRIShHBwoicncibVu8pSNGTYr0He11xgdFU3IvdxiaFGme6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30n6Bibiaahcd4Pwr7mrSib7QibWicyffP7SZlTZUCOic4t2KABymuiccLzvCPdw/640?wx_fmt=png&from=appmsg "")  
  
继续往handler下面走，如果前面得到的规范化路径，也就是E:\\aiohttp\src\images\data.db是一个目录，则将目录转换成html页面返回，如果是文件，则使用FileResponse返回。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nictJy6m2wDdBTiaIkbIpKTTtNmJwgvzRNAnTqUIoLt33iaIN1l7Cd8n3g/640?wx_fmt=png&from=appmsg "")  
  
直至这一步，filepath就被确定了，到FileResponse后面还有挺多处理的，包括根据Content-Type来进行不同的响应如Gzip、application/octet-stream等，以及各种请求头做对应的处理等等，就不继续看下去了。  
  
为什么follow_symlinks==True，当follow_symlinks!=True回进入relative_to获取文件的路径，这也是后面修复使用的方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30nicmz1sbv7HeF67IXk0ViaoHZ74fACmhqW3ysFKPHrSoGfh98XUqu6DcA/640?wx_fmt=png&from=appmsg "")  
# 修复  
  
修复主要是改变了原先路径的拼接方式，将拼接的方式改到了relative_to方法，通过比较请求的filename路径相对于指定的静态目录路径，如果请求的filename路径不是静态目录的子路径，则会抛出异常，最终返回404  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicP8Wia0Urd6ITiadLzWkMB30noVKTiaYhrZ1l8svX8TLuFw9YQnBF3Zib031E8HC5JN1wcJDnKc1u9xLw/640?wx_fmt=png&from=appmsg "")  
```
```  
> 首先，将当前路径(filename路径)和传入的其他路径(静态目录路径)参数进行解析，提取出各自的驱动器（drive）、根路径（root）、路径部分（parts）等信息。接着，根据条件判断当前路径和其他路径的情况，包括是否带有根路径或驱动器等。进行路径的比较，判断当前路径是否是其他路径的子路径或在同一目录结构下，如果不是则抛出异常。如果当前路径是其他路径的子路径，则返回当前路径相对于其他路径的相对路径。  
  
# 总结  
  
主要是因为开发者在对follow_symlinks==True情况时，处理的方法不对导致的，没有对请求的filename路径与静态文件的路径进行比较判断是否是子路径导致的问题。写的比较啰嗦，主要还是为了看看aiohttp，这个框架的代码为了达到异步，里面用了很多的await对定义函数的处理。  
  
来源：https://xz.aliyun.com/   感谢【  
Aiwin  
】  
  
  

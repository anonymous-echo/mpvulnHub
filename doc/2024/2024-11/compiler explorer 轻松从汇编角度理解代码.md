#  compiler explorer 轻松从汇编角度理解代码   
 进击的HACK   2024-11-15 23:55  
  
## 介绍  
  
compiler explorer 是一个交互式编译探索网站。用C、c++、c#、f#、Rust、Go、D、Haskell、Swift、Pascal、ispc、Python、Java或其他30多种支持的语言组件编辑代码，并查看代码在实时编译后的样子。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DuibU3GqmxVmRsdItbBVRKegNHicHQvAHDdZsGpLVU7touSU1AU1twHTfRjG3Vu5aUh0RnPPllfVUhs4qdWF5QYQ/640?wx_fmt=png&wxfrom=13 "")  
  
声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途给予盈利等目的，否则后果自行承担！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zYJrD2VibHmqgf4y9Bqh9nDynW5fHvgbgkSGAfRboFPuCGjVoC3qMl6wlFucsx3Y3jt4gibQgZ6LxpoozE0Tdow/640?wx_fmt=png&wxfrom=13 "")  
  
  
截止目前，star 16.4k  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaaeH06JQjG2Dh0mz7d6Q4ibbeRmUUpYSZUMQVZfaGRiaYv4bia29tgK1ePDZcD1woiaR6G4CPNLHBYkg/640?wx_fmt=png&from=appmsg "")  
### 优点  
  
有在线版，国内可这直接访问 https://godbolt.org/有github开源地址，可在本地搭建 https://github.com/compiler-explorer/compiler-explorer  
  
可以从底层观察各个函数是如何构成的，程序是如何运行的。  
  
C、C++、Java、Python都是高级语言，它们为了方便我们人理解，语法进行了很多人性化的操作，方便上手和理解。但随着时间推移，用的多了，项目复杂后，我们可能会变得疑惑，这么写和那么些有什么区别，为什么这么写有问题。  
  
有些东西在高级语言上看不同的东西，其实在CPU看来是没有区别的。  
  
比如 int i 和 int* p，在汇编代码层次，他们并没有区别，都是给一个栈地址赋值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaaeH06JQjG2Dh0mz7d6Q4ib1dF5SRbRqXib896F63v4icY0DCw6KsKgkb6Y104QKtIHqCT6kDJlRibbQ/640?wx_fmt=png&from=appmsg "")  
  
对于想要入门逆向的人来说，用 compiler explorer 来了解高级语言和汇编之间的对应关系，为后续逆向汇编，从汇编反编译成高级语言也很有帮助。  
  
案例：下面都是支持的语言https://github.com/compiler-explorer/compiler-explorer/tree/main/examples  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaaeH06JQjG2Dh0mz7d6Q4ibxOW2DM65WGic85ppVNBQuNZu5Fpfah6OsIclQAUVKdTz2ia5tIcwA8FQ/640?wx_fmt=png&from=appmsg "")  
  
推荐一本书：《CPU眼里的C/C++》，微信读书上也有  
  
  
作者根据 compiler explorer 工具，分析了C/C++当中遇到的常见指令，比如指针变量和一般变量的区别，goto和if、for、while的区别。从底层的视角看，往往能解答很多我们在高级语言中看到的代码的疑惑。  
  
让我印象最深刻的时候，是看 goto 和 for 的区别，这在C语言中是两个不同的指令，但在汇编层次，我们用 goto 构造指定的代码，然后到了CPU验证，汇编指令是没有任何区别的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaaeH06JQjG2Dh0mz7d6Q4ib652RRZPNlxgogV59fm5gzfwxCNCnM2kqOHyUzZWqzMIZib55Kt4IeuA/640?wx_fmt=png&from=appmsg "")  
  
还有就是 i++ 和 ++i 的区别。如果是在大学学过C语言，参加过考试的，一定会见过对这两种区别的考核，问最后的结果是多少。从C语言上看，可能不明所以，但到了汇编，具体过程就一目了然。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbriaaeH06JQjG2Dh0mz7d6Q4ibvVicJibeR3vInwD69fNz3IBz5kAVKUQyroCiaHBuh6Z23iaGskbN3MYTpA/640?wx_fmt=png&from=appmsg "")  
  
  
往期推荐  
  
[基于flutter的Android vpn代理工具](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486777&idx=1&sn=9c0144199ee718665d6bd790bfb1ee26&chksm=c150aad2f62723c4c2ecbcb94e2d7edbcf4064074d512b96620401dfe59e692ed136406b9dfe&scene=21#wechat_redirect)  
  
  
[用友漏洞一键探测利用](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486765&idx=1&sn=491b37f45c408d9dee05bff7e18a5173&chksm=c150aac6f62723d0ce47ddd18c39fc24525a39be5d9032bf0bdd6a565c4503fd616e39ee6831&scene=21#wechat_redirect)  
  
  
[Jar Obfuscator - 图形化 JAR/CLASS 字节码混淆工具](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486687&idx=1&sn=bd93740fbab2f192142c3c56ee3c3074&chksm=c150ab34f62722221c32a6cd3b9e051fe0f7383d8c7fae763d428b8a117d61eacd43bbe01428&scene=21#wechat_redirect)  
  
  
[降低js逆向分析难度的油猴脚本](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486673&idx=1&sn=d7ca2ae0861850d4807ff558468c79ba&chksm=c150ab3af627222c68566213b34cbcdbe0ca008bf01303c539364ae906259f1490d3cab3d265&scene=21#wechat_redirect)  
  
  
[简单绕过 IOS应用 frida检测](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486561&idx=1&sn=6582b889e69674b5bfc7c817ec7ce2b3&chksm=c150ab8af627229c4fa75be0bc1f27e24aef5a51059fb88b7e6de9e0bf33f93aeaa3479a0294&scene=21#wechat_redirect)  
  
  
[burp插件 | 自动丢弃不需要的http数据包](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486478&idx=1&sn=435438f1416fe0ab5345bb7f2be38354&chksm=c150abe5f62722f38e7282c061f587c6dd9be835cf25d2ebe15925a381c370efab48ffc05b24&scene=21#wechat_redirect)  
  
  
[轻松入门，frida n种过app特征检测办法之一](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486441&idx=1&sn=d3ca56d7bb74111768ad6450ef567589&chksm=c150ac02f627251487e69e23f91ae5556b76ea1e28d63aebe5e62bb79ada5603e97f5453e021&scene=21#wechat_redirect)  
  
  
[小技巧 | Proxifier使用Chain实现多级代理](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486353&idx=1&sn=1376103e17556115de4ee25fa40dd8e7&chksm=c150ac7af627256c464d4e981bb3caa42e747646ccc765ae2319a19260be973dbfec29e116ee&scene=21#wechat_redirect)  
  
  
[SpringBoot jasypt 配置文件/属性ENC加密](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486338&idx=1&sn=dbfdeacd4b8a7698f9666e8ed3e8ac9e&chksm=c150ac69f627257ff376a05283e4d101d45dad4e3307f8722c47df3b91107bab38410a32bb78&scene=21#wechat_redirect)  
  
  
[Databasetools 一款用Go语言编写的数据库自动化提权工具](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486295&idx=1&sn=396bbb6655376fcb2cbd32d33bf62187&chksm=c150acbcf62725aa1442f15a872db0a7944e6dff2b55e7c1409e0f49500ab31dca19d7eda1da&scene=21#wechat_redirect)  
  
  
[在混淆的so中寻找sign签名函数](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486092&idx=1&sn=1337e6907b7f0643a3dd361d1b0bdb35&chksm=c150ad67f62724717af1c95f6c45951454ce2fb1c033a7bb366cebd18f41d7775b3fd8ff2d18&scene=21#wechat_redirect)  
  
  
  
  

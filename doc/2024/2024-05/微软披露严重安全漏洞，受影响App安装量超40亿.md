#  微软披露严重安全漏洞，受影响App安装量超40亿   
小王斯基  FreeBuf   2024-05-06 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38CjpE7SgibY8ZVMThOhz1b00HIZUhGXhgLG77KGXkeb2ibaNxXJMBDEz2vIGY2YK954mPNDcicNKCMw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38CjpE7SgibY8ZVMThOhz1b0ycLYBiaw8ibq9jmtbib8JhFJnj7ludraCLcf0nVAKm2crzl5uicBLA2TYQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JUxstKWezpdrYK4Moo0lczKksvlRgbrY6zrzH27UrLDBjFmZYh7owb6MFQPoa1sV57MGib2HJqEbY/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JUxstKWezpdrYK4Moo0lczKksvlRgbrY6zrzH27UrLDBjFmZYh7owb6MFQPoa1sV57MGib2HJqEbY/640?wx_fmt=svg&from=appmsg "")  
  
  
  
  
近日，研究人员披露了一个名为「Dirty Stream」的严重安全漏洞，该漏洞可能影响几款下载总量数十亿的 Android 应用程序。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38CjpE7SgibY8ZVMThOhz1b0eLosdrGXM4wd9VCUASYrVAhr1P7KjZw2bBDBekpUYMvmJML72TYcvw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微软威胁情报团队成员 Dimitrios Valsamaras 在一份报告中声明，威胁攻击者可以利用该安全漏洞，执行任意代码以及盗取令牌。一旦成功利用漏洞，威胁攻击者就可以完全控制应用程序的「行为」，并利用窃取的令牌在未经授权的情况下访问受害者的在线账户和其他数据。  
  
  
这一安全漏洞可能会给大量设备带来威胁风险， Google Play 商店中目前已经发现了几个易受攻击的应用程序，这些应用程序的总安装量超过了 40 亿，其中受该安全漏洞影响程度最大的两个应用程序如下：  
  
- 小米文件管理器 (com.mi. Android.globalFileexplorer) -，安装量超过 10 亿次  
  
- WPS Office (cn.wps.moffice_eng) -，安装量超过 5 亿次  
  
安卓系统通过为每个应用程序分配专用的数据和内存空间来实现隔离，并以安全的方式促进应用程序之间的数据和文件共享。但实施过程中的疏忽可能会导致绕过应用程序主目录内的读/写限制。  
  
  
Valsamaras 表示，这种基于内容提供商的模式提供了一种定义明确的文件共享机制，使服务应用程序能够以安全的方式与其他应用程序共享文件，并进行细粒度控制。  
  
  
然而，在执行的过程中，经常遇到消费应用程序并不验证其接收到的文件内容，最令人担忧的是，它使用服务应用程序提供的文件名将接收到的文件缓存在消费应用程序的内部数据目录中。当服务应用程序为了实现应用程序之间的文件共享而声明恶意版本的 FileProvider 类时，这一「陷阱」可能会造成严重后果，最终导致消费应用程序覆盖其私有数据空间中的关键文件。  
  
  
换句话说，该机制利用了消费应用程序盲目信任输入这一事实，通过自定义、明确的意图，在用户不知情或未经用户同意的情况下发送带有特定文件名的任意有效载荷，从而导致代码执行。  
  
  
这时候，威胁攻击者就可以覆盖目标应用程序的共享首选项文件，使其与受其控制的服务器通信，从而外泄敏感信息。另一种情况是应用程序从自己的数据目录（而不是「/data/app-lib」）加载本地库，在这种情况下，恶意应用程序可以利用上述漏洞，在加载本地库时用恶意代码覆盖该库并执行。  
  
  
值得一提的是，在接到安全漏洞披露通知后，小米和 WPS Office 均已于 2024 年 2 月对该安全漏洞问题进行了整改。与此同时，谷歌也就此发布了详细的指导意见，敦促开发者正确处理服务器应用程序提供的文件名。  
  
  
谷歌方面强调，当客户端应用程序将接收到的文件写入存储时，应该忽略服务器应用程序提供的文件名，而使用自己内部生成的唯一标识符作为文件名，如果生成唯一的文件名不能轻易实现，客户端应用程序就应该对提供的文件名进行核验、清查。  
  
  
最后，微软方面指出，该安全漏洞问题非常普遍，相关开发者应当采取措施，仔细检查自身应用程序是否存在类似问题。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://thehackernews.com/2024/05/popular-android-apps-like-xiaomi-wps.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493411&idx=1&sn=6e2fc6872803cd754a1d6796ea8d1153&chksm=ce1f1dbcf96894aa2d841924f91841720a1f96f4350d488f736af89e16d901aa1d02ca372a4c&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493362&idx=1&sn=39c9b1c4d709e5ad0babb44995b0e412&chksm=ce1f1c6df968957be704d2843b3f448b252d2a2e1b5271efa486c3e57819849e0e287b04568b&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

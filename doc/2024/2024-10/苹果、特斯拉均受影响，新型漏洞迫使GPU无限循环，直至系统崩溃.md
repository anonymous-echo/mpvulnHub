#  苹果、特斯拉均受影响，新型漏洞迫使GPU无限循环，直至系统崩溃   
小薯条  FreeBuf   2024-10-24 18:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39kAI3TcFnhMR7VN4VcqXcLgF13F0HFhoLibJEN7OeLLmsxmpkkJhInJe4MsMQvzibwRaM9PVvicIichg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
近日，Imperva 研究人员发现了一个名为 ShadyShader 的漏洞。该漏洞允许攻击者反复冻结苹果设备的 GPU，最终可能导致系统崩溃。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39kAI3TcFnhMR7VN4VcqXcLCWd9hmcNR0vHw8Wibiaaa7qfrAhxL7UJ9grdr3tTtibtCRxJmG3PokHMA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
研究人员认为，主要问题在于现代 GPU 如何检测和停止无限循环，即如果不终止就会无休止运行的指令序列。虽然 GPU 能够熟练地检测并阻止明显的循环，但研究人员展示了一种方法，即制作一个嵌套循环，并在未被发现的情况下执行。  
  
  
Imperva 公司的安全研究员罗恩-马萨斯（Ron Masas）尝试制作了一个简单的着色器代码，该代码只迭代大量循环，迫使 GPU 执行大量计算。这种代码可以添加到网站上，使用户系统崩溃。它还可以通过信息、电子邮件和带有恶意链接的 QR 码扫描器发送。如果用户点击链接，浏览器就会加载带有恶意着色器的 WebGL 内容，设备就会进入数字迷宫。这些操作往往都无需用户许可，因为在执行许多常见任务时，GPU 访问都是悄无声息地进行的。  
  
  
马萨斯表示，驱动程序无法识别着色器不必要地垄断了资源。这使 GPU 不堪重负，无法再管理其他任务，最终导致系统崩溃。  
  
  
苹果的显示管理服务（macOS 上的 WindowServer 或 iOS 上的 SpringBoard）会等待 GPU 完成任务。当受到 ShadyShader 的攻击时，这个负责管理屏幕的服务就无法获得任何更新，整个系统就会变得很迟钝。  
  
  
苹果设备内置的计时器可以监控关键进程，确保它们不会耗时过长。120 秒后，该计时器会触发内核恐慌，迫使系统崩溃并重启。在 iPhone 和 iPad 上，计时器的反应速度更快，只需 30 秒。  
  
  
研究人员指出：在我们的测试中，Macbook 会在 1-2 分钟内完全重启，而 iOS 设备则会在显示锁屏之前的 3-6 分钟内保持无响应状态，在大多数情况下都不会完全重启。  
  
  
**尽管打了补丁，问题依然存在**  
  
  
  
苹果公司早在 2023 年就更新了 GPU 驱动程序来解决这个漏洞，因此运行最新 iOS 和 macOS 版本的用户应该没有问题。但根本问题似乎具有更广泛的影响。  
  
  
Imperva 警告说：在我们看来，GPU 资源耗尽问题依然存在，并可能在未来的攻击中被利用。我们在其他设备上也观察到了有趣的行为，尤其是在谷歌 Pixel 手机上。  
  
  
一些机会主义测试显示，Pixel 手机上的浏览器应用会变得无法使用，直到用户重启手机，尽管设备并未崩溃。  
  
  
甚至在特斯拉汽车上，Imperva 的研究人员也观察到主屏幕在遭遇 ShadyShader 漏洞攻击后暂时无法响应的情况，不过其关键的驾驶功能没有受到影响。  
  
  
研究人员表示，虽然目前没有测试该漏洞可能带来的全部影响，但所有带有 GPU 和浏览器的系统都可能受到类似的影响。  
  
  
如果用户发现自己的设备因这种攻击而陷入崩溃循环，可以尝试在打开浏览器之前在设置中禁用 JavaScript，然后关闭有问题的标签页。  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://cybernews.com/security/flaw-crashes-apple-devices-tesla-also-vulnerable/  
  
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

#  【安全圈】Windows 零日漏洞正被黑客利用，以此获得内核权限   
 安全圈   2024-03-01 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
被称为 Lazarus Group 的朝鲜威胁行为者利用 Windows AppLocker 驱动程序 （appid.sys） 中的漏洞作为零日漏洞来获取内核级访问权限并关闭安全工具，从而绕过嘈杂的 BYOVD（自带易受攻击的驱动程序）技术。  
  
Avast 分析师检测到此活动，他们立即将其报告给 Microsoft，从而修复了该漏洞，该漏洞现在被跟踪为 CVE-2024-21338，作为   
2024 年 2 月补丁星期二  
的一部分。但是，Microsoft并未将该漏洞标记为零日漏洞。  
  
Avast   
报告称  
，Lazarus 利用 CVE-2024-21338 在其 FudModule rootkit 的更新版本中创建了一个读/写内核原语，ESET 于 2022 年底首次记录了该版本。以前，rootkit   
滥用戴尔驱动程序  
进行 BYOVD 攻击。  
  
FudModule的新版本在隐身性和功能方面具有显着增强功能，包括用于逃避检测和关闭安全保护（如Microsoft Defender和CrowdStrike Falcon）的新的和更新的技术。  
  
此外，通过检索大部分攻击链，Avast 发现了 Lazarus 使用的一个以前未记录的远程访问木马 （RAT），该安全公司承诺在 4 月份的   
BlackHat Asia  
 上分享更多细节。  
## Lazarus 0 天漏洞利用  
  
该恶意软件利用了Microsoft的“appid.sys”驱动程序中的漏洞，该驱动程序是提供应用程序白名单功能的 Windows AppLocker 组件。  
  
Lazarus 通过操纵 appid.sys 驱动程序中的输入和输出控制 （IOCTL） 调度器来调用任意指针，诱骗内核执行不安全的代码，从而绕过安全检查。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljSE8yiak6JHIoRcXTQldm1X8iaYyD0u0wYbeHh5DVLD6xTPORa5ua1OwvDQVrwQe0m2zsnyEibXA7Lg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞利用中使用的直接系统调用** （Avast）  
  
FudModule rootkit 内置在与漏洞利用相同的模块中，可执行直接内核对象操作 （DKOM） 操作，以关闭安全产品、隐藏恶意活动并在被破坏的系统上保持持久性。  
  
目标安全产品是 AhnLab V3 Endpoint Security、Windows Defender、CrowdStrike Falcon 和 HitmanPro 反恶意软件解决方案。  
  
Avast 在新的 Rootkit 版本中观察到了新的隐身功能和扩展功能，例如通过操纵句柄表条目来怀疑受保护进程轻量级 （PPL） 保护的进程、通过 DKOM 进行选择性和有针对性的中断、篡改驱动程序签名强制和安全启动等。  
  
Avast 指出，这种新的漏洞利用策略标志着威胁参与者内核访问能力的重大演变，使他们能够发起更隐蔽的攻击并在受感染的系统上持续更长时间。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljSE8yiak6JHIoRcXTQldm1Xic579tJr8AVMk8PVOUiaZywG7qafEeibcFYBJdKYiamC5ib5HqAl8o5BW2A/640?wx_fmt=png&from=appmsg "")  
  
**Rootkit 的主要功能是执行单个技术** （Avast）  
  
唯一有效的安全措施是尽快应用 2024 年 2 月的 Patch Tuesday 更新，因为 Lazarus 利用 Windows 内置驱动程序使得检测和阻止攻击特别具有挑战性。  
  
可  
在此处  
找到 YARA 规则，以帮助防御者检测与最新版本的 FudModule rootkit 相关的活动。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljSE8yiak6JHIoRcXTQldm1XrTuK66gEJwOAmUJWhLgFYxVrIibue29mxfzcHSiaF8oZMbcmpVuTjvQQ/640?wx_fmt=jpeg "")  
[【安全圈】南昌某超市所属IP被黑客远控，频繁发起网络攻击，被罚5万元！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054869&idx=1&sn=19414a1e61bda2e20a618b7d998d4aeb&chksm=f36e0915c41980033fa307eee53e70e485bf5aabcfb5c80cccefaac2b232663ed326fb01e682&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljSE8yiak6JHIoRcXTQldm1XFaKG5N8AdQoCPKicsYydNTjAmVJxAg5zkP1QEzibkVajvSQibsgPXEXxQ/640?wx_fmt=jpeg "")  
[【安全圈】音乐人包小柏用AI技术“复活”女儿，为妻子唱生日歌](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054869&idx=2&sn=5a2704b75a67170bccbe97734ab5265e&chksm=f36e0915c4198003b67afa48aa5a8584a9df4fbc3f3e20c23e13e5e8a7b13f089230410e1dcb&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljSE8yiak6JHIoRcXTQldm1XghNwiaMicNK0ZZ2mPy2yP6MicrQBiczZZV9LttJXJ3lrz9kib1vQHU8ueVQ/640?wx_fmt=jpeg "")  
[【安全圈】制药巨头 Cencora遭遇黑客攻击，致个人信息泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054869&idx=3&sn=6aa4cb41bc4cdaf6d6844996c6aa9262&chksm=f36e0915c4198003e5a7ed8be3f1efef0e71e366e61eb58bd434418bd552a2c202a2c3979afb&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljSE8yiak6JHIoRcXTQldm1X4stXicnH1lbQFlp9xhAdpDD5X7iaYHHfPyuq57J3XrBswBKPnKvRxWpg/640?wx_fmt=jpeg "")  
[【安全圈】WordPress 插件存在安全漏洞，500 万网站面临严重风险](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652054869&idx=4&sn=e83c805666be44f52ab80d8d0dc86964&chksm=f36e0915c41980036865fffb88c7a61ec3df4ed9bf608b2e232be17ae3a64890873ac8c3e0a0&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  

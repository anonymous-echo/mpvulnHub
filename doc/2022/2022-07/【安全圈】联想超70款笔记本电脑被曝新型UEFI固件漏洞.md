#  【安全圈】联想超70款笔记本电脑被曝新型UEFI固件漏洞   
 安全圈   2022-07-17 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylh7xc6n7wCwImnVdc9ib4xcZC9NHXhaSPH1NGsSp13A9bp0agw1SUWw9EEyEQb1I12PCk9KGRs9Bqg/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
UEFI、漏洞  
  
  
  
由联想生产的超70款笔记本电脑正受三个 UEFI 固件缓冲区溢出漏洞的影响，这些漏洞能让攻击者劫持Windows系统并执行任意代码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylh7xc6n7wCwImnVdc9ib4xcZyd1tL5DNsyyg3ohocpRD2cuf47WO2ic1AXRBAGibKMXlKqxwcoSQWEMA/640?wx_fmt=jpeg "")  
  
  
据悉，这三个漏洞由安全软件公司ESET的分析师发现，并已经将其报告给了联想。根据联想的披露，这三个中等严重级别的漏洞分别为CVE-2022-1890、CVE-2022-1891 和 CVE-2022-1892。其中第一个为联想部分笔记本产品使用的ReadyBootDxe驱动的问题，后两个是SystemLoadDefaultDxe驱动的缓冲区溢出漏洞，该驱动被用于Yoga、IdeaPad、Flex、ThinkBook、V14、V15、V130、Slim、S145、S540 和 S940 等70多款电脑型号。  
  
  
ESET的分析师表示，这些漏洞是由于传递给 UEFI 运行时服务函数 GetVariable 的 DataSize 参数验证不充分引起，攻击者可以创建一个特制的 NVRAM 变量，导致第二个 GetVariable 调用中数据缓冲区的缓冲区溢出。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylh7xc6n7wCwImnVdc9ib4xcZ7LhicwtCC112Bzs0ZciaQPrFxMqmOxzpch2icqeQlemy89snWRN8xuAww/640?wx_fmt=jpeg "")  
  
  
触发利用 CVE-2022-1892 的变量  
  
  
总体而言，利用UEFI 固件漏洞的攻击非常危险，能让攻击者在操作系统刚启动时运行恶意软件，甚至在 Windows 内置安全保护被激活之前，从而绕过或禁用操作系统级别的安全保护、逃避检测，并且即使在磁盘格式化后仍然存在。对于一些经验丰富的攻击者，能够利用这些漏洞执行任意代码，对设备系统产生难以预估的影响。  
  
  
为了解决这一风险，官方建议受影响设备的用户通过官网下载适用于其产品的最新驱动程序版本。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdRSjJwE3WrMzmE7uVG8mFB4ibWDgvcV3EEJnhAc9WZjepjvxwfmA60rAA/640?wx_fmt=png "")  
[【安全圈】甘肃回应“健康码系统访问异常”：升级维护，正在紧急修复](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=1&sn=59ef1a75ca3fa6d426444169cb84064a&chksm=f36f4a1ac418c30c084ed70e9a05bbb53cc7e96ec0ec18186e55f18405c89cf74309262d522c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdRIxnfJK58vrKiaknR8H8d42uLUYoktq3ox4TVklibryQWWyV9WLTSQvRA/640?wx_fmt=png "")  
[【安全圈】苍南男子破解赌博网站漏洞，每月“薅羊毛”10 多万元](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=2&sn=8dae9f471f869738d493f89bcb8b43c2&chksm=f36f4a1ac418c30c3bb6a19721674950992c26f9dc7f992488574fd4bc1609b26e01adbc4cc8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdRHnIjxsMav1P4ghS2xFn7rG4D8GSjIicQzBPQFWCp1RRzbvvgXOkNqbQ/640?wx_fmt=jpeg "")  
[【安全圈】这么自信？苹果打出千万元悬赏！只为寻求 iOS 16 锁定模式 Bug](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=3&sn=042e42b99f3886fc684c3d9738bad74b&chksm=f36f4a1ac418c30cdd0dbe610fdce30dda6a013c562422bb4197f4cfb24dff1ab371a5e56b62&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdR4t1qMYALVyhMK9ZDwam3tneHibeEVew6h0aHaTgibSILwtYdbJax37aA/640?wx_fmt=png "")  
[【安全圈】DHS 首份网络安全审查委员会报告认为 Log4j 已成为待续性威胁](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=4&sn=cee45a6943ca4591c04bfc7ad86788b2&chksm=f36f4a1ac418c30cee92452712c53790719ae65d5d292d54ab435e9fe3d19dce7169f667f03c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylia5hic2rWpHUibLlRyX6uIzdRia8X2H4z5Z2m3u2Kg19lDF0W7hiambsz5oomrgxrIHVvSLLVj6PEr4uA/640?wx_fmt=jpeg "")  
[【安全圈】遭勒索软件攻击，美190万条医疗记录被泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652005978&idx=5&sn=fd6aa2eecfa2bb80b58a6508b2284d4f&chksm=f36f4a1ac418c30c0f6020b102ce009121697284e2450c37d1ff72030bbfc2a7e0bebd6c7b3d&scene=21#wechat_redirect)  
  
  
  
  
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
  

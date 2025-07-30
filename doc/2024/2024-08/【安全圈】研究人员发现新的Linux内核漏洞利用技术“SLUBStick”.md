#  【安全圈】研究人员发现新的Linux内核漏洞利用技术“SLUBStick”   
 安全圈   2024-08-11 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
网络安全研究人员揭示了一种名为 SLUBStick 的新型 Linux 内核利用技术，该技术可用于将有限的堆漏洞提升为任意内存读写原语。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljAFjGaTVoDVsO6Ig4BVn4gRicBdLQItSb3GkoibSv87LxnBndordqF10kwiaAeia2ib8BiajNNLCbqlOwg/640?wx_fmt=jpeg&from=appmsg "")  
  
“最初，它利用分配器的定时侧信道来可靠地执行交叉缓存攻击，”格拉茨理工大学的一组学者说。“具体来说，利用侧信道泄漏可以将常用通用缓存的成功率提高到 99% 以上。”  
  
影响 Linux 内核的内存安全漏洞功能有限，并且由于存在 Supervisor 模式访问预防 （SMAP）、内核地址空间布局随机化 （KASLR） 和内核控制流完整性 （kCFI） 等安全功能，因此利用起来更具挑战性。  
  
虽然软件交叉缓存攻击已被设计为一种对抗内核强化策略（如粗粒度堆分离）的方法，但研究表明，现有方法的成功率仅为 40%。  
  
SLUBStick 已在 Linux 内核的 5.19 和 6.2 版本上进行了演示，使用了 2021 年至 2023 年间发现的 9 个安全漏洞（例如，双重释放、释放后使用和越界写入），导致权限升级到 root，而没有身份验证和容器逃逸。  
  
该方法背后的核心思想是提供修改内核数据的能力，并以可靠地克服现有防御措施（如 KASLR）的方式获取任意内存读写原语。  
  
但是，要使此功能起作用，威胁模型假设 Linux 内核中存在堆漏洞，并且非特权用户具有代码执行功能。  
  
研究人员说：“SLUBStick利用了更新的系统，包括v5.19和v6.2，用于各种堆漏洞。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgm7BPNz5YicMF3LWPzQfvNGoZ4SIfZ1UMWLJkLkMicDHX5j6HyVq9GUwbc0gaia2wgw7b1S7ZhpicKSA/640?wx_fmt=jpeg&from=appmsg "")  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063000&idx=1&sn=bf67cbcf454f238accc31965c6a79a67&chksm=f36e6958c419e04e0cae1c24316f71208a0cbb37f999f92d4d2e877353b4b0d1ad460c9ae6e6&scene=21#wechat_redirect)  
[【安全圈】派出所义警滥用职权出售公民隐私数据，非法获利终获刑罚](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063469&idx=1&sn=f9ff449c10fb7acbffc65e0153f7873e&chksm=f36e6aadc419e3bbb9bb9f630e125a12202b8e3d4a86559b977b306cc2a294948cab8601e78b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljGavtOjl55QlW9NVI68g47wd2VA6mmUmnB85ufUQFZLdAzovZ0RCgMJ1ba7IFDVCicP3uAnbGsnww/640?wx_fmt=jpeg "")  
[【安全圈】5G 基带安全堡垒被突破，黑客可利用漏洞静默监视手机用户](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063469&idx=2&sn=761374073d1c4cc7b0aac0c05f7eba9f&chksm=f36e6aadc419e3bbda3430219df10f333a8761244e6488cd66c155d24e545c38db5e46f47e3b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljGavtOjl55QlW9NVI68g47710mLUVun5D7RyNHmQGmRB0icSndGxCNSKLK5OSibJFyicSZDe0fibj1sQ/640?wx_fmt=jpeg "")  
[【安全圈】酒泉公安：网安部门查处一起擅自改变计算机信息网络数据案](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063469&idx=3&sn=1d07d25d97345e3cc5a33f2a21994a09&chksm=f36e6aadc419e3bbadb3b190493e7844f8ffc9419221f3fbf8b606c4b38d51cead490d7b49ea&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljGavtOjl55QlW9NVI68g476EXgSjqvzIxHMGbicoZEBayibLNXwICOf5qn08g1d3psuMh2ibXIicQIVQ/640?wx_fmt=jpeg "")  
[【安全圈】巴黎奥运会场馆遭受网络攻击，黑客要求以加密货币支付赎金](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063469&idx=4&sn=1dd61d069f7312797f451a07e616186c&chksm=f36e6aadc419e3bb8ba4a930411977bddc8075079b5f44bc387177014d97e8eafe6ef04ab59e&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  

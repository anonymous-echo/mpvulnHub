#  【安全圈】苹果 Apple Silicon 芯片被曝安全漏洞   
 安全圈   2024-03-24 12:57  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
安全专家近日在苹果 Apple Silicon 芯片上发现安全漏洞，被黑客利用可以窃取用户数据。**专家表示该漏洞固然可以被缓解和修复，但会严重影响性能表现。**  
  
该漏洞存在于 Data Memory-Dependent Prefetcher（DMP）中，黑客利用该漏洞可以窃取加密密钥，从而访问用户的数据。  
  
IT之家注：DMP 又被称作间接内存 prefetcher，位于内存系统中，可以预测当前运行代码最有可能访问的数据所在内存地址。  
  
而黑客可以利用现有的访问模式，预测下一个要获取的数据位，从而影响正在预取的数据，访问用户的敏感数据，研究人员将这种攻击命名为“GoFetch”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljGr6WSPj3FpmyPAicSZakzLiazqLtqDTmu1WJn0ND7vQlZTFc4w1pqwjyVWcMA0mnzmFOOEwsjuXVQ/640?wx_fmt=jpeg&from=appmsg "苹果 Apple Silicon 芯片被曝安全漏洞，能缓解但需牺牲性能")  
  
研究人员确认，黑客可以将数据伪装成一个指针，欺骗 DMP 让其视为地址位置，并将该数据拉入缓存。这种攻击无法立即破解加密密钥，但可以通过反复尝试最终获取密钥。  
  
GoFetch 攻击使用的用户权限与许多其他第三方 macOS 应用程序相同，并不需要 root 访问权限，这降低了实际运行攻击的门槛。  
  
研究人员的测试应用程序能在不到一个小时的时间内提取出 2048 位 RSA 密钥，提取 2048 位 Diffie-Hellman 密钥则只需两个多小时。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljGr6WSPj3FpmyPAicSZakzLbZ5f6hktBQR9qBvcd6VLGh0u76s22jC13uqAUia6Qx80NR7EjG1diabw/640?wx_fmt=jpeg&from=appmsg "苹果 Apple Silicon 芯片被曝安全漏洞，能缓解但需牺牲性能")  
  
而摆在苹果面前的问题在于，由于这个漏洞存在于 Apple Silicon 芯片的核心部分，因此短期内无法完全修复。  
  
而且苹果部署任何缓解措施，都会增加执行操作所需的工作量，进而影响性能。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljGr6WSPj3FpmyPAicSZakzLtWu0oWXgrP1vy5KSld02wd0AOsvGLGLCFMyb3VVETIxb2eC2OiaKO2w/640?wx_fmt=png&from=appmsg "")  
[【安全圈】黑客发现特斯拉系统漏洞，赢得20万美元奖金和一辆Model 3](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056307&idx=1&sn=a4432e46e4eed40e1dd24e95ef69a80f&chksm=f36e06b3c4198fa580aa761d3eefb2b27f40fbdae9cf0b84e8417b8b1fb379122fbf3f89d3e2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljGr6WSPj3FpmyPAicSZakzLy3hWZ9VmmzP49yz27hBeBJJx7ZEWFVRBqoDTAygU75oTmibfDibXDKSQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】苹果Apple Silicon芯片被曝安全漏洞，能缓解但需牺牲性能](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056307&idx=2&sn=fde5be420d5bfd136579a634221ee231&chksm=f36e06b3c4198fa5e659cfe64c59a8b13bbc9d004a123374a168874db5366516bfb9eb7d2776&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljGr6WSPj3FpmyPAicSZakzLe8KDgy3C6HzNdBlj5xBo2KrYtzR9mXSNApy8TTGtCwKAUzibGL0Sib3g/640?wx_fmt=jpeg "")  
[【安全圈】警惕！全球APT组织正在使用大模型辅助网络攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056307&idx=3&sn=e65a4ef1e7bb6a61d67f701d09a525ab&chksm=f36e06b3c4198fa53ecd5b46c43edd02bbcc3a9348d9b069ae061c4506bc85d8a7f18e071ed5&scene=21#wechat_redirect)  
                          
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljGr6WSPj3FpmyPAicSZakzLYldmQibf73DN2N3ibCHP1a6eZpGobXsAibeAmNcOzreFVicrVxMEyxWHBQ/640?wx_fmt=png&from=appmsg "")  
[【安全圈】AWS曝一键式漏洞，攻击者可接管Apache Airflow服务](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056307&idx=4&sn=6c4afb8de0bdc9da9cd75d84f4313838&chksm=f36e06b3c4198fa5d1b887f133390b24988529fd277fbf56d411cb3359fb7fe49cf77051f675&scene=21#wechat_redirect)  
  
  
  
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
  

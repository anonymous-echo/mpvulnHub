#  热门Fastjson 中出现高危RCE漏洞   
Ravie Lakshmanan  代码卫士   2022-06-17 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxFSUORBBuUtbhq53ibjE2c8z1NzWaiaRKZrK0pahtib0YzibCMwMmVnUCvw/640?wx_fmt=png "")  
  
网络安全研究员详述了最近修复的位于热门 Fastjson 库中的一个高危漏洞（CVE-2022-25845），它可被用于执行远程代码。  
  
  
  
该漏洞和受支持的特性 “AutoType” 中的不受信任的反序列化有关。项目维护人员已于2022年5月23日在版本1.2.83中将其修复。  
  
JFrog 公司的研究员 Uriya Yavnieli 在write-up 中指出，“该漏洞影响所有满足如下条件的Java 应用：它们依赖于 Fastjson 版本1.2.80或更早版本，将受用户控制的数据传递给 JSON.parse 或 JSON.parseObject API而不指定反序列化的特定类。”  
  
Fastjson 是一个Java库，用于将Java Objects 转换为JSON 表示，反之亦然。易受该缺陷影响的函数 AutoType 在默认情况下是启用的，当解析可被反序列化到恰当类的对象时，指定自定义类型。  
  
Yavnieli 解释称，“然而，如果被反序列化的JSON 受用户控制，则通过启用 AutoType 进行解析可导致反序列化安全问题，因为攻击者可实例化 Classpath 上的任何类，并以任意参数提供给构造器。”  
  
虽然项目所有人此前引入了禁用 AutoType 的安全模式并开始维护类的阻止列表来防御反序列化缺陷，但新发现的这个漏洞绕过了阻止列表，从而引发远程代码执行后果。  
  
建议Fastjson 用户更新至版本1.2.83，或启用安全模式（不管使用了允许列表还是阻止列表，该函数被关闭），从而有效地关闭反序列化攻击的变体。  
  
Yavnieli 表示，“尽管已存在公开的PoC 利用，且潜在影响非常大（远程代码执行），但攻击的条件并不容易（将不受信任输入传递到特定的易受攻击API中），而且更重要的是，需要开展特定目标的研究，找到合适的小工具类实施利用。”  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2021中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505380&idx=1&sn=01d2f5af200abc6bb20411ee8f17b6b5&chksm=ea94e48edde36d98f20b66aecf9f359e49226b411872bcea527fcca0a5de018f407415313800&scene=21#wechat_redirect)  
  
  
[【漏洞预警】FastJson远程代码执行漏洞安全预警通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490406&idx=3&sn=905cf3c77a33fcde8ba90a45d023e0fa&chksm=ea972a0cdde0a31a73016e7d5355c8f9f194aefbc2d79f62b22ae3279c0b6c96f877732664c6&scene=21#wechat_redirect)  
  
  
[新型恶意软件FastPOS专注于数据渗漏速度](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485746&idx=5&sn=526c3a98db3f0f6815a30731100aaa1a&chksm=ea973858dde0b14ecf5690b3f69e6e0edae267ea6acc8ea4a4d78502e8161f51d5f231760b90&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/06/high-severity-rce-vulnerability.html  
  
  
题图：  
Pixabay License  
‍  
  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  

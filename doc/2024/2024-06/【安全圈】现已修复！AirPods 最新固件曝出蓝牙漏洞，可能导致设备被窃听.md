#  【安全圈】现已修复！AirPods 最新固件曝出蓝牙漏洞，可能导致设备被窃听   
 安全圈   2024-06-27 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliamkv1f9zquk5B1GEBYNFHTzQPdQHSbU7mfjxzcL4fbamcH7nXBM01a7nMttj3o4EibrYQzscTdU8g/640?wx_fmt=webp&from=appmsg "")  
  
  
近日，苹果公司发布了 AirPods 的固件更新，但此版本固件曝出了一个严重漏洞，被追踪为 CVE-2024-27867，可能允许恶意行为者以未经授权的方式访问耳机。  
  
该漏洞影响 AirPods第二代及更高版本、AirPods Pro所有型号、AirPods Max、Powerbeats Pro 和 Beats Fit Pro。  
  
本周二（7月25日），苹果公司发布公告称：当你的耳机正在寻求配对设备的连接请求时，蓝牙范围内的攻击者可能会欺骗预期的源设备，并获得你耳机的访问权限。物理距离很近的攻击者可以利用这个漏洞窃听私人对话。  
  
Jonas Dreßler 最早发现并立刻报告了该漏洞。对此苹果公司表示，该漏洞现已通过改进状态管理得到解决。该漏洞在 AirPods 固件更新 6A326、AirPods 固件更新 6F8 和 Beats 固件更新 6F8 的一部分得到修补。  
  
两周前，iPhone 制造商推出了 visionOS（1.2 版）更新，共修复了 21 个缺陷，包括 WebKit 浏览器引擎中的 7 个缺陷。  
  
其中涉及到一个逻辑漏洞，被追踪为CVE-2024-27812，用户在使用设备处理网页内容时可能导致拒绝服务（DoS）。该公司表示，该漏洞已通过改进文件处理得到修复。  
  
安全研究员 Ryan Pickren 报告了这一漏洞，并将其描述为 "世界上第一个空间计算黑客"，其可以绕过所有警告，在没有用户交互的情况下，用任意数量的 3D 动画对象强行填满你的房间"。  
  
该漏洞利用了苹果公司在使用 ARKit 快速查看功能时未应用权限模型的漏洞，在受害者的房间里生成 3D 物体。更糟糕的是，这些动画对象在退出 Safari 后仍会继续存在，因为它们是由一个单独的应用程序处理的。  
  
对此，Pickren 表示：它甚至不需要人类'点击'这个标签就可以实现上述的情景。因此，JavaScript 的程序化点击（即 document.querySelector('a').click()）是没有问题的。这意味着我们可以在不与用户进行任何交互的情况下，启动任意数量的三维动画声音对象。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgK1DO9pswib04S8RU8ArpaKZe9mR93j3m9PdQqtNcFlEiaMEJ8ic8TH7iayfhhFvuQwUfISnibPQV6EEg/640?wx_fmt=png&from=appmsg "")  
[【安全圈】新的 Linux 恶意软件通过 Discord 发送的表情符号进行控制](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062196&idx=1&sn=62b9f5c6dc6de95ade3ed4b1d985704d&chksm=f36e6db4c419e4a23fe721bbbc9771cd3812ca25d370d3b704150165e9cfff72b7949ec4dfbf&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgK1DO9pswib04S8RU8ArpaKZyuNcibSXW8f6d7TagPIdMwTJ5JAXrYmYkoxPwhU2N9ibVmSrGNSTtdw/640?wx_fmt=jpeg "")  
[【安全圈】印尼国家数据中心遭黑客入侵，被勒索1310亿印度尼西亚盾](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062196&idx=2&sn=cb23681361d08c7c7f54abf9cfb408b1&chksm=f36e6db4c419e4a2e1fe7cff27886caec55f5a59ca9ff7f4519a685b180a1111f7ccc0bd08a6&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgK1DO9pswib04S8RU8ArpaK51KyMJD9ibxBSa8mUBYiaDykQcxeluhCTuRneYqbibic5RDpoVFC2Rrafw/640?wx_fmt=png&from=appmsg "")  
[【安全圈】南非国家卫生实验室在 mpox（猴痘）疫情爆发期间遭受勒索软件攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062196&idx=3&sn=295627f44ce2010befd4089bfdf29d38&chksm=f36e6db4c419e4a2782b4072cf8b63a1686b0a3bd539484cf98d8a523c6c18c43ed4c827773a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliamkv1f9zquk5B1GEBYNFHToFsCNG7iaiaqDlP9piavkQOy7twl4k6EdApR6icZBgQ7goxF8mhapAuMiaw/640?wx_fmt=jpeg "")  
[【安全圈】研究称 2.8 亿 Google Chrome 用户安装了危险扩展程序](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062196&idx=4&sn=35cea44ca1c0bfc4edac50ef48cb66a3&chksm=f36e6db4c419e4a2c6dc2531bac9d8571d4213b1286d9777dfce2abfe7a28883198974ae5601&scene=21#wechat_redirect)  
    
  
  
  
  
  
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
  

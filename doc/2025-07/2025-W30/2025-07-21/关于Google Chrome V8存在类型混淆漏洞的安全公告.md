> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547257&idx=2&sn=6745ead8cbc9f22456ea133e4c77d148

#  关于Google Chrome V8存在类型混淆漏洞的安全公告  
CNVD  安小圈   2025-07-21 00:45  
  
**安小圈**  
  
  
第713期  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbNqM3Lnaqq6icl1RhgBIMsJlJkPcBRKQHsgCG4NetR4nvyfbgA3aibGl2y8tNO1ze95SxbDDAljqINw/640?wx_fmt=png "")  
  
  
  
安全公告编号:  
CNTA-2025-0010  
  
2025年7月2  
日  
，  
国家信息安全漏洞共享平台（CNVD）收录了Google Chrome V8类型混淆漏洞（CNVD-2025-14800，对应CVE-2025-6554）。攻击者利用该漏洞，可通过诱骗用户访问恶意页面，实现远程代码执行攻击。目前，  
谷歌公司表示该漏洞已发现在野利用，并发布Chrome新  
版本  
。  
CNVD建议受影响的单位和用户立即升级至最新版本。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbO2pQ1EwjRs2YAnb6JjT1BX4UQjiciakoibqh8icjbeEfqOLgICDmv051ZmCEnEJA39iciaplpBlKe748Zw/640?wx_fmt=jpeg "")  
  
  
安全公告编号:  
CNTA-2025-0010  
  
2025年7月2  
日  
，  
国家信息安全漏洞共享平台（CNVD）收录了Google Chrome V8类型混淆漏洞（CNVD-2025-14800，对应CVE-2025-6554）。攻击者利用该漏洞，可通过诱骗用户访问恶意页面，实现远程代码执行攻击。目前，  
谷歌公司表示该漏洞已发现在野利用，并发布Chrome新  
版本  
。  
CNVD建议受影响的单位和用户立即升级至最新版本。  
  
  
一、漏洞情况分析  
  
Google Chrome是一款由谷歌公司开发的网页浏览器，该浏览器基于WebKit、Mozilla等开源软件开发，具有较好的性能、出色的兼容性和丰富的扩展程序，得到了广泛使用。  
  
2025年7月2日，国家信息安全漏洞共享平台（CNVD）收录了Google Chrome V8类型混淆漏洞。由于Chrome浏览器V8 JavaScript（JS）引擎在处理JS代码时，对某些数据类型的边界检查和类型转换处理不当，导致浏览器无法正确区分不同类型的内存数据。攻击者通过精心构造包含特定JS表达式的恶意Html页面，并诱骗用户点击访问来触发此漏洞。未经授权的攻击者利用该漏洞，可远程对目标主机执行任意读写操作，并进一步实现远程代码执行攻击。  
  
CNVD对该漏洞的综合评级为“高危”。  
  
  
二、漏洞影响范围  
  
漏洞影响的产品和版本包括：  
  
Google Chrome < 138.0.7204.96  
  
基于Chromium内核开发的浏览器  
  
  
三、漏洞处置建议  
  
谷歌公司已紧急发布新版本修复该漏洞，各平台Chrome的修复版本情况如下：  
  
1）Windows版：Chrome v138.0.7204.96/.97  
  
2）Linux版：Chrome v138.0.7204.96  
  
3）Mac版：Chrome v138.0.7204.92/.93  
  
Microsoft Edge、Brave、Opera和Vivaldi等基于Chromium内核开发浏览器的安全更新仍在开发中。  
  
CNVD建议受影响的单位和用户立即将Chrome升级至最新版本，同时在使用Chrome时做好安全防范措施，谨慎访问来源不明的网页链接或文件。  
  
  
参考链接：  
  
https://chromereleases.googleblog.com/2025/06/stable-channel-update-for-desktop_30.html  
  
https://issues.chromium.org/issues/427663123  
  
END  
  
  
  
**【以上内容**  
**来源于：CNVD漏洞平台】**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeeR4VInT56J0KCLD3HkiaRxjMLLV6rricOadHohJB1sOtPT02fETAxr4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
- [2025HVV【技战法】丨0Day漏洞专项篇](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547247&idx=3&sn=1441149c1af904009b997eb107e06de9&scene=21#wechat_redirect)  
  
  
- [护网—2025｜严守视频会议“安全门”，谨防信息泄露“一瞬间”](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547222&idx=1&sn=7c675c635e6cfe10bfb3d73942f52fad&scene=21#wechat_redirect)  
  
  
- [疑似国内护网红队攻击样本被捕获并深度分析](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547198&idx=2&sn=4495b434c8f51f3b951bcd517bbb73d7&scene=21#wechat_redirect)  
  
  
- [蓝队快速识别隐藏恶意文件的 20个文件特征及查找方法总结](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547198&idx=1&sn=a4864a2f90042bfbbc6b29231fee7b16&scene=21#wechat_redirect)  
  
  
- [【新！】CNNVD通报微软多个安全漏洞](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547154&idx=1&sn=ed18dc2a48d5baf054db84d47279fb1b&scene=21#wechat_redirect)  
  
  
- [2025-07-11 HW情报分享](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547148&idx=1&sn=0ae664aa5bccf7415f3a82722f47d905&scene=21#wechat_redirect)  
  
  
- [【HVV】护网—2025 | 网警公布适用《网络数据安全管理条例》典型案例](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547133&idx=1&sn=5eeb8ad5cb874ecbcb59397a92b4c74e&scene=21#wechat_redirect)  
  
  
[微软紧急修复高危蠕虫级RCE漏洞，威胁全网Windows系统](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547132&idx=1&sn=cd484270f0cd9ed5dc17fdeafb2e76dd&scene=21#wechat_redirect)  
  
- [【HVV】护网系列 威胁情报共享7.9](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547108&idx=1&sn=01f68c9cc76760e8e5e0615df3b54c6c&scene=21#wechat_redirect)  
  
  
- [25HVVRT钓鱼样本，警惕！多家单位已中...](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547104&idx=1&sn=8e06fcde039b325eedcb2eac8ba04f95&scene=21#wechat_redirect)  
  
  
- [【HVV】护网系列 威胁情报共享7.8](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547054&idx=1&sn=014e2f4baedfea584d880c612e51b884&scene=21#wechat_redirect)  
  
  
- [【更！】25HVV热点攻击漏洞含0day，各单位自查...](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547053&idx=1&sn=ab425df27b630dfa1c1d59759bf1ad37&scene=21#wechat_redirect)  
  
  
- [【HVV】护网系列 威胁情报共享7.7](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547048&idx=1&sn=d943617032f197fb6cb70fff9f8eb3d2&scene=21#wechat_redirect)  
  
  
- [25HVV最新0day更新，各单位自查...](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546998&idx=1&sn=c3077c2a50dfec80de8f9e21b507ae53&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=1&sn=2f16da5665014b4c07bcbd53e3d1c03e&scene=21#wechat_redirect)  
- [【HW】8个因护网被开除的网安人](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=1&sn=2f16da5665014b4c07bcbd53e3d1c03e&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=2&sn=e9578e62a475ac5c46b95ac81066d2a7&scene=21#wechat_redirect)  
- [HW应急溯源：50个高级命令实战指南](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=2&sn=e9578e62a475ac5c46b95ac81066d2a7&scene=21#wechat_redirect)  
  
  
- [震惊全球！中国团队攻破RSA加密！RSA加密告急？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546856&idx=1&sn=11b36f6fabde860e889e4ac2f4797bba&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOugegrykhydnkHibcSWjpibTBZoK6jjGxJiax1BcwwctpA5SBric9aPdQFXsxFnn4LQJWdkYwbtPN0gg/640?wx_fmt=jpeg "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546815&idx=1&sn=99a4f3228f322ef92c93d23cee01f071&scene=21#wechat_redirect)  
- [2025年【护网】攻防演练时间已定！](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546815&idx=1&sn=99a4f3228f322ef92c93d23cee01f071&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546578&idx=1&sn=87cdf84e6fd7d35986b29acd90954c65&scene=21#wechat_redirect)  
  
[突发！小红书惊现后门......](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546578&idx=1&sn=87cdf84e6fd7d35986b29acd90954c65&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPwt82pEdc2YwCDz6n3H3c2C0ibcMl4Tea8hM59iaZoR1FDMTCUswDiclc1icLoSywpkWbdqyb6uBNcnA/640?wx_fmt=jpeg "")  
- [2025年“净网”“护网”专项工作部署会在京召开，看看都说了哪些与你我相关的关键内容？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546673&idx=1&sn=53fe0365785465d4ff6193a9ca639119&scene=21#wechat_redirect)  
  
  
- # 护网即将来临，这场网安盛会带给了我们打工人什么......  
  
- [护网在即，企业还有什么新思路可以应对吗？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546698&idx=1&sn=55ab4ac8dffb5f7ccf02a4f759537acf&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPwt82pEdc2YwCDz6n3H3c2Noz3ibYqNZ52uicBtuVVlFRg6vSuF8YFjPvCVma1ADrT1ViaKVE9URNOA/640?wx_fmt=jpeg "")  
- [HW必备：50个应急响应常用命令速查手册一（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546304&idx=2&sn=45ef99e528ded7ff2e65e4d70e6d5181&scene=21#wechat_redirect)  
  
  
- [HW必备：50个应急响应常用命令速查手册二（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546327&idx=2&sn=cf1ebbd2b511524ec965a3672b6fc3dd&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546530&idx=1&sn=4a2820b60102e538e87c956375f6fcdb&scene=21#wechat_redirect)  
- [网安同行们，你们焦虑了吗？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546530&idx=1&sn=4a2820b60102e538e87c956375f6fcdb&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546466&idx=1&sn=a9d55d0b430dbf61dc219fd71ce25ae1&scene=21#wechat_redirect)  
- # 网安公司最后那点体面，还剩下多少？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
- [2024年网安上市公司营收、毛利、净利润排行](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
- [突发！数万台 Windows 蓝屏。。。。广联达。。。惹的祸。。。](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
  
  
#   
- # 权威解答 | 国家网信办就：【数据出境】安全管理相关问题进行答复  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247539649&idx=1&sn=8858b449c89d21240e1f522e92be4fbd&scene=21#wechat_redirect)  
- # 全国首位！上海通过数据出境安全评估91个，合同备案443个  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544405&idx=2&sn=a961d43ca4a9ed667fccbbab758d9196&scene=21#wechat_redirect)  
- # 沈传宁：落实《网络数据安全管理条例》，提升全员数据安全意识  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
- [频繁跳槽，只为投毒](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
- [【高危漏洞】Windows 11：300毫秒即可提权至管理员](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
- [针对网安一哥专门的钓鱼网站](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
- [为什么【驻场】网络安全服务已成为大多数网络安全厂商乙方不愿再触碰的逆鳞？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOYPldtHVUmKQJ2WtL12GUnHRyzBiaKosLNicTZ2QkDFSRPUha2Eiaqk8R5fPdXc75zxprkTRB0ib5hUw/640?wx_fmt=jpeg "")  
- [HW流程以及岗位职责](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=3&sn=97e6083dbfbdd896680e24770a10d319&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247543989&idx=1&sn=2821b91efdd626e1a38ec6b2b439186b&scene=21#wechat_redirect)  
  
- # 网络安全【重保】| 实战指南：企业如何应对国家级护网行动？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542929&idx=1&sn=8cf6f15ddca44e343a494eea0fa619b2&scene=21#wechat_redirect)  
- **DeepSeek安全：AI网络安全评估与防护策略**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542701&idx=1&sn=567674aa12d861c3561d453268badb91&scene=21#wechat_redirect)  
- **虚拟机逃逸！VMware【高危漏洞】正被积极利用，国内公网暴露面最大******  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542458&idx=1&sn=d81d049331d175a2176f0978d7f032a8&scene=21#wechat_redirect)  
- **挖矿病毒【应急响应】处置手册******  
  
****- **用Deepseek实现Web渗透自动化**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542225&idx=2&sn=244a465fab183f4fa91a284b92a920e6&scene=21#wechat_redirect)  
- **【风险】DeepSeek等大模型私有化服务器部署近九成在“裸奔”，已知漏洞赶紧处理！**  
  
****- **关于各大网安厂商推广「DeepSeek一体机」现象的深度分析**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
- [Deepseek真的能搞定【安全运营】？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540432&idx=1&sn=b9e7e6103e86b9966f29d7eacf8e3d1e&scene=21#wechat_redirect)  
- **【热点】哪些网络安全厂商接入了DeepSeek？**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540206&idx=2&sn=300737ad84f684e622fdde03da0fc1a7&scene=21#wechat_redirect)  
- **【2025】常见的网络安全服务大全（汇总详解）**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540343&idx=1&sn=59d6f592f71a7f1e3a18fd082aa3de40&scene=21#wechat_redirect)  
- **AI 安全 |《人工智能安全标准体系(V1.0)》(征求意见稿)，附下载**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMbfUY7RtO1t6ZAxjoibZoZ8DSVPU0yI9v2nXpiat0oN8eLia5jiaoWOhlib5GiaPWQJeCsUmShI4QOqaGg/640?wx_fmt=png "")  
- **2025年 · 网络威胁趋势【预测】**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbM09kF5tXEb8PRXicFibPic4un6rwDI2CBUxrVaDINuM8ChyotgWiag4icErAHniaYNYiccQiaVkyyJUTX13w/640?wx_fmt=jpeg "")  
- **【实操】常见的安全事件及应急响应处**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbMASB7RibZ1nezrias4SvtcqzjvsJJPXhFiceJPEoVHVLhI2Soolaf8OhWQOVafycOibiaclJkT7NgG4Nw/640?wx_fmt=jpeg "")  
- **2024 网络安全人才实战能力白皮书安全测试评估篇**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeOsnl5ayrQXc0wPVutL1dQXg7BugT7vAe8qkpfszTrlhUAq4DQZFaVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  

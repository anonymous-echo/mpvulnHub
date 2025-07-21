> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247504063&idx=1&sn=3862aedb5fdb4ae21a2600a1dbbfb8e7

#  Kernelhub，一个聚合了linux、windows、macOS的提权漏洞合集，带复现过程  
Ascotbe  泷羽Sec   2025-07-20 13:30  
  
这个项目很适合学到windows内网提权的师傅们，复现过程都有，就不用花费大量时间去找相关的学习资料了  
  
项目的制作初衷是为了学习、分析、研究最新的内核漏洞，不再需要花费大量时间去搜索系统及相关内容。  
  
![image-20250720010320549](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEOOMAiaDKbiaGxnHq6a7BhOdBDTuHnxiaFRSdlPBSF7nXcmc0t8ptDl72lfLqZZjzoTSAFLt59pFs7A/640?wx_fmt=png&from=appmsg "")  
  
image-20250720010320549  
  
本项目是一个提权相关的集合，除了测试失败或未指定的Exp，都有详细的说明以及演示GIF图。  
  
![image-20250720010457918](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEOOMAiaDKbiaGxnHq6a7BhOdPqfMA0IwFvUBNfmE1Rs0ZUn7iaqicMvxOz8a5qSic4XcvaGABYC2yO8iag/640?wx_fmt=png&from=appmsg "")  
  
image-20250720010457918  
  
exp程序  
  
![image-20250720010630813](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEOOMAiaDKbiaGxnHq6a7BhOdLzHibaLOBKDNUlU4X6kRYgGWNoAaiaJj2OuwDMYkNUzD0L3uolbNnv6Q/640?wx_fmt=png&from=appmsg "")  
  
image-20250720010630813  
  
如果有遗漏CVE漏洞，欢迎提Issues并带上利用代码。  
  
项目代码禁止在真实环境进行测试！代码的可靠性自行验证，您造成的过失项目作者概不负责。  
  
开源地址：https://github.com/Ascotbe/Kernelhub  
## 往期推荐  
  
[新版BurpSuite v2025.6.3汉化版，附激活教程](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247504007&idx=1&sn=ad9bc57b63e5aec5264ca123e8d2148e&scene=21#wechat_redirect)  
  
  
[挖SRC必须知道的25个漏洞提交平台](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247503982&idx=1&sn=0b4f5d87ce51350878b046afc4d40c31&scene=21#wechat_redirect)  
  
  
[FeatherScan v4.0 - 一款Linux内网全自动信息收集工具](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247503736&idx=1&sn=e62fae44a2605ab0df8dc812fee51167&scene=21#wechat_redirect)  
  
  
[掩日-适用于红队的综合免杀工具](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247503360&idx=1&sn=e068394c757012cb72227e702975234f&scene=21#wechat_redirect)  
  
  
[2025最新渗透测试靶场推荐](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247503236&idx=1&sn=2181776334a185b732907eaf0573034a&scene=21#wechat_redirect)  
  
  
[近400个渗透测试常用命令，信息收集、web、内网、隐藏通信、域渗透等等](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247502791&idx=1&sn=d113f9b4fb661e66e8ab69d27c186c2b&scene=21#wechat_redirect)  
  
  
[【内网渗透】隐藏通信隧道技术](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247502651&idx=1&sn=1f08f90f98e3738ec1bb8033f83c5319&scene=21#wechat_redirect)  
  
  
[内网渗透必备，microsocks，一个轻量级的socks代理工具](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247502471&idx=1&sn=84c975ff8c1eaa18fd0f757ba1b3a6ab&scene=21#wechat_redirect)  
  
  
[神器分享 红队快速打点工具-DarKnuclei](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247500483&idx=1&sn=b6ef0e3ffebed948b3caa06a1a84cd17&scene=21#wechat_redirect)  
  
  
[红日靶场5，windows内网渗透，社工提权，多种域内横向移动思路](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247500172&idx=1&sn=8efb51ecf7c5309bd02b784c856f7eda&scene=21#wechat_redirect)  
  
  
[【渗透测试】DC1~9(全) Linux提权靶机渗透教程，干货w字解析，建议收藏](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247495774&idx=1&sn=ad20212bd08f94652d40e286406ed40f&scene=21#wechat_redirect)  
  
  
[【OSCP】 Kioptrix 提权靶机（1-5）全系列教程，Try Harder！](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247496963&idx=1&sn=646e34d7b03cef9741616ea8d7e20968&scene=21#wechat_redirect)  
  
  
[一个永久的渗透知识库](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247502572&idx=1&sn=42a9853381a099fc7c074230c39824a3&scene=21#wechat_redirect)  
  
  
  

#  JS接口提取,漏洞检测工具   
0x7eTeam  夜组安全   2024-01-07 13:10  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
  
**01**  
  
**工具介绍**  
  
空间测绘  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WYtHFpXpmicOIiaPXu6Jq5FhOWIwOwdyENZK1v00eqZibEJcJTbMvqPLSofxuAWNpkGy6ouq3IuyQrg/640?wx_fmt=png&from=appmsg "")  
  
第三步：选择自己的脚本，检测即可  
  
脚本编写要求【可以参考模板】  
  
1、要求只从控制台获取一个参数，内容是url  
  
2、检测的结果请输出之控制台  
  
3、代理需要自己加到py里面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WYtHFpXpmicOIiaPXu6Jq5Fh2K0c8RibBuf5qtpQNyspu49mDKicOKmGrBkYeyzVbSaIVekznRVAiaRZA/640?wx_fmt=png&from=appmsg "")  
### 内网横向  
  
py调用的impacket-0.11.0  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WYtHFpXpmicOIiaPXu6Jq5FhGV6a0hfhenBXGSmicMPaMCQL85hpVhNuvWCW7ibAS9syBLUJico4Xv1GQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WYtHFpXpmicOIiaPXu6Jq5FhBuyC8ib3S7nwAKpqWynxa5YxasFMSaXT5v5YOGbfTsKKyod5ZKyOtew/640?wx_fmt=png&from=appmsg "")  
### JS接口  
  
第一步：输入网址 获取js  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WYtHFpXpmicOIiaPXu6Jq5FheYHNVeorMkSFOicGK1IVKrQjsA09ic0648F7hORsNAbLbbyIE4OHjrEA/640?wx_fmt=png&from=appmsg "")  
  
第二步，挑选一个感觉有接口的js  
  
这里的js不能有参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WYtHFpXpmicOIiaPXu6Jq5FhXsMqm0WZMqI2pC3YlcI9FgxRk5DRpJ1usBhsqsT19AYnY1DvdyYlrA/640?wx_fmt=png&from=appmsg "")  
  
第三步：(可选)，观察结果，如果有特定的目录，可以添加在前面  
  
第四步：选择请求方式，然后点击获取接口状态即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WYtHFpXpmicOIiaPXu6Jq5FhF10qOr8W4Sh6mXCTDibqVkm95ibCYWWvpSct5vO5w8icHU44xfa3PzYWg/640?wx_fmt=png&from=appmsg "")  
  
结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WYtHFpXpmicOIiaPXu6Jq5FhzOVYeTQklM56BoBRZDbP9uqW8dEMt43EWYBlazA7PtNnAsgyXrSWoA/640?wx_fmt=png&from=appmsg "")  
  
  
**02**  
  
**工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【240107****】获取**  
**下载链接**  
  
  
**03**  
  
**往期精彩**  
  

							[ 一款Go Wails实现的GUI工具，功能涵盖网站扫描、端口扫描、企业信息收集、子域名暴破、空间引擎搜索、CDN识别等 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247489497&idx=1&sn=a6847403397663039717e71c9a30ef94&chksm=c3685321f41fda37b3e0a17139c0dd497994e02a292ce8c001cf3fd0e42d78e66ebe979839b6&scene=21#wechat_redirect)  

						  
  
  

							[ Container Escape Check 容器逃逸检测 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247489492&idx=1&sn=1e3060fff1495b232983c7dd6b582bcb&chksm=c368532cf41fda3ae6ac7bac251b03d625ff83c0c08a25606d6b65cf3939f77fc004690a6b58&scene=21#wechat_redirect)  

						  
  
  

							[ :: 棱镜 X · 一体化的轻量型跨平台渗透系统 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247489491&idx=1&sn=e9156ff6f7f8841e60697ed82075c88b&chksm=c368532bf41fda3d429f413f976beb357aca13fca9c36a93f852b69639ed8519533897324326&scene=21#wechat_redirect)  

						  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557 "")  
  

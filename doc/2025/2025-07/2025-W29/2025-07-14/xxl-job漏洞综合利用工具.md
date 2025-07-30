> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494731&idx=1&sn=e8b10030b95eeeb908be3ace5b5a2b04

#  xxl-job漏洞综合利用工具  
pureqh  夜组安全   2025-07-14 00:01  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WrOMH4AFgkSfEFMOvvFuVKmDYdQjwJ9ekMm4jiasmWhBicHJngFY1USGOZfd3Xg4k3iamUOT5DcodvA/640?wx_fmt=png&from=appmsg "")  
  
## 工具介绍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2W3wbpG01OWbHNsNA7RXiaLLjBJNs0W2gUCIuqNGSnDzW3pEEm9yIq2q0YxgTwuqcGr3Tdib6awibtPg/640?wx_fmt=png&from=appmsg "")  
## 检测漏洞  
  
1、默认口令  
  
2、api接口未授权Hessian反序列化（只检测是否存在接口，是否存在漏洞需要打内存马验证）  
  
3、Executor未授权命令执行  
  
4、默认accessToken身份绕过  
## 关于内存马  
  
1、内存马使用了xslt，为了提高可用性提供了冰蝎Filter和Vagent两种内存马  
  
2、如需自定义可替换resources下的ser文件，其中filter.ser为冰蝎filter内存马、agent.ser为冰蝎agent内存马、xslt.ser会落地为/tmp/2.xslt,  
  
3、内容为使用exec执行/tmp/agent.jar、exp.ser则是加载/tmp/2.xslt  
  
4、vagent内存马连接配置:冰蝎:http://ip:port/xxl-job-admin/api, 其他类型内存马类似， 将api改为luckydayc、luckydayjs等即可  
  
5、Behinder内存马连接配置:   
  
密码: Sgjmccrzo  
  
请求路径: /api  
  
请求头: Referer: Lepxcnzd  
  
脚本类型: JSP  
  
6、由于agent发送文件较大，所以可能导致包发不过去，建议多试几次或者将超时时间延长  
  
7、由于Hessian反序列化基本上都是直接发二进制包，所以理论上讲其他的Hessian反序列化漏洞也可以打  
  
## 工具获取  
  
  
  
点击关注下方名片  
进入公众号  
  
回复关键字【  
250714  
】获取  
下载链接  
  
  
## 往期精彩  
  
  
往期推荐  
  
[理想中的网安专业VS现实中的网安专业](https://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494730&idx=1&sn=4ab209a9a3b12ca8cb798c61887cb56e&scene=21#wechat_redirect)  
  
  
[网络摄像头漏洞扫描工具！更新](https://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494722&idx=1&sn=07be35bca8fdbda650e5d8e58efe5d9d&scene=21#wechat_redirect)  
  
  
[Struts2全版本漏洞检测工具更新！V19.68](https://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494721&idx=1&sn=60b7e45e36b42d51e75a8cb4a6dca210&scene=21#wechat_redirect)  
  
  
[X-SAST 专业多语言代码安全审计工具套件](https://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494700&idx=1&sn=aec4f555c2c98fedfd9ab4bab2996520&scene=21#wechat_redirect)  
  
  
[Fiora：漏洞PoC框架Nuclei的图形版。快捷搜索PoC、一键运行Nuclei。可作为独立程序运行也可burp插件使用。](https://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494699&idx=1&sn=69f6bcf949f34426d14e3cb19a6128ed&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557&tp=webp "")  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2NzY5MzI5Ng==&mid=2247506876&idx=1&sn=2d668c8796937650ddc81aa1b8cfb37d

#  Burp插件 | 高效SQL注入检测，提高测试效率  
saoshao  菜鸟学信安   2025-07-22 00:30  
  
工具介绍  
  
**DetSql**  
是基于 BurpSuite Java 插件 API 开发的 SQL 注入探测插件，主要作用为快速从 http 流量中筛选出可能存在 SQL 注入的请求，在尽可能减少拦截的情况下提高 SQL 注入测试效率。  
  
注意：**DetSql**  
采用 Montoya API 进行开发，BurpSuite 版本需满足（>=2023.12.1）。  
  
**使用方法**  
  
插件装载: Extensions - Installed - Add - Select File - Next  
  
主面板（dashboard）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9JPpNb7icHgGqOvUPelqhBAA3QvhPngvVmibZpxa1kLibZVM8E7ibzPkGPibfE5Y66xUUiaOoVUH94NOwic9FZOiagfCcQ/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
在Logger模块中查看扫描流量，选择Extensions类型如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9JPpNb7icHgGqOvUPelqhBAA3QvhPngvV0ibM8Mx1zpIfJt4qHM52Wuw8owKLM0mk9WLp9W82PgkEQwOae0z8JRg/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
例子  
  
报错类型页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9JPpNb7icHgGqOvUPelqhBAA3QvhPngvVO0jF7cwia6uL8XVVY7yoBmfXXy7wGU34gLMRA3QqG2u5ba3tybMibLsw/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
order类型页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9JPpNb7icHgGqOvUPelqhBAA3QvhPngvVepCzaHMCV2YPibgDibqOYT0YfH6KaEibHIkt898Be65bCvVnFx6ezQ7nQ/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
数字类型页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9JPpNb7icHgGqOvUPelqhBAA3QvhPngvVvSmiaaIetPOqfGpX27Nt1HcIuncjTKNRE7aQByPxvstwJPTQgMqKJbA/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
字符类型页面（包含多种类型）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9JPpNb7icHgGqOvUPelqhBAA3QvhPngvVbOFJMe83XhlYhsJzKOVkAYFBTCxY4qTlc9Zks4Xs6SN4BfNiciaAE70w/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
双引号问题  
  
由于双引号闭合的情况出现极少，此处仍在报错类型中保留了双引号的原因，经本人测试出现过双引号报错的情况，因此仍在报错类型保留了双引号，如想自行设置报错payload可在配置面板自行设置。  
  
项目地址  
  
https://github.com/saoshao/DetSql  
  
扫码加好友免费领取AI大模型教程  
  
限前10名  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgEvT8YYxHSam8ibFp2LzgHyEMcom9z0p6Z3GlLibGTZem7qjqUNspTX8pKUKJ8MItU9XwqDKLKial2Yg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgEvT8YYxHSam8ibFp2LzgHyEQHjZknUEolyFEB3AgiaGyMjQl8QOqTnaIQG05zDIME1XdiaEnVvfPdkw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgEvT8YYxHSam8ibFp2LzgHyEjNLvzCsd257vEgib42iablKQYLus0DAORtiaxMRRLRp1JwV3jBhH91ksA/640?wx_fmt=png "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/IaOSZ1DGNLibTuXMCUMhwGCazTMxBzLGictlam7eTmG1b1ficvmqCHJTkRAh3xWjIO7lEiak31Nctr2UOV5KHibNljQ/640?wx_fmt=png&from=appmsg&randomid=y9rp3k08&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
  

#  某一cms后台代码执行漏洞   
 船山信安   2024-11-23 10:35  
  
## 前言  
  
最近在漏洞平台看到ucms后台漏洞，便寻找了一下发现有开源源码，分析一下  
## 漏洞复现  
  
首先漏洞发生在后台，也就是需要先登录后台可利用，有点鸡肋，但还是要学习一下  
  
后台管理中心->文件管理->任意选一个编辑->保存->抓包![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOobpB6uDmTEFyGdPnibLjTwHY080XT6UOvMhdaY1bD7HTXkBLFicwWvxn1FPT2hDFcBRq8liavP4SUQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOobpB6uDmTEFyGdPnibLjTwPHO62R2pyyEvTokY1smOgUPiceU2wzKhhHHgkWicPaaArVY67ArpsAwA/640?wx_fmt=png&from=appmsg "")  
  
然后访问该文件名![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOobpB6uDmTEFyGdPnibLjTwDqEzs8hlsQZSIYx0Uc9xKOWJtK2djwCt8WPUCibNrjhKRriadtSnITVA/640?wx_fmt=png&from=appmsg "")  
  
## 漏洞分析  
  
uncms/index.php 44行  
```
```  
  
也就是说获取get的do值为文件名，跟踪一下漏洞指的sadmin/fileedit.php文件  
  
sadmin/fileedit.php  
```
```  
  
可以看到该文件对传进来的路径与内容没有进行任何过滤与验证,引发了漏洞  
```
```  
  
在请求co参数的时候，这一行，w指当文件不存在的时候会自动创建，由此触发了文件写入漏洞  
  
来源：https://xz.aliyun.com/ 感谢【  
路过的一个人  
 】  
  

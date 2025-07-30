#  安服水洞系列 | Tomcat堆栈跟踪启用漏洞   
原创 进击的HACK  进击的HACK   2024-10-02 09:20  
  
国庆放假水一篇，说到水，那就不得不提安服水洞系列，也是久违的更新了。  
Tomcat堆栈跟踪启用漏洞，听上去高大上，其实非常简单，一看就会。下面是案例。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DuibU3GqmxVmRsdItbBVRKegNHicHQvAHDdZsGpLVU7touSU1AU1twHTfRjG3Vu5aUh0RnPPllfVUhs4qdWF5QYQ/640?wx_fmt=png&wxfrom=13 "")  
  
声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途给予盈利等目的，否则后果自行承担！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zYJrD2VibHmqgf4y9Bqh9nDynW5fHvgbgkSGAfRboFPuCGjVoC3qMl6wlFucsx3Y3jt4gibQgZ6LxpoozE0Tdow/640?wx_fmt=png&wxfrom=13 "")  
  
  
  
正常访问一个url，比如https://example.com/， 返回404，看报错是Tomcat  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgUywDEq1rpUvPXOU56cBicbzDaiaBgibqX55x8PUL5PQLBpicTXwRvZwJrfpxk0KQoLxzMANSicxpGnlA/640?wx_fmt=png&from=appmsg "")  
  
在url当中添加一个不存在的参数和参数值 \[，如https://example.com/?a=[  
```
https://xxxx/?a=[
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgUywDEq1rpUvPXOU56cBicbJzIWIpDcaOXdpoJPIWQsaiau5ZziaTP6c7P57JlGlWJDCzda6GZ7X3Fg/640?wx_fmt=png&from=appmsg "")  
## 修复方案  
> https://cloud.tencent.com/developer/ask/sof/117138051  
  
  
找到tomcat的配置文件server.xml，默认路径在apache-tomcat-9.0.89\conf下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgUywDEq1rpUvPXOU56cBicbP7V2F6skDX8KfpfucXhwMuCBjHnFGx8t1qzl5fALjGuCTvRiankaKicA/640?wx_fmt=png&from=appmsg "")  
```
<Valve className="org.apache.catalina.valves.ErrorReportValve"
    showReport="false" 
    showServerInfo="false" />
```  
  
  
修改后重启tomcat，400不再返回堆栈信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgUywDEq1rpUvPXOU56cBicbA3U8fsQZo8PWzbm1EC9TicEsGBtibwhAdUKtZ2HKmhe3cvs98JGsazpg/640?wx_fmt=png&from=appmsg "")  
  
在这里庆祝各位师傅们节日快乐，顺便推荐下最近在看的书。  
  
  
  
  
往期推荐  
  
[frida|修复被加固的so文件](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486143&idx=1&sn=360e028de2a9aa3df8b27382e274976d&chksm=c150ad54f627244230dc34debc335e895611961cb181af0b36fd0dd519e3bcd4113cd5c20c20&scene=21#wechat_redirect)  
  
  
[更换了麒麟操作系统](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486118&idx=1&sn=9b3915d4ec29f4612682015846bc8e2b&chksm=c150ad4df627245b52fb74eaaaea9cde2ece9f62f340227b3bbd59d077ac3ab94fe51ff64e31&scene=21#wechat_redirect)  
  
  
[web指纹finger字典合并（附源码）](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486101&idx=1&sn=baf5bdfd8e1f4e99c2b78d5f4d2391e8&chksm=c150ad7ef6272468cd28353bc1bad78bd9bb8adb63c70905fb3ce856d8a7eb409e44ea6d42c3&scene=21#wechat_redirect)  
  
  
[在混淆的so中寻找sign签名函数](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247486092&idx=1&sn=1337e6907b7f0643a3dd361d1b0bdb35&chksm=c150ad67f62724717af1c95f6c45951454ce2fb1c033a7bb366cebd18f41d7775b3fd8ff2d18&scene=21#wechat_redirect)  
  
  
[价值$5,825赏金的tomcat信息泄露（CVE-2024-21733）](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247485999&idx=1&sn=b9c10f06a394728fa4a24682bdadce23&chksm=c150adc4f62724d2053a77b6415e49b3e545e1cd77e05d66e36757a0d34228ec1f653c15ae2c&scene=21#wechat_redirect)  
  
  
[分析Actuator未授权出现的原因](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247485856&idx=1&sn=40c2737a6dc73466bc50e9a0f7c75b2b&chksm=c150ae4bf627275d6b7c3935367c23dbf167f31119d43c9c2383b9e678265deb0b823d16f39b&scene=21#wechat_redirect)  
  
  
[代码审计 | API批量分配导致的普通用户垂直越权到admin](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247485820&idx=1&sn=d62c97c7f544683b31280e8412dc7ee1&chksm=c150ae97f62727812b79436a078fed7d363c681695f673b58765de5aab7cabefc6236a12c179&scene=21#wechat_redirect)  
  
  
[代码审计 | 发现项目的swagger-ui未授权访问](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247485797&idx=1&sn=88ae7dda1b439fcef90e06c5a35ac4be&chksm=c150ae8ef62727988ac55dcd8d3da18f46a9ff58e2e8507b81914c9ab9cb3c2514e21d93a5b9&scene=21#wechat_redirect)  
  
  
[好用！一键化搭建各种虚拟机](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247485612&idx=1&sn=64652a2c46b9bf4eba1ec966a88f0abe&chksm=c150af47f6272651d4853691f9cd2674d4803714b695179dc404ef8632fc87f520a05064dbce&scene=21#wechat_redirect)  
  
  
[微信小程序/网页动态调试的方法](http://mp.weixin.qq.com/s?__biz=MzkxNjMwNDUxNg==&mid=2247485528&idx=1&sn=b25ae79ec1279f219e2027a0566a3024&chksm=c150afb3f62726a50aac52661948df228ea96ca38b5a391ed75947c2c4ad72218f5e09c4c875&scene=21#wechat_redirect)  
  
  
  
  

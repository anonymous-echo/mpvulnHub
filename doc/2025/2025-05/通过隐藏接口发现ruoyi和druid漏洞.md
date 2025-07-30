#  通过隐藏接口发现ruoyi和druid漏洞   
原创 锐鉴安全  锐鉴安全   2025-05-25 00:26  
  
声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
关注公众号，设置为星标，不定期有宠粉福利  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4ricRiaXQ6WVVlTAgCW8HUbC2rHkicA2rpDNEPAGyiatRibqB9LN5NyHcqLCmbibM1siaumqF5Yu6UtSsYA/640?wx_fmt=png&from=appmsg "")  
  
浏览器进入开发者模式，切换到源代码，直接暴露网站的打包方式为webpack。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5hhg8TynotiaeKqiaLjBnYdLS89cibnZP5SfhFpRjxDgSagD9d2ib4kIhcw/640?wx_fmt=png&from=appmsg "")  
基于网站的指纹，使用packer fuzzer，批量进行js分析，这个工具的好处就是可以全量下载js文件，并批量分析。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5QicMu9cc9wCdOYRSpWVqmB7aDzqdaQ6Svel8NOYyF2ZUkUA0v8aRbxw/640?wx_fmt=png&from=appmsg "")  
  
分析完后，打开接口无任何有用信息，难道连基本的接口都没有？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5pAerOfW6ZClWRAmS4RR3DjbLgZvw2AduhVjiaOFAMtNbSdRVgUFHs0A/640?wx_fmt=png&from=appmsg "")  
  
抱着怀疑的态度，  
手撸js分析脚本。复用的是HAE的规则。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q55GQE2rbOoBPawjYfyFLGqm7ib3UBZCAF4KTl4gNPpgVvNkUgRTSKwPA/640?wx_fmt=png&from=appmsg "")  
  
运行脚本后，在控制台输出了每个js及里边对应的路径信息。证明  
packer fuzzer确实有缺陷，好多接口都漏了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5jBibHjP5p7dJyKCz2TArPQiaelwVtwib7gptuGmWSU2QnJlvnvibsib5Isw/640?wx_fmt=png&from=appmsg "")  
  
结果输出到_path.txt文本中，直接可定位到关键的js文件位置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q53QEFzLibPjGjpiaf9wIicSqgN3hKZax9hibVF5nJwC4M4RGWB8fIVR2CjQ/640?wx_fmt=png&from=appmsg "")  
  
接下来具体分析js文件，可以发现在登录系统后才能加载的文件接口，针对发现的接口，进一步开展漏洞挖掘。接口有点像"若依"。  
  
  
首先是隐藏页面register，这个路径关键字建议大家加到日常的目录扫描字典中，非常容易出洞。  
  
可以看到前端只有登录页面，没有注册页面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q59yEAu38JyUtKgGyYiawibCvxic1VLocVsRUys1kRVh5epGvgvaTHysepg/640?wx_fmt=png&from=appmsg "")  
  
js中找到的注册页面路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5ZlEh1XucS8JnRdNfCicmAL55sHkOP5QvAwPSHty8QQDkIEGx6cYERHQ/640?wx_fmt=png&from=appmsg "")  
  
拼接后来到注册页面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5R1uSZtqg1J1RrqVsJrmoOSuAFZYOgSHiboUyhk4ViaD2dlec926C4tlg/640?wx_fmt=png&from=appmsg "")  
  
拿到注册接口信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5d0RumI4oN5ODOMYCIBj4UjSCJ4R8mH92EiazBTbiaM3v9MvQluPXqAcw/640?wx_fmt=png&from=appmsg "")  
  
  
prod-api，“若依”的特征。通过访问不存在的路径，使网站报错，通过网站的报错信息，可以看到是spring开发的站点，直接拿spring字典扫描。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5bNNTXtibR5mjeemiakPgicibY9ybibIKh2TuEx8e4Kl5ql2oicaFDeHF9abg/640?wx_fmt=png&from=appmsg "")  
  
在使用druid相关的目录字典扫到时，发现了重定向，原因为druid鉴权了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5Uppe8RhKTkNGTu2jK8XK6UpGvEqjS6Kkjrj0yHOpYmMOiazSzTlG7ag/640?wx_fmt=png&from=appmsg "")  
  
  
打开链接，发现同一域名下，http协议下，居然有不同入口，应该是重定向的原因。此前的https为实际的业务入口。http为若依入口（测试时未删除）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5uStgTUzqhQs7WNxM7kzxqf1BgcepCEmDOoxTeLyJEpy3UnawoxRLBg/640?wx_fmt=png&from=appmsg "")  
  
  
同时，出现了“若依”的logo。基本可以确定这个系统是ruoyi了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP57sgRx7RP5bW2acDp4UxzUAfzHsGgzP1Qqz1xBkyEAC2cMvCSWJ4b631p7pID0xWs9rbKmENGbvA/640?wx_fmt=png&from=appmsg "")  
  
  
经过多次尝试，使用ruoyi提示用户不存在。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5A5ria7uicRibo9StCfZScRMoOzRqzaL38k9Lr1Hb099c7dECINb2Ppk3A/640?wx_fmt=png&from=appmsg "")  
  
使用admin，提示用户不存在或密码错误。那账号就是admin。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5nhWg4hQR31OicURo2PaKYQeED0Qs6a2OJ7JlJXznwDXGYaKsmtCEH3A/640?wx_fmt=png&from=appmsg "")  
  
  
掏出ruoyi的漏洞检测工具，下载链接见文末。  
  
NB，直接重置密码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5oiaFS1GWk4a3HE575rUvqO72WiaM9jhbjZTjrHhV6riaCzE1pLicUxZGpQ/640?wx_fmt=png&from=appmsg "")  
  
使用重置后的口令登录了系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP57sgRx7RP5bW2acDp4UxzUc3oaqehccRj1T2e8ibYbyEYEyXN8uKj0VRhkD0g2XrNlv9CoCDf01EQ/640?wx_fmt=png&from=appmsg "")  
  
  
以及druid的登录入口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4qzmqEZWWKgvy2IJbem9q5w65EK2M1hpvWdvnSA4VhVm4dx3qQ3EgM32W0gUL0j91VJyoxMfn4Ag/640?wx_fmt=png&from=appmsg "")  
  
使用admin/admin123，登录druid。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP57sgRx7RP5bW2acDp4UxzUzib09OibghqlGz7ygpdJp2qevXcoBMviciaaFT7EwPoOtcfZiavp9fMIbuA/640?wx_fmt=png&from=appmsg "")  
  
  
收工收工，顺带总结下ruoyi的特征，供各位师傅后续挖洞使用。  
  
1、接口特征针对druid  
```
/druid/index.html
/druid/login.html
/prod-api/druid/login.html
/prod-api/druid/index.html
/dev-api/druid/login.html
/dev-api/druid/index.html
/api/druid/login.html
/api/druid/index.html
/admin/druid/login.html
/admin-api/druid/login.html
```  
  
  
2、ruoyi接口特征  
```
/captchaImage
/common/download/resource?resource=
/common/download?fileName=
/monitor/job
/monitor/job-log
/prod-api
/prod-api/common/upload
```  
  
  
3、logo特征  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP57sgRx7RP5bW2acDp4UxzUZuaal7KUchNJaGBuGcJ5o81LxknhjWrmbE4ibvnyuTRafH1s1sSibzAA/640?wx_fmt=png&from=appmsg "")  
  
  
4、系统加载特征  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP57sgRx7RP5bW2acDp4UxzUcUibHOmeqd6lDhPtSvPQ4ibWpAbqCgundKx7Q6VAZiaG8TWziagiczydZXw/640?wx_fmt=png&from=appmsg "")  
  
  
工具获取方式：关注并回复关键字“250525”，获取下载链接。  
  

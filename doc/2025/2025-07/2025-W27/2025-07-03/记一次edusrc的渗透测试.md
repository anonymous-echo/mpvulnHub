> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwODc1NTgyMg==&mid=2247486206&idx=1&sn=7d166c71f60c37671cdc33f657228818

#  记一次edusrc的渗透测试  
n1sdkw  蓝云Sec   2025-07-02 16:01  
  
1. 信息收集  
  
目标地址:.  
.com 这里用了百度语法  
  
个人所见，如果要挖掘edusrc的话,可以尽量避免门户网站,因为一些漏洞都已公开且有修复方案了,除了弱口令以及敏感文件路径泄露我会直接跳过，直奔一些业务网站。  
  
如:毕业设计系统 人才招聘系统 以及一些常见的业务场景  
2. 分析  
  
网站的具体结构是这样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQ0HWLQTIicG25NDE1qYwkgAus2oRmWSOEk34qzGFjANx5HjmvdUmhnkw/640?wx_fmt=png&from=appmsg "")  
  
有4个功能。都是采用相同的cms。但前三个是跳转到统一身份认证平台进行认证的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQ4ic2FCUOETsLuQ2bx2qeD8A1YUib2T8Zjicqibdx9eZuk8FUtYibpn5kYgA/640?wx_fmt=png&from=appmsg "")  
  
只有第四个是本地认证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQuJSRWiczwSrkoxCKdIRPVApDzUECQ1OcjtGqqB5fgD9TtsXINpPdAaQ/640?wx_fmt=png&from=appmsg "")  
  
但是这里我看到了一则公告:知道了登录账户时什么类型以及默认密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQcMknN2zM0kzZPnQA35Qnx7h8EyBTEYgHnhvIRc8T1lhzOgCMoqBxYQ/640?wx_fmt=png&from=appmsg "")  
  
通过公告可知,该网站的登录账户是学号。。默认密码是123456  
  
那么我是不是只要得到一个学号就可以登录了？？？  
  
收集方法: site:.  
.com 学号  
  
这里通过测验了多个账户，最终成功了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQjpMSwzibyvWVk5yPDbsibXRpbicdsGiaYgx96EnyUwSVAZNmO23feURQGQ/640?wx_fmt=png&from=appmsg "")  
  
但是,当我点击系统管理的时候  
  
提示我权限不足？？？  
  
这里值得思考的是:  
1. 权限不足?那么也就是说同一个登录系统,具备多层权限的分别  
  
那么后端是怎样通过数据包识别到权限的？？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQiavibHNMu0iarhMujzKzzsh2icDkfIAVxQfaSibvCdGib9YiattmkWcPoYILw/640?wx_fmt=png&from=appmsg "")  
  
这里我用burp抓了一次包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQKa2iaMvFlbMNthzBaUR5XNI7bQe3D4ibOj5bj4r6fm77Qj0UnOlzBvlA/640?wx_fmt=png&from=appmsg "")  
  
通过cookie观察到  
1. 该网站有safedog 安全狗  
  
1. Cookie里有username 是我的账户名，password是我账户密码的md55密文  
  
那么password值是我密码的密文，也就是说，他还要验证username和password是否正确？？？  
  
但是这里我还是蛋疼的改了下username为admin  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQxUh10JuvFvN6jDIq4b26eLUOvaCl0rKmu39PaY9MA1QhCelnXKmxlQ/640?wx_fmt=png&from=appmsg "")  
  
当我放包过后,居然切换到了admin。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQdqCT9ticS9lrDtZGZ3Lp72Cxz6Q0NNE5wFAz67mTJribOicpicSVOrDoGw/640?wx_fmt=png&from=appmsg "")  
  
也就是说，password值并没有什么作用？？还是说admin的密码也是123456？  
  
当我切出去重新试着登录，发现admin的密码并不是123456.也就是说，网站是根据username来判断用户的。Password参数没有什么作用。  
  
这里再次点击系统管理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQH6WBdRjetTUwoKarDfIUmAfKdhzGPhjibDNDSKntt0GLyxP7icAyAxAw/640?wx_fmt=png&from=appmsg "")  
  
成功切换到了管理员页面，权限提升成功。  
  
同时，我们知道该网站有4个子系统。并且都是同一个cms  
  
那么其他的是否能完成权限切换？？  
  
试了一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7C9oVgOBoX4R1RE00tQDtQzpGP7Aoj5b9pky8NvxEukCQeFCFWs0icvLLC0RcciaYCosib4pfzGxV1w/640?wx_fmt=png&from=appmsg "")  
  
发现可行。。。  
  
一个username参数直接是管理员。  
  
相关内容已提交至edusrc。。  
  
  

#  Src漏洞挖掘-拼出来的严重漏洞   
 Z2O安全攻防   2024-11-22 09:42  
  
**No.0**  
  
**前言**  
  
  
挖洞就是要多思考，我是爱思考的张三，给大家分享一个严重漏洞的挖掘思路。  
  
，我是  
  
**No.2**  
  
**实战过程**  
  
  
1、A站点重置密码处需要提供账号即学号，以及姓名，接下来需要信息收集到姓名，学号，以及后面会用到的手机号。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQyFsDSsVmCFwhDbDhWJOfQyia4qLgyWp9ibluiaiaqWODnWg84sibmkKUp3Q/640?wx_fmt=png&from=appmsg "")  
  
  
2、主站SSO重置密码输入工号即学号，通过信息收集到证书站学号  
  
语法，site:xxx.edu.cn filetype:xls 学号  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQemg8Erias00tg4LsPBytuvC06Jy1ZNsK6XPQM6f7MUGIYs3CISFiaicEA/640?wx_fmt=png&from=appmsg "")  
  
  
3、出现姓名以及中间四位数脱敏手机号，188xxxxx888  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQ9tGc6m3DRBJXucAaWdC0EHBqn096lqs4AYhVXt8iciaFSwibxicxibkvXRQ/640?wx_fmt=png&from=appmsg "")  
  
  
4、通过第一步学号+姓名校验后，此处需要输入完整手机号通过校验才会下一步  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQFk7OibZbwKKDI5TmZQvYe0nF1S48sA9ZLTRZibk42b85FT1DrFdWZIfA/640?wx_fmt=png&from=appmsg "")  
  
  
5、爆破手机号，根据返回包长度判断，获取完整手机号  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQqDBRptMfy9RM8yfGibY5AT2r4rEIEBeBN5CmsYtdoa2iboAXdoZKXRiaw/640?wx_fmt=png&from=appmsg "")  
  
  
6、输入学号，姓名，手机号  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQCN9n8pfCXUHTnenzO6FK0KYmabuVD7WVQFeelsWFjocv1s4TRiaicPHQ/640?wx_fmt=png&from=appmsg "")  
  
  
7、设置新密码，无需旧密码验证，抓包发现X-Runtime疑似短信验证码  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQhOcrPb71kgjxQoQXVSQaPsgNKrRibX0kyUa8RLJW5ARziciby8rhicQN5w/640?wx_fmt=png&from=appmsg "")  
  
  
8、输入X-Runtime的值107574即验证码，通过校验成功重置密码  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQS8KtPn7HuzabnlDho2sVp0FzQEHC3cSVvoIx2fRTyAeYpEIWE9oh0w/640?wx_fmt=png&from=appmsg "")  
  
  
9、此账号密码可登录SSO  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQL8aOhKrn4wZicbsuyiayTibeh6XSWDtPFhhWh8pF5n9RjyeB0GNy5PgHA/640?wx_fmt=png&from=appmsg "")  
  
  
10、成功进入后台  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQficS8V4om9gcsdicVeblIHtU5KLgickxqYBEQPmGldwCEsfZ1WEl40crA/640?wx_fmt=png&from=appmsg "")  
  
  
11、漏洞评级：严重  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zmDcwnpIworOWwhI9rZ9AQ9tzrOgzIXibhI3t2m6VTDh6yhh0HjnpqiajkdaANRH85NicmqtQKpYMBg/640?wx_fmt=png&from=appmsg "")  
  
  
  
one more thing  
  
  
建立了一个src专项圈子，内容包含src漏洞知识库、src挖掘技巧、src视频教程等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuaehOF5tHCCpjqsaibBZvicC9icONEE7ZAStTkNtl3l9JIzB97TZeiafOSbnkusSfliaROBLIdeLK4xupQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuaehOF5tHCCpjqsaibBZvicC9nurT4YsPibj0DdE4EVHnQJKMDfUKNmzjCqKDejOJRj71srsNkXXGCGw/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuaehOF5tHCCpjqsaibBZvicC9k2aael12glC8KLjlDxwSD2ZJNG5r6Bo68hmiaDfCIibEPytBj1MnQILA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuaehOF5tHCCpjqsaibBZvicC9vfPsfTmZkUjeuJ5v9Znumokj7aV7UjzuHzteeP9ORtRbuuvcpNTkTQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuaehOF5tHCCpjqsaibBZvicC9D7xNU1xOW7U54MZfJZjeibBzXMNPhvV3eD7k82ibicXsHNRzU9vYjFbNw/640?wx_fmt=jpeg "")  
  
  
  
  

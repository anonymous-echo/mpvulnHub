#  SRC挖掘之Access验证校验的漏洞挖掘   
 蚁景网安   2024-12-31 08:30  
  
漏洞已修复，感觉某大佬的知识分享  
  
任意用户密码重置->可获取全校师生个人min感信息  
  
开局就是信息收集  
  
对于挖掘edu的信息收集  
  
1.可尝试谷歌搜索语法，获取学号信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhLJDlgPn4zXlV3SCzxwlDom8pQjzYhK5v7H0MM8VBtWeKmRnNZ3RCSA/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJh5ic1uskebNH6OyiaorI12V4oHORaOFibhXFUy6oqVqFmhsQ10CiadWia13g/640?wx_fmt=png "null")  
1. 1. 旁站的渗透获取  
  
1. 2. 学校的贴吧获取(大部分都是本校学生)  
  
当然我就是闲着蛋疼，进了目标学校的贴吧，跟他们聊天，然后你懂的(不推荐这样去做)  
  
类似于钓鱼吧  
  
在获取到学号的信息，自然就是水到渠成  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhFovCISK8EoTU8VJaSPCAu5TC90sA97kVgJGoDStFMVJe5lKbXezhbQ/640?wx_fmt=png "null")  
  
由于权限太小，功能点太少，fuzz不到接口，j也没有铭感接口,越权就更不存在了  
  
放弃了，去看看找回密码吧  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhe4m0q8YMgD79sXUkxReibIqED10eiaYzwf1pFQtdyepdWuRmQpkC0N4Q/640?wx_fmt=png "null")  
  
先爆破一波账号是否存在(能不用别人账号就不用)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhxzXAe6icC9YdlddpIwySM5Spsk8tO0GPOkCg1vLHeAVPdUVSyl4QmZQ/640?wx_fmt=png "null")  
  
123456账号存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhIalAgab8ElzAcnt9WO7LuPAicibRCtj7NBGI9Jfajcx8SolozDCLIsfQ/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJh5a2hKYBcfvR3Aba8d5EM3jL2tbA3icK3BoanowtOqgAYM9fytWxYh6Q/640?wx_fmt=png "null")  
  
找回密码这里随便输入3个必选项然后提交  
  
尝试更改返回包，看看是不是只有前端校验  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhDYIMhzv0lf9jXj7z0eos7OwCIKxYEETMQKPn6NK9icpuwxkHdBWQwGw/640?wx_fmt=png "null")  
  
果然跟我想的一样回到输入账号处了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhO1UibM0fbwAjDnrtfKYChrAn4bQdn9BhaLFqbibI8NpzMgRqfJiahsLSA/640?wx_fmt=png "null")  
  
那没办法了，咱还是得用关系，用好大哥的账号，然后再从他个人信息里面掏点东西过验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhjqnBzdYticRicD9EOxrkXurG3XtxNfzHNAficricFsHrcicDQeKrpVrXhrg/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhQnqibm2deYybk3bfPc2VgaxDmuCCdEWTPvnPEpB6UqNjXgUWI9iaE3AA/640?wx_fmt=png "null")  
  
重置成功了，但发现一个不对劲的地方，仔细想想发现有机会可以绕过  
  
首先Newpass参数是加密的重置密码，也就是123456  
  
Post发包就一个参数还是密码  
  
通过排除法能判定  
  
Access-Reset-Ticket是校验用户  
  
一开始我是不信的，CAS校验应该是这样的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhoAricxt4r1K5QsfyTkEJiagcEmChJaQBVAJ6YatibG9HEFcmCSxtK8rqA/640?wx_fmt=png "null")  
  
本来TGT是CAS为用户签发的登录票据，拥有了TGT，用户就可以证明自己在CAS成功登录过。  
  
这些直接大缩水呢。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJh182VcBSYPbQ5mVibUn0ZNd1F6cdnwzrMZCXsjXBFjtPT9niaT0rQ9WTQ/640?wx_fmt=png "null")  
  
但又没登录  
  
怎么获取的当前用户的Access-Reset-Ticket  
  
真相只有一个，看看接口哪里获取到的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhHxWBOynHia3HxT2Ric9TqZzibdHgeiae3ib7EK3CqhomD73tb9hkqgtQffQ/640?wx_fmt=png "null")  
  
原来是在输入要找回的用户就会获取当前用户的Access-Reset-Ticket  
  
6到了，开发是我大哥  
  
尝试修改  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhegs40CBYRkkGc6KaXomslcX6nbDzBs8ibDvYmfcYGyx3ubJfyuwQLRw/640?wx_fmt=png "null")  
  
可行，修改管理员账号，然后起飞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhxAYB66jJrPbRcHcGPAQrjXEhOxHCOibfm25e5uXyaEH7KwMNqibTfYZw/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhYbqUKcyQj93O9CJgsZ6Hc6lfIEwgg1IH2hdpRYABSVhU1J8UiaqQVFQ/640?wx_fmt=png "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfuQ81NKqhpfax791z4lSJhz1XH3Cot65fPVOT2099mOx0jiaRBul4WUadTibbC3v90vc5U9wpJYUBw/640?wx_fmt=png "null")  
  
下机。漏洞已修复，厂商也修复了漏洞更新到了最新版本。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6iavic0tIJIoZCwKvUYnFFiaibgSm6mrFp1ZjAg4ITRicicuLN88YodIuqtF4DcUs9sruBa0bFLtX59lQQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
学习  
网安实战技能课程  
，戳  
“阅读原文”  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNzY5MTg1Ng==&mid=2247489822&idx=3&sn=3739ae1e9cbcd22ab23c790068f69d15

#  企业SRC实战挖掘  
小王的黑色短裤  富贵安全   2025-06-30 00:00  
  
# 漏洞描述  
##   
  
此漏洞是由于  
cookie参数鉴权问题，造成任意用户的账号接管。  
  
公众号专注于分享最具有实战的漏洞案例，师傅们  
可以  
关注我们的公众号，我们会分享各种实战技巧在公众号和知识星球中。  
# 漏洞复现步骤  
##   
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ4kWwcR7UMMjOsu1Ohet26IYuBic8EupPO9RiaBBXibgeqbRC7qnE5BUMeA/640?wx_fmt=png "")  
  
进入公众号，来到网上图书馆。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ4J7NmekfLH2fZmXxBdy6PXobfYcHYE8ecOdDALAo4RxHDnWdOib6Paqg/640?wx_fmt=png "")  
  
进入公众号，来到我的模板。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ4X3fBuIejCKMMXdJKOGQ17hh6MynrglFH8dmw2JcqwBhiaJMVicLIERXw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ4n6rQ5icrEbq5TLfVgAiaOS8p6zEndfJNzAxHqskvOqbV6m0HXZfhibwDA/640?wx_fmt=png "")  
  
进入我的编辑资料，进入联系方式中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ46DSIgJqt4j8sbxwknztWvYtKEWhibPPJlHF7LOkLF5TtIgL1ZcCzWLw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ4KspyJAicRJh3Z1NGqHDxicOM78w6ftGr8y1ia9rJknibUQrhjnOic6b29cw/640?wx_fmt=png "")  
  
这里修改抓包，正常修改成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ492nia32DcTwsbTSv16N9XzVY7AbJHq9zpITyO1rYu4Ua2iat4LQb7njA/640?wx_fmt=png "")  
  
   
  
这个时候，我删除了  
cookie里面的其他参数，发现决定身份的参数，只有一个，即这个参数1xuezhe_LoginMid。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ49PuDibcD9NIWom2ZhlvGJQNHWn7nckyWn4dELnmmRSQoCQglRWo7tmQ/640?wx_fmt=png "")  
  
这个时候登录，另一个号来进行测试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ47cQl0lMYubWn8Ygt1JQLJIPM2XU66Nu1WvvEJlIpKD6Leic8bxFROicQ/640?wx_fmt=png "")  
  
  
可以看到该账号的联系方式为。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ4xK1pKr7oCmTIz0O0APeot6PIwQkPPEIjNkDDBR0GYDZnV36EIfIZ1w/640?wx_fmt=png "")  
  
  
在该账号的随意一个地方抓包，即可得到该账号  
1xuezhe_LoginMid的值。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ4j3Jd6CTejS6kQScMKPgKgnmu1MK5aJ5BaPkheuraRJvlXJnJut6nFA/640?wx_fmt=png "")  
  
这个时候发现两个账号的  
1xuezhe_LoginMid的值相差不大，一个是1xuezhe_LoginMid=3787424，一个是1xuezhe_LoginMid=3787599，只需要遍历最后3位数字，即可。  
  
这时候，我们来到修改资料的这个数据库。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ43kn5T5iawQclsMA1NgqcTrzKQnTFErx2RUbLhgkDZ4ETkejibZ5juMtg/640?wx_fmt=png "")  
  
将  
1xuezhe_LoginMid=3787599，修改为1xuezhe_LoginMid=3787424。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ42vyfYHcmvP3O0ro1iaHibFZoKs6502bGh70JhBGg7TL3ySJedKfDoV9g/640?wx_fmt=png "")  
  
  
这个时候发现，还是无效对漏洞，这个时候发现  
post传参数里面的mid参数和1xuezhe_LoginMid的值一样，这个时候就在会想会不会两个鉴权，于是将mid值也修改为mid=3787424。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ4lqjWUoU5NJBCwvIyIKsVMqWgUQPbLUDSeX9yfhfsX91ZN0qiazhBkXA/640?wx_fmt=png "")  
  
这个时候再去看是否被修改。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Tb6OwBlojE9mK6sVMGwa2QcDbzarHNJ42ehjLexTWwTm4vhfoXia78zNXAwvw6wZEDAVTecHcz3KCgicqPxuGbCg/640?wx_fmt=png "")  
  
成功被修改，造成了账户接管，全站都存在这个问题，可以直接造成任意用户的账户接管。  
  
在这里我只是举一个这个功能的例子，其他的功能也是存在这个问题的，直接就是接管别人的账号。   
  

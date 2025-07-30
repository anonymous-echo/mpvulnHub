#  SRC实战：指纹识别->代码执行   
 迪哥讲事   2024-08-13 20:28  
  
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
  
# 四.提交src  
  
教育src点到为止，不要上传马(bushi)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wF30Z0OMuW3FEiazh6uEkXapzt9ypXzL88fFrSkctp3DkOdSAO3FctQugJ2iaB5bzmlia9m6OfZF5Wic0qXH0biaFzA/640?wx_fmt=png&from=appmsg "")  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  

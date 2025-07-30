#  Yonyou NC6.5 uapim文件上传漏洞分析复现   
原创 刑天攻防实验室  刑天攻防实验室   2023-11-24 18:09  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/USH8Nb3Hz5Svdc9eaaEr5WD2rHSNMQhFKuWFBusuiaxSG937KC8L28qKicSDs87KSMhJEbeqD9LL961vib4ja4f72y8gXRzaJ7s/640?wx_fmt=svg&from=appmsg "")  
  
### 环境配置  
  
  
l 系统：Winserver2008  
  
l 数据库：Oracle  
  
l JDK：java 1.7  
  
l 复现版本：yonyouNC6.5  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/USH8Nb3Hz5Svdc9eaaEr5WD2rHSNMQhFN0FAcE1LlAVjSMwj6ibJrwrPkLyX8jeyPoHPQESEC6UDjPicVGpoynU6X3EPOib5icRQ/640?wx_fmt=svg&from=appmsg "")  
  
### 源码分析  
  
  
URL:uapim/upload/grouptemplet?groupid=test  
  
对应的路径  
  
com.yonyou.uapim.web.controller.UploadController.class  
  
我们就只传入一个参数groupid，获取临时路径文件路径和真是文件路径；244行DiskFileItemFactory类的参数factory，245行设置缓存大小和临时存储位置；248行由于maxSize是null，所以直接进入252行try语句  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UfIgFeC2Vot5qC9oP978WaPKDAuOia0EUBia89gHL8pC1XIg0elMCiatJHrPDA12dVDy8YhOYjRTRrB0ZyYI19c1g/640?wx_fmt=png&from=appmsg "")  
  
252行try语句：创建了一个解析request对象items，得到所有上传项然后创建了一个迭代器进入dowhile语句，每迭代一个对象item，就调用其isFormField方法判断是否是上传文件。如果文件没有上传进入81行if语句：获得上传文件名filename和文件后缀名fileEnd；268行我们传入的fileType是null，所以到288行处。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UfIgFeC2Vot5qC9oP978WaPKDAuOia0EUicE8GStRIR5PpFMRic7a9DsDNv6jibTibmibGIduICLJRvNVDqQ6sMwQbRg/640?wx_fmt=png&from=appmsg "")  
  
288行：定义uuid的值为head，创建一个StringBuffer类的参数sbRealPath，将filePath真实路径+uuid作为文件名称+”.”+fileEnd后缀名；创建对应路径的文件对象file，根据filePath创建路径，upload上传文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UfIgFeC2Vot5qC9oP978WaPKDAuOia0EUzhdpCGQPNjSJAbQiaM3GCl7fYGrSRdUhPzgD1Z2Ehk71fLqSpq91ibLQ/640?wx_fmt=png&from=appmsg "")  
  
文件名是固定的head，没有对后缀进行过滤,但是上传的路径是不可控的，利用范围空间有限  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/USH8Nb3Hz5Svdc9eaaEr5WD2rHSNMQhFKuWFBusuiaxSG937KC8L28qKicSDs87KSMhJEbeqD9LL961vib4ja4f72y8gXRzaJ7s/640?wx_fmt=svg&from=appmsg "")  
  
### 漏洞复现  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UfIgFeC2Vot5qC9oP978WaPKDAuOia0EUgibMLlvRkJUlscCqBCHSQykpt1uNb6ic6qQsOf8eibH37jqkr2ic4puNow/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UfIgFeC2Vot5qC9oP978WaPKDAuOia0EU4sdEdPmNSSARXZeedwViaE8ILz13ib4XHYLM4D0lBvKyN9iawo6P3tQgg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/USH8Nb3Hz5Svdc9eaaEr5WD2rHSNMQhFUcrpxbyadHpBfcSaKz5KXO0WsGzXegiaflxNZVXVPQ3yicct8QhRPZ60LiasF4icYKicd/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/USH8Nb3Hz5Svdc9eaaEr5WD2rHSNMQhF65j6ZACFlHRf745hS0JUREvtKVWrrgAeL5ZJj17IJKEmjVQHk83IBLdjD4v2SpYq/640?wx_fmt=svg&from=appmsg "")  
  
###### 公众号：  
  
  
###### 刑天攻防实验室  
  
  
扫码关注 了解更多内容  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UfIgFeC2Vot5qC9oP978WaPKDAuOia0EUgJE1XuFB6YCicafl9NYUp8BvUc8QQ7gicDsM92sic3wszNdHQicYJrtdSQ/640?wx_fmt=jpeg&from=appmsg "二维码")  
  
  

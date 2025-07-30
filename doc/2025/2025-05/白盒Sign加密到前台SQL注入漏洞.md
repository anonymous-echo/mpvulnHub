#  白盒Sign加密到前台SQL注入漏洞   
 阿乐你好   2025-05-29 00:30  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
一、前言  
  
    这个项目之前自己已经审计过了，拿到了前台rce也成功给学员交差了，但是今天自己重新进行分析的时候发现了一个新的前台注入点，写出来分享分享，里面还包含了参数sign的加密过程。  
  
二、审计过程  
  
    还是熟悉的Struts2框架，这里查看Struts2框架的相关文件，来寻找路径对应映射类和方法即可，包括去查看相关鉴权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW3w7PmXR806X85ZYd7QW8Zib05POdibK1HCoBaD6KRcba5cq2CDKGfeibe91NUmVQesAymN6RXSgOaw/640?wx_fmt=png&from=appmsg "")  
  
    这里直接定位到了一处对应的配置文件，知道了路径，并且这里没有拦截器之类的进行鉴权，直接可以前台访问，跟入寻找YktJrhx这个类，并且我们查看方法getRoomList方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW3w7PmXR806X85ZYd7QW8ZKicUJBoibjC1fVHmDbx4wo5936Y4CF25ibykjASo6NCto98arwe3573GQ/640?wx_fmt=png&from=appmsg "")  
  
    这里进行传递了非常多的参数，其中有一个关键参数为SIGN参数，这里继续往下走，查看这个参数干了什么。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW3w7PmXR806X85ZYd7QW8ZuqQa19Wh7TlzWhHv8GgQu9Wjrafl5RURJyDoE90OeEs3jibvUWFXqAg/640?wx_fmt=png&from=appmsg "")  
  
    这里对参数都put进去并且调用了createSign方法，然后进行加密并且与传递的sign参数进行比对，成功之后继续往下走，否则提示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW3w7PmXR806X85ZYd7QW8Z4lIfU6ibuIia740sZnmkY6NYgub6kDXGaN7ia6aC0qLrGZpPS14oMws2Q/640?wx_fmt=png&from=appmsg "")  
  
    成功的话json返回当中status提示1，sign校验不成功提示2.  
  
    这里先进行查看createsign的逻辑，并且把对应传递的key值也获取到。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW3w7PmXR806X85ZYd7QW8Zooz2OXa12DmAqo6YNTicy99UEU09xAlbIt07peJs48DiaImTvB8ErokQ/640?wx_fmt=png&from=appmsg "")  
  
     
 获取到了加密方式之后，我们可以正常往下走，我们继续查看代码逻辑。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW3w7PmXR806X85ZYd7QW8ZOAN8wPwZYAvFdH9cichzwVdw2Rs76MAibfPtgbuhZIdUZQRddOQKfAKg/640?wx_fmt=png&from=appmsg "")  
  
    在这里直接拼接获取到了对应的SQL语句，并且进行了执行导致存在了前台SQL注入漏洞，但是这里sign一定要校验过去，程序才可以过if语句到达这个注入点。  
  
三、Sign脚本编写+前台注入  
  
      
这里根据系统中的createSign函数编写对应的sign生成脚本，然后本地测试。  
  
正常进行注入延迟5s测试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW3w7PmXR806X85ZYd7QW8ZhUWDksg4eQhJicNpWML5lDRaIVbzZmQIS0ibia1quaib01JEElA1c7uFpA/640?wx_fmt=png&from=appmsg "")  
  
常规操作下提示2，我们sign没有通过，这里生成对应延迟5s的sign脚本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW3w7PmXR806X85ZYd7QW8ZX4Ghd7EwTicq29eZT1RQiawiarVQew29ljiajnJL0ma6w3Y75oNJs5ictyA/640?wx_fmt=png&from=appmsg "")  
  
把我们的sign添加上去。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhW3w7PmXR806X85ZYd7QW8ZVeUqvjpTbZaAQTOibzmyIUlVPAPUSkagABrokm4UicfathwxgHD4XyWQ/640?wx_fmt=png&from=appmsg "")  
  
成功延迟，出货！  
  
四、完结  
  
     代码审计第四期，富含PHP、JAVA、NET代码审计，顺带APP、小程序、WEB当中参数逆向以及JAVA工具二开与SRC案例讲解，其中多多0day讲解，实战案例分析，不拿着靶场去做，想学习速速报名了。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhUicibrBmrZ2iazoDJic2RyDklw4547e6aNia1OEMntI6wGqRdvr87XVgUdiaiczwW67bRO3iayvd7H7bZoeQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU0MTc2NTExNg==&mid=2247492350&idx=1&sn=5586252e5859dfb692618f047c00faa2

#  攻防下帮助学员快速审计NET前台rce漏洞  
 实战安全研究   2025-06-19 02:00  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
一、前言  
  
学员找到我，让我审计一套源码，于是这里开始进行审计。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qAjrnRpiagwfrc22ZiaxYtu5jXmh6C7rZS2k2vIxC32A2uVhCCM0icJpAA/640?wx_fmt=png&from=appmsg "")  
#### 二、框架查看  
#### 下班之后打开进行查看，跟学员对应的靶标。这里确定了UserLogin方法，于是载入反编译工具快速审计（这里其实已经开出来时MVC架构了，因为登录没有走ASPX文件）定位到了Controller就好说了。  
####   
#### 三、鉴权分析  
  
一般的NET MVC架构会进行使用注解来进行鉴权，但是这个文件不是，不过我们肯定知道，登录的那个方法绝对是前台可以访问到的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qaPCIhhVic0Sl85vggEicQaib1XvicicDKh5yPEO5SZrXnbWRQicCor0X2YQQ/640?wx_fmt=png&from=appmsg "")  
  
登录的方法没有非鉴权的那个注解，于是回头查看类的继承父类，然后发现，通过父类来进行查看是否存在鉴权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qWAAo8S0Mic9q70I3dkrvAHvVMO2f1nArTcKJOqPO7ylm6ibRic1yibf9AA/640?wx_fmt=png&from=appmsg "")  
  
像这个类当中继承了PermissionController类，我们跟入这个类查看是否存在鉴权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qribictibicF97FTszbibDZicJiaCaubSs70KpUicuWyOHVjv8SQRoBibPPhwEtA/640?wx_fmt=png&from=appmsg "")  
  
像是鉴权方法，但是没找到Oninit方法，我们进行实践，这里就不贴图了，直接进行跳转回去了登录页面。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qicibcmiaLUx5CPSIhozEytHe9cHX2JEkMwRfCvdapPyBbhJ4MoYAvicFiaw/640?wx_fmt=png&from=appmsg "")  
  
  
我们知道了，只要一个类继承了BaseController就是前台可以进行访问的。  
####   
#### 四、前台文件上传  
  
这里我们根据Controller的命名也可以才出来哪里没有鉴权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qkVe28tH6vKzXXVtUnJteKERYR94qOmNiadXMSuZlQDCPPcE84cK1rCA/640?wx_fmt=png&from=appmsg "")  
  
在WebApi当中没有鉴权，进行审计。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qvHVMd03Fo0fRRSKq4l9LtIqW46pCOZa1XJTS0ZY0fbfujzFxCmjHpw/640?wx_fmt=png&from=appmsg "")  
  
存在一个方法为uploadimg的方法，这里进行尝试上传但是失败了，找了很多资料之后了解了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62q0J5iaSZH7p8KEmaicmzKQMFicZwibNlJ6knAjNt9FoDqjdp7pl8lxY6Fiag/640?wx_fmt=png&from=appmsg "")  
  
这一行要对文件进行压缩变为缩略图，我们直接上传aspx肯定不行，于是我们上传一个图片，在图片后面更改为ASPX的马子。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62quBTA0JdQtKrf7NqbrjVgdVjyVc968oAb74Be2ZHSFibdp5rwsv2zuXQ/640?wx_fmt=png&from=appmsg "")  
  
成功上传，但是还是不行，这里发现ASPX不可以像PHP那样子在文件后面加，上面太多的东西了，导致aspx报错，这里的解决办法是，截屏了一个一点点大小的图片进行上传，后面加马子代码，把报错降低到最低，本来想着注释图片的二进制数据，但是那个方法检测开头所以没行得通。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qNZJ3d8c21hicea2icUA59onIwFzCPPAjAQOvHTaDDce7h34icicosShwhw/640?wx_fmt=png&from=appmsg "")  
####   
#### 五、前台RCE  
  
最终  
通过上述方法成功RCE  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qJa7Jc6Ekfib1fuL7ulwAJk1vhBs2Bh8rwuRC9dJKoBBYKibhDac291ow/640?wx_fmt=png&from=appmsg "")  
  
这里上传的是在github当中找到的一个马子。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhWchHGmp8CpTa9M8kI0K62qpRw9vSqFqnK1KeYfIVHIoCdv54zDF5fmGicN2JoQHau5QsDzEHfQquw/640?wx_fmt=png&from=appmsg "")  
  
  
最后也是倾囊相授。  
  
  
六、完结  
  
     代码审计第四期，富含PHP、JAVA、NET代码审计，顺带APP、小程序、WEB当中参数逆向以及JAVA工具二开与SRC案例讲解，其中多多0day讲解，实战案例分析，不拿着靶场去做，想学习速速报名了。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhUicibrBmrZ2iazoDJic2RyDklw4547e6aNia1OEMntI6wGqRdvr87XVgUdiaiczwW67bRO3iayvd7H7bZoeQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
  

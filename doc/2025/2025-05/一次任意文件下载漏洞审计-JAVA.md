#  一次任意文件下载漏洞审计-JAVA   
 sec0nd安全   2025-05-18 15:15  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
一、前言  
  
    突然电脑里面多了一套源码，然后开始审了审，是以jar包启动的，虽然最终拿到了鉴权绕过以及任意文件上传，但是不解析JSP所以没什么用处，这里挑其中的任意文件下载漏洞讲一讲。  
  
二、审计流程  
  
    这里其实一  
眼就可以定位到  
Controller层。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVly8qplaE54SHodo51qict8BiaPjIeebZfjaqF2ewr5xyhZpALaNVQf5LRwtvh4eLDwicTHBQOL0zzA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVly8qplaE54SHodo51qict8SFyRGMYCHBkv2px7yF0eeydCGhDlT0TTZ2JuNUwzQdrM1JQNiciatJwQ/640?wx_fmt=png&from=appmsg "")  
  
在类当中还是比较明显的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVly8qplaE54SHodo51qict8ysIl2MO2pOEjVzCUVPrdTuBicHJ1muxWPOlLvHGxXb0kzmyQpw6iaOIg/640?wx_fmt=png&from=appmsg "")  
  
这里传递进去了参数path并且给到了downloadFileStand方法，跟入方法进行查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVly8qplaE54SHodo51qict89Cicd029KOMjEzbYqHeLKN3GEoO0yUfAEGBgh9eSUdCJHKILzX4Tl9w/640?wx_fmt=png&from=appmsg "")  
  
可以看到这个if判断也没有起到实质的作用，最终还是通过Header头设置进行把文件下载出来了。  
  
三、漏洞验证  
  
    这个功能本来是后台才可以访问的，但是刚好在鉴权当中存在一些逻辑缺陷导致可以进行绕过，不过由于特殊性就不做过多的解释了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVly8qplaE54SHodo51qict8XEkwWkd9FwfPKWpTGf52HupDgWJtTvnZ3X115jEw9wFFZmPdS20gCg/640?wx_fmt=png&from=appmsg "")  
  
四、完结  
  
     代码审计第四期，富含PHP、JAVA、NET代码审计，顺带APP、小程序、WEB当中参数逆向以及JAVA工具二开与SRC案例讲解，其中多多0day讲解，实战案例分析，不拿着靶场去做，想学习速速报名了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhUicibrBmrZ2iazoDJic2RyDklw4547e6aNia1OEMntI6wGqRdvr87XVgUdiaiczwW67bRO3iayvd7H7bZoeQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=13&wx_lazy=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
  
  

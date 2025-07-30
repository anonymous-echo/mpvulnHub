#  Guns后台任意文件上传漏洞分析   
 船山信安   2024-12-30 01:12  
  
下载地址：  
  
主项目：  
https://gitee.com/stylefeng/guns  
  
核心包：  
https://gitee.com/stylefeng/roses  
## 分析认证逻辑  
  
找个正常的接口访问，发现没有自定义filter，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9OK98B5Erjymj8Sibibx1Sjic77adxLTHau1oicextdwvU1ArrKu89hbfSg/640?wx_fmt=png&from=appmsg "")  
  
  
我们大概看一下spring的filter执行流程是咋样的，  
  
可以看到这里有6个filter，但是从上面的堆栈图可以看出，  
  
有些filter执行的是他父类的doFilterInternal方法、父类的doFilter方法，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9ibDVmsayeaqMXj58NlD5nUWEYxv09nrJhq7lJqpp2QohGpECqhibiba8Q/640?wx_fmt=png&from=appmsg "")  
  
本来以为是实现了WebSecurityConfigurerAdapter接口，结果并没有，  
  
发现此系统是实现了HandlerInterceptor接口进行权限认证的，  
  
分析TokenAndPermissionInterceptor拦截器，  
  
这里使用getRequestURI()后，就开始匹配路由是否被拦截，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9haZiaFny74L5cvVmgqqAaRJGNYkVGT9mmDCHLYQjh551aBZlvUtE4kQ/640?wx_fmt=png&from=appmsg "")  
  
这里是不拦截的路由，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9xp7YAJvvxUtB7eGF3rg1PLycbmp0yRV1wYwTIADhdibQEIEzndlw8jg/640?wx_fmt=png&from=appmsg "")  
  
之后判断如果存在token，就会验证token是否有效，无效则报错，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9JHgmW94MdZ49skaYWo50SyC9Axevwr23WCj5bDiakAlO81zFJibq20gw/640?wx_fmt=png&from=appmsg "")  
  
如果不存在token，就在resourceServiceApi中查找路由资源，  
  
并判断访问的路由是否需要权限验证，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9vicbiaAIiaJxGnL0xEQPibPGupaSPPrLq3HYxFnC8dzibDh8PVsI4Kicwgbg/640?wx_fmt=png&from=appmsg "")  
  
权限绕过思路：  
  
白名单路由可以用../绕过，不过最后还是会被spring拦住，（这里可以用%2e%2e\绕过，不过存在tomcat环境，直接报错）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9TULvfNribwmia3BJcTa750JW5NOwmeybaLecRcrDeic9HtJUhibnUgKy8Q/640?wx_fmt=png&from=appmsg "")  
  
jwt不是硬编码在本地的，秘钥没有通用性，伪造token不行，  
  
resourceServiceApi会调用到以下函数，  
  
resourcecache存在一些接口资源，可以访问一些未授权的接口，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9GDqDxN2FricxU76VcD9qTrC1qVmMF6ibGbLw8VdglOVIklAjTvIyTtfw/640?wx_fmt=png&from=appmsg "")  
  
在resourcecache中的接口，利用@GetResource注释设置了requiredLogin = false，就不需要认证，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9HWAPqSWI3IMsZ5j70cHJ6vTGUIDERtibpmBNJQ17HibVMDkGcO1YpAbA/640?wx_fmt=png&from=appmsg "")  
  
分析这些未授权接口后，没有一个接口有洞，就很尴尬，，，  
## 任意文件上传  
  
这里可以任意文件上传，不管更改fileBucket或者filename，总会用fieldid拼接文件路径，  
  
因此可以控制文件名，那么文件夹就是fieldid，  
  
如果控制文件夹，那么文件名就是fieldid.后缀，  
  
如以下数据包，任意文件上传，不过文件名不可控，  
```
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9pTUpm1cLn8icHuKIJFmUICyXhCvnlFF1OeEUJ2TnibLjc6RChS56ibNPw/640?wx_fmt=png&from=appmsg "")  
  
可以用在钓鱼，如果项目在c盘，可以放到启动项中，  
  
这里可以看到是在哪个盘，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOBjxpPIsXeepSF1TphHica9RBlCywgXTxauH9NQQL7sAeOVSaEgicWRc2rkH4IRpWwGLFIxPoicVrvQ/640?wx_fmt=png&from=appmsg "")  
  
来源：https://xz.aliyun.com/  感谢【  
tj  
】  
  
  

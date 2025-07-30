#  某云盘系统 API 端点无限制上传漏洞解析   
 黑白之道   2025-03-29 10:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
### background  
  
在某次赚钱的时候,发现出现了这个系统的低版本 搜索了很久相关只找到了一个  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yl8ib41uA6HcFic5SicKJnMt46x7vEics40pDOHTSeQ6y9cD8y2HsWfnqTA/640?wx_fmt=png&from=appmsg "")  
简短的一句话 但没有其他漏洞细节 于是本地搭建挖一下  
### 0x01 漏洞限制条件  
  
![image-20250306174220208.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17y5UAoxFg8heZWs6Y8yYQ2350kvYIiciaichtCyYoYJRjkTTb0SduFGiaic7w/640?wx_fmt=png&from=appmsg "")  
  
首先是需要一个账号来调用后台的插件  
  
但是本套系统默认两个账号  
  
guest:guest demo:demo  
  
还有一个就是要知道web的路径 当然这个后面说  
### 0x02 漏洞分析  
  
定位到函数 发现有一个in['file']的参数  
  
![image-20250306174557708.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yHhcIml0UXZpk0ibICqDoTz5Oia3287VTDTV1XXZsDWtDWibTQF4eGTic1g/640?wx_fmt=png&from=appmsg "")  
  
跟进in 在controller里面可以看到这个参数  
  
![image-20250306175026755.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17ydzDDnoG37UmsgXmdSIyuDDra84QVdgHby9tfEwNaMd1QPJjabjYJSA/640?wx_fmt=png&from=appmsg "")  
  
![image-20250306182032074.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yfMOtnpnKib4MunXIqW8HRfsIbMibV7fgVfNYlyLaUOHP7ibtKXkPA0V6w/640?wx_fmt=png&from=appmsg "")  
还是全局变量 很容易判断他可以直接传参数  
  
跟进这个可以发现有一个get_path_ext后缀  
  
![image-20250306182255890.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yiaibyXgQ8e2ic8Lpjb3ljosdRwSuv4M7vNmWsvDG0WZIHMkkFMib2YaA5A/640?wx_fmt=png&from=appmsg "")  
  
可以发现只限制了数量和一些不可见字符 并没过滤php  
  
继续跟进unzip_filter_ext 可以发现他过滤了 .user.ini .htaccess  
  
![image-20250306182624887.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yZgWQGIJDAKr7Z6gLYFic0QcBILW3o2j0W3NlNn5duVxMLOMqoEEuqug/640?wx_fmt=png&from=appmsg "")  
  
但是有一个checkExt检查后缀 但是逻辑有点问题  
  
在这里有一个不允许的名单  
  
还会不断的merge  
  
![image-20250306185117546.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yUSDibz7Q9ZC6ick4ViaPsFoCnpayoZ4jKucQgc9icvpB5dG6oo4TwoBjFw/640?wx_fmt=png&from=appmsg "")  
  
在这里进行判断  
  
![image-20250306185314860.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yzsoOxbWml36DibFiayHTzgJBiad2MhX4pLL9IKPaa2UIZJeibR9RS6abYQ/640?wx_fmt=png&from=appmsg "")  
逻辑错误点在这里 我们这里的$file是php 而后面的则是.php  
  
因为stristr的意思是在前面的字符串查找后面的 而在php字符串里并不包含.php  
  
所以在这里我们可直接传入php  
  
![image-20250306190635350.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yjibkvazFWUeyVjUAY2cwx1e7aa6KB6Bn5Tcjx6g4RMsHicJFhQUpRCVg/640?wx_fmt=png&from=appmsg "")  
  
打印了下 $infoData发现为NULL 那后面$linkfile就是单纯的网页地址  
  
而且他会对一个url发起请求并保存文件  
  
我们可知$cachefile 的后缀是php 其实就可以直接写文件了  
  
在目录下放一个/1.php的马  
  
![image-20250306194818702.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yF7Ty4WnvOlgiaVdkgkGak8zRQCO4aTHUpwNeykQwcEZdILdB2es7iclg/640?wx_fmt=png&from=appmsg "")  
  
直接进行访问  
  
![image-20250306191647101.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yxJfcxHauvd04Es2WpWgfiaecSQDCClZoXllMnFMTtF6oVicP845M9XzQ/640?wx_fmt=png&from=appmsg "")  
  
发现在响应头里会有php文件名 但实际上  
  
![image-20250306191716494.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yLOr3rrZHgSWvxxlHonSVrMHrDicw3UNAyHP5AhvZXeQNAylibk1y64eQ/640?wx_fmt=png&from=appmsg "")  
  
在这里也写了完整的生成语句  
  
![image-20250306191943227.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yWKgwXtfdAibCHxMqzvhFEg1icPN3FZ8O10ibsg9gkAzdnzCGbH2CnxBHw/640?wx_fmt=png&from=appmsg "")  
  
但是我们发现在生成文件的时候还是有一个目录的  
  
![image-20250306192008663.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yczyiaSnQpDxN83CIyJ0ggI2BSSQSnicwOGuW7gpRfrtw84Pdg7BUqJUQ/640?wx_fmt=png&from=appmsg "")  
  
回到刚才代码  
  
我们查看cacheFile类  
  
![image-20250306192121007.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yzOSXKClq7Q7ibcdzM8s5wsgzpgm6YayfpwQhGNeicWRyb5ZaSic2QmcIQ/640?wx_fmt=png&from=appmsg "")  
  
在这里有一个hash_path的生成  
  
可以选择下断点 或者直接var_dump下变量  
  
发现大致目录如下  
  
![image-20250306192340806.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yADc00e3Vibx7PsHia1RlZ8eIMIHg1XH7o3pndz5Jo4CXicRNmmN49dIqg/640?wx_fmt=png&from=appmsg "")  
  
其实可以推断出来 /var/www/html/data/User/guest/home/ 为一般漏洞利用的hash_path  
  
而且你会发现虽然说他在前面设置了一个随机生成的系统密码  
  
但实在底下只是进行了md5的编码就把$path写进来了 所以  
  
![image-20250306194548339.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yYwZYziarcagIvtz6hrVSwbT3EkiaVuWOOHMNVpq0EFHCUSic5cDSC4Tzw/640?wx_fmt=png&from=appmsg "")  
![image-20250306194412913.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yGjl6XHWCvNUHJrF9dh1iahndXebEI5ayDcaWgxODub3d8pk5fWzvWvQ/640?wx_fmt=png&from=appmsg "")  
  
只要文件不变 md5值是不变的  
  
![image-20250306194654634.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17ysehWHEib9Eic7sfMtaolNS0rWllqOyL2o3dRmMlMEUqNSueSVIjrpqfw/640?wx_fmt=png&from=appmsg "")  
  
构造poc即可写木马  
### 0x03修复方案  
  
官方的修复中  
  
![image-20250306194957952.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yKYJ4AcPxx6iaRLFichYG2tq9KKwnve8pN3YaNicZmaSjMRzib1b6Yk6m2w/640?wx_fmt=png&from=appmsg "")  
  
在这里把文件返回头给注释掉了 但是我们上文提了自己生成也可以  
  
可以看到在path生成上完善了 拼接了$pre 没办法再进行路径的查找  
  
![image-20250306195030619.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLibctHBxvacIJEI44ibyIS17yhYDDOdkFiaaNw6xS9GniaMUoWae5zibJtzT0uFVlDKohxkmIvRjYichLYw/640?wx_fmt=png&from=appmsg "")  
  
> **文章来源：奇安信攻防社区**  
> **链接：https://forum.butian.net/article/673**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  

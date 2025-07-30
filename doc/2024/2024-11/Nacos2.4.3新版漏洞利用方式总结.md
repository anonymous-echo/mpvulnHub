#  Nacos2.4.3新版漏洞利用方式总结   
 船山信安   2024-11-28 16:37  
  
## ilter分析寻找未授权接口  
  
HttpRequestContextFilter 获取请求头信息，  
AuthFilter 获取uri，token，权限控制  
ParamCheckerFilter 处理参数，过滤恶意字符  
  
AuthFilter，  
请求头如果存在jwt秘钥，那么就进入下个filter，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXEm1M6MozQiaPuRINzh1SUrlBpYGxZVuIUricPeuUHqHq58T6LDmDIZdA/640?wx_fmt=png&from=appmsg "")  
  
如果配置了nacos.core.auth.enable.userAgentAuthWhite=true，那么利用伪造userAgent就进入下个filter，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXEo4hf2IM5MQUY0hIXMMuXwbvN4rBIC8hibsJMtArZq1rDwVjQssDXEw/640?wx_fmt=png&from=appmsg "")  
  
然后获取uri从map中匹配是否存在相应路径，如果map中没有匹配到路径，那么就进行进入下个filter，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoX7qzvHIQNhFFxdkJicTtNibSd1whIibjvXHM23E5DicQ3mCR7NXOiagQKbXg/640?wx_fmt=png&from=appmsg "")  
  
如果在map中匹配到路径，就会根据Secured注解去判断是否需要获取token去验证身份，  
如果没有Secured注解，就直接进入下一个filter，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXyYTIcEBFKWzL4lFRczaibniaDcHnJtXfiaoRjvk15Q6NkqbmCm9Qhv4tQ/640?wx_fmt=png&from=appmsg "")  
  
如果Secured注解需要验证，就会获取ip和accessToken，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXia33T9gRLKrISE3DSicQLsOh3wURgD0DZnx9nEdFHLhDWJh8jSlBPiaqw/640?wx_fmt=png&from=appmsg "")  
  
然后用jwt秘钥解密，解密失败则报错退出，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXw0sOTKKYwIfuWNCLy9ogyU5NGH8qjHNDCZACs3jGJTskJOIvnOkJfg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXwliaVliciahaWLVYX3Loegf4rJCuOC7dLKuB4fVv5IxwgNnsB1Mh11A8A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXHYMiaYxefNT8iaJwW5b4zjibZaGSLiaGca2ia6aKA0cc9RqyFIDBx19dFSQ/640?wx_fmt=png&from=appmsg "")  
  
解密正确则进入下一个filter，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXUpD0O53dcarDD5HnNSHH5EZHWuza1OHXSzJcH7snQQDcOfGqv4v3pQ/640?wx_fmt=png&from=appmsg "")  
  
ParamCheckerFilter，  
会通过Extractor注解去得到需要被检测的参数，  
然后使用checkParamInfoList去检测参数是否符合要求，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXSlghsecJOzsqfjgiagFu54jbYBrPuOGqvSLtLfnaicGKOy8ibhSqZH2Zg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXPJl2Uz6icAnu9TmJQ8oungicmCibZ8fFUyhgabr9ZnOQZe3sKJQPsfMtA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXxBqib9ibQkh2q7qc9O2IplkHdcEKRbME6rITMglAs1MCNutjRBH9eYaA/640?wx_fmt=png&from=appmsg "")  
  
如  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXsU9IIGsFbFiapA1V1qZQVMARRxvjkTWx4uqzibllLyBI5WibAFH5o7Exg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXcmyC81h1QJialUYSRTXdCiazmcQ1L22WluT1FH855VXCDtPn45K41icqg/640?wx_fmt=png&from=appmsg "")  
  
或者  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXp5qBx6yrVyWNCg6n7G28CbHyBQRrB8OjbSMwCTB1jokWrLjbJ8IykA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXaIJggtdjlaDhHNJwjSrVdbBNPa1PgfDbFMmBofvibzMaFm5wOtAeElA/640?wx_fmt=png&from=appmsg "")  
  
那么需要满足以下三个条件，就能找到未授权sql注入：  
1.查找没有被Secured注解的路由，  
2.Extractor注解时，是否存在一些参数没有被获取检测，  
3.参数执行相应的sql语句，就可能存在sql注入，  
但是后面发现都是预编译处理sql的，因此未授权sql注入这条路就利用不了了，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXGt3CVxn27SEOQ6GSmt9YskGalEVOloVTicD225EMUBwjzNxqeBx5gQQ/640?wx_fmt=png&from=appmsg "")  
  
这里刚好存在接口/nacos/v1/ns/instance/statuses?key=DEFAULT_GROUP@@1'，  
并且Extractor注解也并没有获取key，因此key就绕过了检测，不过key带入进去后，并没有执行相应的sql语句，因此此接口也利用不了，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXCiaIC97IqTyzDrkgKByMOcIa3cv8lbPYX2qKFcFiaKKTHLKTeuzicpr8A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoX6B5IctfkhBJm28zeibIBEvkQbI7UXtOeCexbxfqYduE29NBibZsxgaTQ/640?wx_fmt=png&from=appmsg "")  
  
以下是一些存在信息的未授权接口，  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoX5M0wBmROxmvG2icnElxdweSlHHyXBibIxw7Y18dv6jdZ0A8iaJLLia5libg/640?wx_fmt=png&from=appmsg "")  
## CVE-2021-29442 可能被利用  
  
设置了nacos.config.derby.ops.enabled=true，  
那么就可以调用derby的sql语句，不过只能使用select开头的语句，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXVq1oxvg0afXxEZZ20T4MbUaXjd6GVR6FWxhoLAQWQyv58SD2WN6FMQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXvdeCIQUMa0YPyf2p6UZtxJ4Kv3QWD0C9RNvzDMw8c9uAUu6yyUnIsQ/640?wx_fmt=png&from=appmsg "")  
  
利用此接口进行条件竞争文件上传，然后使用select加载恶意包达到命令执行，  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMPrkjdAmNlMNNSGWkXcqoXmAiaJHjGlaXTNRE8Gu9LMkR9Uup2wag4Sl4icjiaR7nYHBicWccpiaic6RLQ/640?wx_fmt=png&from=appmsg "")  
  
## 总结新版漏洞利用方式  
  
1.新版本依然是默认没有开启鉴权，需要用户开启，不开启则存在未授权  
2.如果设置了nacos.core.auth.enable.userAgentAuthWhite=true，可以有useragent绕过权限认证  
3.可以利用CVE-2021-29442后台getshell，条件是使用derby数据库，设置了nacos.config.derby.ops.enabled=true  
4.存在一些无关紧要的未授权接口  
  
  
来源：【https://xz.aliyun.com/t/16328?time__1311=GuD%3D0KAKYK7Ie05DKB4CTqYu71TYLAPx】，感谢【tj]  
  

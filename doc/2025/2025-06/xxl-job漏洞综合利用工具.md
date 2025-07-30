#  xxl-job漏洞综合利用工具  
 黑白之道   2025-06-09 01:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
## 工具介绍  
  
xxl-job漏洞综合利用工具  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUCCJg3pR9eIphgknhe0o6z2chDjOEkUlCS7mva8JarBzVrvrUxmvkGeUndDBBYZfOKnO6vJw2fr7Q/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
## 检测漏洞  
  
1、默认口令  
  
2、api接口未授权Hessian反序列化（只检测是否存在接口，是否存在漏洞需要打内存马验证）  
  
3、Executor未授权命令执行  
  
4、默认accessToken身份绕过  
## 关于内存马  
  
1、内存马使用了xslt，为了提高可用性提供了冰蝎Filter和Vagent两种内存马  
  
2、如需自定义可替换resources下的ser文件，其中filter.ser为冰蝎filter内存马、agent.ser为冰蝎agent内存马、xslt.ser会落地为/tmp/2.xslt,  
  
3、内容为使用exec执行/tmp/agent.jar、exp.ser则是加载/tmp/2.xslt  
  
4、vagent内存马连接配置:冰蝎:http://ip:port/xxl-job-admin/api, 其他类型内存马类似， 将api改为luckydayc、luckydayjs等即可  
  
5、Behinder内存马连接配置:   
  
密码: Sgjmccrzo  
  
请求路径: /api  
  
请求头: Referer: Lepxcnzd  
  
脚本类型: JSP  
  
6、由于agent发送文件较大，所以可能导致包发不过去，建议多试几次或者将超时时间延长  
  
7、由于Hessian反序列化基本上都是直接发二进制包，所以理论上讲其他的Hessian反序列化漏洞也可以打  
## 工具下载  
  
https://www.libaisec.com/2587.html  
  
  
> **文章来源：李白你好**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  

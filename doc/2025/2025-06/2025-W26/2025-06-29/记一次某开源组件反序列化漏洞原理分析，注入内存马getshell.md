> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI3NDI0NjMxMQ==&mid=2247483874&idx=1&sn=8d3f7ea725620fc6df9225b77fcb9d28

#  记一次某开源组件反序列化漏洞原理分析，注入内存马getshell  
原创 不知名菜鸟%%  吾入安全圈的二手程序猿   2025-06-29 00:52  
  
源码下载好依赖，运行组件，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08ZsXeiaQuQfwVhG39DxfQR4ibhLgvv7zpS6TjV3mbdBS7hF4cApEBBdGqtQ/640?wx_fmt=png&from=appmsg "")  
  
寻找路由api,全局搜索，可以看到一个未授权访问的api请求端点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08ZsnzD8qEgotCJWYDfJj1ORgDS1M0SuqdtfVJyJBfm5mMAJ25m6pyS2ug/640?wx_fmt=png&from=appmsg "")  
  
AdminBiz接口的MAPPING方法被映射到JobApiController使用，JobApiController方法类实现于接口InitializingBean，可以看到是一个序列化接口；同时可以看到权限是未授权false,传入的请求参数是request  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08Zssia2QMjiceQ5vuF4IUYrR3FkA4yCE1JNictFtyyDZnNScJIhBicx5akk4g/640?wx_fmt=png&from=appmsg "")  
  
跟进invokeAdminService方法，来到com/xxl/job/admin/core/schedule/XxlJobDynamicScheduler.java#  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08ZsUW9uIZUHKDjHVmFckibIlQiaI49CQmhYcP1BL3PJd4a1eq8x3XseGMKw/640?wx_fmt=png&from=appmsg "")  
  
进一步跟进handle，jettyServerHandler.handle是Web应用程序中的请求转发或代理方法，将请求委托给Jetty服务器处理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08Zs18SOHJSs19eibJsFMKez1gqcibyd6DXYV8Wl6as7R5gPsibafTnIQdBwA/640?wx_fmt=png&from=appmsg "")  
  
来到com\xxl\rpc\remoting\net\impl\jetty\server\JettyServerHandler.class，这里会将参数输入的对象交给parseRequest()处理；  
  
parseRequest()将HTTP请求解析为RPC请求对象，如果解析成功，通过xxlRpcProviderFactory调用服务；将响应序列化为字节数组写回客户端  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08ZsP7MqB7SzW6IcKibctp1pIWnJ0CJ1SdyPL2iahCm93vLIhUBLn0qne1hQ/640?wx_fmt=png&from=appmsg "")  
  
继续跟进parseRequest方法，主要功能代码如下：  
  

```
 byte[] requestBytes = readBytes(request);#调用readBytes方法从HttpServletRequest对象中读取字节数据，序列化的RPC请求数据


 if (requestBytes != null && requestBytes.length != 0) { #检查字节数组是否非空且长度不为0
     XxlRpcRequest rpcXxlRpcRequest = (XxlRpcRequest)this.xxlRpcProviderFactory.getSerializer().deserialize(requestBytes, XxlRpcRequest.class); #通过序列化器将字节数组反序列化为XxlRpcRequest对象；xxlRpcProviderFactory.getSerializer()获取配置的序列化工具；deserialize方法执行具体的反序列化操作
     return rpcXxlRpcRequest; #返回反序列化后的RPC请求对象
 }
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08Zs3vRjDksTlc3NmLRmibkzSYzIpW7KZibPiczDaRAx9eGiauPPNUmGTdicpjw/640?wx_fmt=png&from=appmsg "")  
  
在反序列方法下断点并开启debug调试，使用burpsuite发送一个请求，可以看到idea成功拦截数据包ludao99，字节长度7  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08ZslRiaVqWTJFzdl1qze4VuY8gDZyFO7FQ6vyAazfyWz9NAe3WV6lIaPDg/640?wx_fmt=png&from=appmsg "")  
  
使用某大佬现成代码生成反弹计算器的反序列化数据文件hessian.ser  
  
验证：使用curl复现，弹出计算器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08ZsIBBibVjEJHacAREncJGeiaZvkiadj50OKJ0wSz4ErjwMMAyCbPGczS6Qg/640?wx_fmt=png&from=appmsg "")  
  
也可以使用现成的工具注入内存马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08Zsmc3y1NWRSuG3XBCKx8JQOpPV8OLvDGGx90b2QTtOTOXj8sWLsf1HaQ/640?wx_fmt=png&from=appmsg "")  
  
冰蝎连接，连接成功，那么就可以愉快的内网渗透了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gHxQN4KeDGrIPeBqIFDczAwgpCeR08ZsYFT5bpbaYrqescHloiam4fKSS2icIWvsW5MnVKfibkMFN2LuZU87Fhp0Q/640?wx_fmt=png&from=appmsg "")  
  
工具链接：  
https://github.com/rebeyond/Behinder  
  

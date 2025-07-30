#  记一次利用wx绑定漏洞的渗透过程   
原创 韵  湘安无事   2024-01-13 08:00  
  
**声明：**  
**由于传播、利用本公众号湘安无事所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。如有侵权烦请告知，我们会立即删除并致歉。谢谢！**  
  
  
某个站点:   
  
https://xxx.xxx.exu.cn  
  
访问链接出现的是一个登入界面，可以微信扫一扫登入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu9n13uS5xclXndyOZMBJnrTM1mqDHbMYEPzY1uopxoL3Xr6UArEvvAdAGMk3EIMrTQbpUel93sGw/640?wx_fmt=png&from=appmsg "")  
  
这里前台是可以注册账户的，注册一个用户进入后台，发现左下角的微信绑定功能  
  
点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu9n13uS5xclXndyOZMBJnr8tqn6nYibOrWSPCXQzy3uYSQg6U0ycoDyRxZC4d4otGlUJKkmLVWR9Q/640?wx_fmt=png&from=appmsg "")  
  
打开手机微信进行扫码，当时就在想我这时候用手机扫码绑定这个账户的话扫码结果应该是一个未授权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu9n13uS5xclXndyOZMBJnrv1jlYwC6K1PjuI6zCC6es6twfV4TIqDJVGfMWlphXm9sQfFkCPo9Xw/640?wx_fmt=png&from=appmsg "")  
  
微信有个功能转发，我把该链接转发出来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu9n13uS5xclXndyOZMBJnrzZNXH8ROLZP0LUibZ7p7gA2ia93JTP6Ch7yKUCY7SQXZTrwFGjlSlF3w/640?wx_fmt=png&from=appmsg "")  
  
刷新页面抓个包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu9n13uS5xclXndyOZMBJnrAJEfTuT71dEp9WcsLAGZYWeITum30UM0Mib80und6yfLgAGqMkWhglA/640?wx_fmt=png&from=appmsg "")  
  
这里我就发现了get请求切参数id没有被数字签名，越权是肯定了修改一下id的值然后放包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu9n13uS5xclXndyOZMBJnrVOho5Yr1EVpYCUbYRuiatuTcz0OBGIB5LJbHE72iceia6zvpmJucBfjEA/640?wx_fmt=png&from=appmsg "")  
  
这里也是成功越权到了别人账户的绑定链接，点一下确认绑定  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu9n13uS5xclXndyOZMBJnrQApWBPqxTJEnZRiboibtELewez8XmJngS4DqkUnwVm0CsDN8e7IV8zeQ/640?wx_fmt=png&from=appmsg "")  
  
绑定成功后我直接拿自己的微信去到浏览器扫码登入，手机上点确认登入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu9n13uS5xclXndyOZMBJnrQu5dBMtQFPZBomQpcHno0pScs9WibPxUn2uO5Cl2jc2C2udib2tySRgQ/640?wx_fmt=png&from=appmsg "")  
  
就直接登入后台了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYu9n13uS5xclXndyOZMBJnrzefNCtmRfNFfwcdc8Ej4kJbwszjsicZLRCiava8bGcdX6ArBGYl846rA/640?wx_fmt=png&from=appmsg "")  
  
进技术交流群可加下方wx  
  
  
****  
  
**知识星球的介绍**  
  
  
预览  
  
内容参看下方  
链接，咨询相关问题可私信上方wx  
```
https://docs.qq.com/doc/DUEVsVWhaUk51VUlr
```  
  
加入星球，您将获得以下永久服务  
```
1.FOFA高级会员(在线网站查询+下载、Key共享)
2.360Quake高级会员、Shodan高级会员、zoomeye高级会员、Hunter高级会(限额度)、00信安高级会员--账号共享
3.众多IT+网安课程资源
4.DK源码终身高级会员账号共享
5.高级会员在线靶场账号共享(Web安全+内网+漏洞复现等方面)
6.在线答疑解惑
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYu9n13uS5xclXndyOZMBJnribTw7zGiaq2KFfCyHUGs03WmSmOsz4P5x5ib8Le3sY9OFCzg0BlZ3XpFA/640?wx_fmt=jpeg&from=appmsg "")  
  
关注下发公众号，输入"  
xaws"即可领取安全类电子书籍一份  
  
  
  

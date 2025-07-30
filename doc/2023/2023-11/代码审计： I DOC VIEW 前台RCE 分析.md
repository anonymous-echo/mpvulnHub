#  代码审计： I DOC VIEW 前台RCE 分析   
Springki11  黑伞安全   2023-11-23 10:05  
  
I DOC VIEW是一个在线的文档查看器，其中的/html/2word  
接口因为处理不当，导致可以远程读取任意文件，通过这个接口导致服务器下载恶意的JSP进行解析，从而RCE。  
## 漏洞影响版本  
  
20231115  
之前版本  
## 源码分析  
  
先定位到问题接口： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fEXib3GzzJZ49skRfw6H35oiafu0lRpvwTicjiaaO28UiclVLOZV2OW1lwCA/640?wx_fmt=png&from=appmsg "")  
  
 接口里面就一个方法toWord  
，那么就来看看它做了什么： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fPaD38Wx0icmgPNXrt3CxnLVu6rV5wiawlFQnPegt8vf8ChS0X13v6Y0w/640?wx_fmt=png&from=appmsg "")  
  
 前面的内容不是特别紧要，这里有一个去爬取页面的方法，也是唯一使用了url  
参数的地方： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9f7gCiclJlqj1Ed4WPeGCSQBJH0crdz3NwL81qB8neK8Xx6icEt8fGDx8Q/640?wx_fmt=png&from=appmsg "")  
  
 这里使用了getPage  
方法来处理obj  
，而obj  
又是url  
来的URL  
对象，但是疑惑的时文件名只能是index.html  
所以去看一下这个getWebPage  
方法： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fGZ3fZx9AlFichog7LW6hEfIoyWXcXpib4OPt8F0aM4L681HcqSBhxP3A/640?wx_fmt=png&from=appmsg "")  
  
   
  
其实到上面这里还好，都是一些写文件的操作，并且写的也是index.html  
但是下面做的操作就是本此漏洞的关键了，软件本意应该是想做一个比较完善的爬虫，所以接下会调用GrabUtility.searchForNewFilesToGrab  
方法继续解析文件内容，这里的conn  
也就是刚才创建的链接： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fLokTcImuJgibkavqbdBJ6pdjpIxDqicqnxg7xeDWwjIZuwnGqoTChhxw/640?wx_fmt=png&from=appmsg "")  
  
 进入到GrabUtility.searchForNewFilesToGrab  
查看，发现其中的内容就是解析响应值，其中获取link[href]  
、script[src]  
、img[src]  
标签对应的内容然后存进GrabUtility  
的成员变量filesToGrab  
中： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9f3CZoBQFmib1RUVOyW4hbYYB6iamAGRvMgVRt0V8IUjA9zouqjvqyyFbw/640?wx_fmt=png&from=appmsg "")  
  
 ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9f0qBtwkr3nH82BTAq2C70dpickXvXH6tl5xdEmV4dVZ8VnU5te38N0jQ/640?wx_fmt=png&from=appmsg "")  
  
 然后就到了触发漏洞的操作了，这里读取了filesToGrab  
的size  
然后开始尝试挨个链接下载了，这里调用了GetWebPage  
重载方法，目录还是原来的目录，文件名时自动解析的文件名： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fcc9JyUiaicHx9RmljQ1032vCPP4JsFNqEQmXtT81AfcbpAiays0lECPDA/640?wx_fmt=png&from=appmsg "")  
  
 ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fTAcJNPt32GaGIg3Dlwn8icj5ZB3iaibxaDT1twX1aYc9PcVFHvWth5Iog/640?wx_fmt=png&from=appmsg "")  
  
 这就好办了，因为程序中只对后缀做了过滤，所以只要我们不是它黑名单的后缀然后再配合目录穿越  
就行了，然后黑名单是html  
、htm  
、php  
、asp  
、aspx  
和net  
，但是没有jsp  
，所以只需要写个jsp  
的🐎就可以了。这里需要注意的是，因为截取/  
后的内容作为文件名，所以不能使用/  
进行目录穿越，但是系统是windows  
上的，所以就可以使用\  
来代替。那么利用流程就是：首先启动恶意服务器，将服务器的index.html  
中放入一个href  
、img  
或者script  
定向到jsp  
马就行了！（这也印证了通告中的诱导  
下载危险文件）  
## 复现  
  
构造页面： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fmH9RibmFqhicc3R3jXoWhaDykXRvjA2iaSS12rWZfmFG91VNmpR4yVBrA/640?wx_fmt=png&from=appmsg "")  
  
 python  
启动简易http  
，访问！然后被杀（谢谢你火绒： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fd1iasdb6npL59fk8p7xRmFib71gwvx4tIQRW7IrpDmiczerrSHKs5ej7Q/640?wx_fmt=png&from=appmsg "")  
  
 关了火绒（因为服务貌似会有缓存，所以需要换个端口）： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fSwP1Gb8yus7BaOoScVntOZuoDIB7xLo3SbcFgLETBdkabCaNiaWrnOg/640?wx_fmt=png&from=appmsg "")  
  
 测试： ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9ficjibGcIthg1MNZ70iaZVoQ7QDYpibzFmToib3OttGjMOpERL8ib4zVEibTMg/640?wx_fmt=png&from=appmsg "")  
  
 当然最后不要忘记打开火绒哦。  
## 结语  
  
文件操作是十分敏感的操作，尤其是向服务器中下载文件，同时下载的文件最好也有固定的目录存放并防止目录穿越，开发者已经想到了下载文件的风险，但是却没有将对策做好，导致了本次漏洞。  
## 彩蛋  
  
天知道我试了多少次…… ![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqvAobU2HFibzhwGeZ6VmL9fGxEIlRv1bG6mzHaNs8qhWm8y2KXrOCt4mJsYkCWFuDfM5iaicTuYIEXA/640?wx_fmt=png&from=appmsg "")  
  
  
  

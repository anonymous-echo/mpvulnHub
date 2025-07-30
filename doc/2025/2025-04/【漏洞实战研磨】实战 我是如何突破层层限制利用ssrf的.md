#  【漏洞实战研磨】实战 我是如何突破层层限制利用ssrf的   
原创 blue澜  小惜渗透   2025-04-23 01:30  
  
#   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7WlExL9icWJCImpVWSXy74hk2II8xPPEXwI2tLmNia9hKjTe9eUgib2gOA/640?wx_fmt=jpeg "")  
# 我是如何突破层层限制利用ssrf  
## 1.1 关于ssrf的基础理解  
  
	ssrf漏洞也就是服务器端请求伪造  
，简单来说就是利用服务器漏洞以服务器的身份发送一条构造好的请求给其它机器。  
  
  
	对于ssrf的利用相信很多小伙伴还知道利用一些协议例如：file  
、dict  
、ftp  
、gopher  
等，其实现在在实际场景中遇到的ssrf漏洞95%不可能支持上述提到的协议（指主流的java站，一些特别老的网站除外），像那些全回显的ssrf漏洞更是难遇到（之前就仅遇到过一次），现在ssrf漏洞最多的就是被利用探测内网ip的存活情况。  
  
	在最近的ssrf漏洞的专项检查中，遇到了几个有意思的案例，而遇到的这几个案例以及遇到他们的时间仿佛就是给我准备的游戏一样，难度逐级提升。  
## 1.2 无限制的ssrf  
  
	这里讲的是我本次遇到的第一个ssrf漏洞，他没有任何限制，这里要说一下，在实战中如何挖掘这类漏洞，由于我不清楚观看我这篇文章的读者是一个什么样的水平，但是我要说的是挖漏洞这件事并不是拿扫描器或者挂上扫描器扫扫而已，现在大多数常见漏洞已经不会存在，而如何保持高效的产出呢，说白了就是心系，我一般在对一个系统进行测试的时候，基本上会把每个接口都仔细看一遍，然后利用对漏洞的理解进行挖掘，例如本文提到的ssrf漏洞  
  
  
	观看请求中是否存在特定的参数名或链接地址，如下图所示，本次案例中遇到一个接口存在两个参数，videoFile  
和coverFile  
，这两个参数值都是url链接  
，于是我直接替换掉里面的域名为我的dnslog  
地址  
  
![image-20250204175556824](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7BuYgiaIknHIqRAXGBHxiazK1iapcOWR5kicWciaJ1yJRrcCQIfXbNYDicqCA/640?wx_fmt=png&from=appmsg "")  
  
	发现dnslog接收到了来自该服务器的请求  
  
![image-20250204175753608](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7kzMFXUSDwMjqZOIOY3YjHv0ELn6DiaNsxplEWjc8pKVAx0SCl5ibLp0A/640?wx_fmt=png&from=appmsg "")  
  
		既然知道它存在ssrf漏洞了，那么接下来我们要进一步利用来确定其确实存在安全隐患，直接将域名改成127.0.0.1  
，直接让服务器探测自己，因为前文说过了它是没有任何限制的，所以直接探测成功，这里响应包内容还是相同的，我们主要根据时间来判断，658毫秒  
  
![image-20250204180051530](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE75H8y666Swbqy3W8RpsKAEzG4nVjkdiaFTrTIoicgvTFxII1iaianol56cw/640?wx_fmt=png&from=appmsg "")  
  
image-20250204180051530  
  
		然后我随手测了两个地址，发现如果地址不存在响应时间会长达40000毫秒  
左右  
  
![image-20250204180308125](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7ibG7UzdApVup1BrNbSYicC0Dn9qL3ppeOmplR7B248vPq215s3L3fwUQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250204180308125  
  
		接下来就可以通过intruder  
模块来爆破确定内网资产分布情况了，探测到的其它IP我这里就不发了，这些ip的响应时间跟127.0.0.1  
是一样的基本上不到1s  
就返回了结果  
## 1.3 限制了域名的ssrf  
  
		这里介绍本次漏洞检测遇到的第二个ssrf漏洞场景，这个场景跟上方差不多，不过它会限制域名（后文我们均用demo.com举例），如图所示，我还是将域名改成了我的dnslog  
地址，但是后面会提示接口鉴权拦截不通过  
  
![image-20250204181203688](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7PgN0QNuL23F1sptUKtmZEE1D5ZJVC8C6eCdLloAtWiak7XsSkUGq07g/640?wx_fmt=png&from=appmsg "")  
  
image-20250204181203688  
  
停留一下，到这里先别往下，大家有什么思路这个时候可以想一下  
  
		这里我只改了域名，它就报错了，那么肯定这个域名要带上的，那么它是否会限制的很严格呢？于是我分别尝试在前面和后面都加上了一些域名如dnslog.cn.demo.com  
和demo.com.dnslog.cn  
，经过证明后面这种形式可以通过接口校验，于是直接拼接dnslog后发送请求，成功接收到了来自对方服务器的请求  
  
![image-20250204182534335](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7ZVRyyN2c1VW3YSL3zFzicsCxU31UOfBSo0icxnZxvqmLmZ6gA2jtmicnQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250204182534335  
  
		既然如此如何进一步利用，如何破局呢？这里就是考验基础的时候了，如下面这个链接，这个链接最终会访问到百度还是4399呢？  
```
https://baidu.com@4399.com
```  
  
		很显然这里利用了@  
符在url中的重定向作用，跳转到了4399  
  
![image-20250204182907160](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7FkFLkyYfRpibiaIYJLxVCcLia0bEYYibz8Wib8WaDGWiam0hEvrG3KER5iaJg/640?wx_fmt=png&from=appmsg "")  
  
image-20250204182907160  
  
		所以我们这里直接尝试利用，还是老规矩，ip存在时间大约在300毫秒  
  
![image-20250204182944634](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7PlVW3d9Y3hgOxBlk2BS2L6l4AQO4Fic845juDLibvzwNIejayNYoxdzA/640?wx_fmt=png&from=appmsg "")  
  
		这次IP不存在时，不仅时间长而且还会返回504  
  
![image-20250204184833686](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7LycgULTQF1yCicCK8ibLHsUVl9qmKBLYJP6tmoTxpjFnpia2s214M1ubA/640?wx_fmt=png&from=appmsg "")  
## 1.4 限制了域名和特殊符号的ssrf  
  
		这次介绍的是第三个ssrf场景，正如我之前所说这次碰到的这几个场景仿佛就像闯关一样，这次这个场景不仅限制了域名而且@  
符号不能使用  
  
		虽然@  
不能用，但是.  
加上域名还是可以用的，如：  
  
![image-20250205124115745](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7nhibFkzDX6c27uXp3AAszowpCWygnB8PQppUwgxdDFuxCV9xX2Q8aYg/640?wx_fmt=png&from=appmsg "")  
  
image-20250205124115745  
  
		那么问题来了这样如何利用呢，我利用漏洞让其服务器请求这种地址也没用，还是要回归到探测其内网资产中，可是这里通过@  
符号的利用方式已经不能够使用了  
  
停留一下，到这里先别往下，大家有什么思路这个时候可以想一下  
  
		接下来这个思路，可能比较麻烦，但是确实是能够使用的，首先需要有个域名（比如my_host.com），然后新建两个A  
记录，让其解析IP一个解析成存在的127.0.0.1  
，让一个解析到我们已知不存在的192.168.11.50  
即可  
  
![image-20250205124831287](https://mmbiz.qpic.cn/sz_mmbiz_png/mxIibC6HQFwx8MC6hsGAae0jBolnBkOE7sJ8oEyHdkQibuEXUbq72ic5KUicwK0ta6BmYIicDzSKORstpicpW0ibmicXtA/640?wx_fmt=png&from=appmsg "")  
  
image-20250205124831287  
  
		这样我们就可以将域名替换成demo.com.aaa.my_host.com  
和demo.com.bbb.my_host.com  
来触发ssrf漏洞，这样我们也可以通过其探测内网IP存活情况了，不过我们新增或修改DNS记录后，需要等待一段时间公共dns服务器才会同步成功。  
  
               当然肯定还有别的利用方式或者更好的解决方案，例如利用存储桶或者自己在对应域名开个web服务，并配置重定向等等，就留着师傅们实际中逐步发现吧！  
  
  

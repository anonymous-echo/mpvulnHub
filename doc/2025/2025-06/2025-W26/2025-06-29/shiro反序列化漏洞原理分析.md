> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2NDY2OTU4Nw==&mid=2247521429&idx=1&sn=dd050c73cd8db8d9b702b190136ec88a

#  shiro反序列化漏洞原理分析  
 船山信安   2025-06-28 18:06  
  
## 漏洞分析：  
### 序列化过程：  
  
1.调用convertPrincipalsToBytes方法并传递数组类型的实例accountPrincipals  
  
![1750504773_685695452b139e57e583f.png!small?1750504765820](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOngI5ibzljpYPWicyWvxajgYtp9SHu611l946GFCaLJc3lqAa3OWzsjiaZQ/640?wx_fmt=jpeg&from=appmsg "")  
  
2.调用serialize实现方法进行序列化  
  
![1750504803_685695632e3cddd337e95.png!small?1750504799627](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOn0kR7WLEzjtibDz3uOJgaRMd8GNGQDXIqT1b6FKzqwdqnp6Nibpib4Vq7g/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504815_6856956fca508b77fdf25.png!small?1750504808276](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnrmLqznrUyOzevoCMawtGpRnGqKyQviaFZic1mKIypT0JnO6ILBDGmAHg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504828_6856957c78018ee8cfb23.png!small?1750504825688](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnYX4qPVCuJDZh0zJQwDy7Hm8F4YXSoq5yZNVFZwX35j8Y7HeHSjfqpA/640?wx_fmt=jpeg&from=appmsg "")  
  
3.调用encrypt方法传递实例对象并进行AES加密  
  
![1750504849_68569591189b28970daf3.png!small?1750504847308](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnzmnZBibcodLic9Q8dgJGiaJ3ZlDCBCJvhyUwFqRqDXlRBVG9qyDU5JKXA/640?wx_fmt=jpeg&from=appmsg "")  
  
4.调用get方法获取key  
  
![1750504870_685695a633ad6739e7f70.png!small?1750504862039](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOn6snkGlFp2A91XpWhXQaOVZV9Ca1aBEibSnAQjibWJcV9vjgpTvNGp7hg/640?wx_fmt=jpeg&from=appmsg "")  
  
5.Get方法返回encryptionCipherKey  
  
![1750504895_685695bf293be4ac34927.png!small?1750504887312](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnbrIpKBQtIKlW2qOQ65tImnzhWic5fmgWpADoGpuTgwJZAiamMlG3Ydiag/640?wx_fmt=jpeg&from=appmsg "")  
  
6.encryptionCipherKey通过set方法初始化成员变量  
  
![1750504920_685695d822f398c964da7.png!small?1750504911989](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnseKiaV0iaLic0VEJho5wpS7Czib1lHcqZaRibOY0d3QndH4VAs57fRyQDzQ/640?wx_fmt=jpeg&from=appmsg "")  
  
7.获取默认key传递给setEncryptionCipherKey再赋值给成员方法，最后由get方法返回key  
  
![1750504939_685695ebc7d99a1f5fe88.png!small?1750504931529](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnURKdavPd4oo0yibw2lMsoYKiaqftfPoHhf0BJpIC6gwgzIP7QhJQE1Tg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504947_685695f3d0b0a10f90fc1.png!small?1750504942245](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnx12qTzxZpdg07MY0LTBIKRc0eRuI7icRgD5NcE05dfqKHyK5YTRYJvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504959_685695ff2e6e6ab2bbf91.png!small?1750504951706](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOn4HzANrQNF4yPgkQoy1PBL8kqJgBGvRibryxDt0LluhBEZh91SeMX5TA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504966_68569606e7ec837bb5c0d.png!small?1750504963750](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnFQia3IqhicvhSUw9c9EF08CsAGnwl4E9ExH2PAMKNBnDxWgrVblVQrrQ/640?wx_fmt=jpeg&from=appmsg "")  
  
8.调用子类中的rememberSerializedIdentit获取EAS加密后的数据  
  
![1750504988_6856961c337491dbf85f2.png!small?1750504980752](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnWPEdeZDnU8QavDujQIh3f7SjV6j6oT7ibYUz2lAWOz0lXsTsxhUeGPQ/640?wx_fmt=jpeg&from=appmsg "")  
  
9.最后进行base64编码  
  
![1750505008_6856963010ecb128a0e98.png!small?1750505006078](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnYDichfOf55JJ3FLHQoPJkfT63DQ9Bg7XJWQbJbRNvI2qKrvicibeibCS5g/640?wx_fmt=jpeg&from=appmsg "")  
### 反序列化过程：  
  
1. getRememberedPrincipals调用getRememberedSerializedIdentity传递SubjectContext实例  
  
![1750505049_6856965982f653efeb286.png!small?1750505041881](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnAHz7j9PpJN6ibVIe7YtrwSQcTSnicNdwyDfVdnw8cIQ5pus3weIdHbLQ/640?wx_fmt=jpeg&from=appmsg "")  
  
2.getRememberedSerializedIdentity调用decode方法进行base64解码返回decode  
  
![1750505069_6856966dcd71c4f9fa36a.png!small?1750505062346](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnTl0W1wHje11kx5iaty7DmBRSrTex2Pv1BNVr72IznTYgxiagnzrIFVgQ/640?wx_fmt=jpeg&from=appmsg "")  
  
3.返回一个byte[]类型实例  
  
![1750505088_68569680a766e4523f644.png!small?1750505081238](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnAO40q0Bh41xGW5iahl2kyFj4wY5ALt327TYoUZRTibweyG3ibAdoXcLvw/640?wx_fmt=jpeg&from=appmsg "")  
  
4.调用convertBytesToPrincipals方法传递bytes  
  
![1750505106_6856969220c0f5dffea29.png!small?1750505107475](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnB5w1DvECSGNWZbw79ickLKfE5hxc0FSOsju946ic7icibEaKTJcSc0GDrA/640?wx_fmt=jpeg&from=appmsg "")  
  
5.convertBytesToPrincipals先调用decrypt方法传递bytes  
  
![1750505172_685696d455dcf99f30021.png!small?1750505164767](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnYia5RJCcjODKrofB0icUwNV0s6WRIRHvoJT3en6h2ApjlnTFibrwWGgcQ/640?wx_fmt=jpeg&from=appmsg "")  
  
6.通过decrypt方法进行AES解密  
  
![1750505189_685696e5d35a36064f518.png!small?1750505181644](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnTjL2BeFPTtibd1fjXzSnyJEibuUnzibicDrzo6lOeOqaUfyIQtl4aXWaqQ/640?wx_fmt=jpeg&from=appmsg "")  
  
7.获取key  
  
![1750505217_68569701640dccc1fe43a.png!small](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnqyL7CjT3pRkHG5PLPbPGGfjWkc0lMxRwNcoSbIh2icpPcnnuQXibG0Ig/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750505232_68569710269b9e4324080.png!small?1750505238416](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOncQAO10E3IibZQgicsmgak0iaGYyibFYzibDlmic42p9pfqSXXQGgfxVnaMpQ/640?wx_fmt=jpeg&from=appmsg "")  
  
8.convertBytesToPrincipals调用deserialize方法传递bytes  
  
![1750505255_68569727b7e963a80d369.png!small?1750505247631](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnSXuplbGiaoQgiaYcNC61fHr51dLnO7MSpUSpov9AwYlKrJYnvoCZybmQ/640?wx_fmt=jpeg&from=appmsg "")  
  
9.最后调用readObject方法进行反序列化  
  
![1750505277_6856973d2775dab72ac6f.png!small?1750505269412](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnuadrxmcKOAZfUcXbhlRrhzS4KSs9Rq1ibMljH0kDZU8v7VPy6C6d45w/640?wx_fmt=jpeg&from=appmsg "")  
## 结论：  
  
1.根本原因是AES加密的过程中使用了默认的密钥  
  
2.序列化过程为：序列化 ->  AES加密 -> Base64解密  
  
3.反序列化过程为：Base64解密 ->  AES解密 -> 反序列化  
## 漏洞利用：  
### URLDNS链：  
1. urldns链测试漏洞是否存在![1750505360_685697909e81cbc036c90.png!small?1750505352676](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnjxzO3z1zyJFXuvjSyGaG4aGXTyPrp0LgNSOVf6IKyk3Jvic1zahusBA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1. 断点调试之后可以看到在此处进行反序列化调用readObject方法实际上是调用hashmap里边的readObject发起dns请求  
  
1. -84 -19 0 5 → 十六进制为AC ED 00 05，这是Java序列化流的魔数标识  
  
1. 106 97 118 97 46 117 116 105 108 46 72 97 115 104 77 97 112 → "java.util.HashMap![1750505430_685697d6e37329ef4fec6.png!small?1750505426199](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnk79PkicXSCTYTr8AILusZeLF3Saq7aaoGGk0M5BHYHpP0epnIhLkRiaw/640?wx_fmt=jpeg&from=appmsg "")  
5.利用成功：![1750505479_685698073cedfdd919542.png!small?1750505478676](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicM80b12pqok5V7J4g71TcOnt72donxrgFetnZqNWKmMygVya6rautbvmnrA9KZvKPCaz4CZBOKJtQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
转自：  
https://www.freebuf.com/articles/vuls/435798.html  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2NDY2OTU4Nw==&mid=2247521147&idx=1&sn=091b2248906de288c8b678376f60cf3a

#  shiro反序列化漏洞原理分析  
 船山信安   2025-06-23 03:58  
  
## 前言：  
  
本文不包含CB链分析，只是单纯的漏洞序列化和反序列化的超详细分析。  
## 漏洞分析：  
### 序列化过程：  
  
1.调用convertPrincipalsToBytes方法并传递数组类型的实例accountPrincipals  
  
![1750504773_685695452b139e57e583f.png!small?1750504765820](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKrysduiac13KQy2FibQ9w30zRv1kBqQtVyzQGJrSzOiaNMicd627HbqaTfjQg/640?wx_fmt=jpeg&from=appmsg "")  
  
2.调用serialize实现方法进行序列化  
  
![1750504803_685695632e3cddd337e95.png!small?1750504799627](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryX1nU4Ds4Ws7cIk5iatABYYw7icibz4mDpZJicGjQkjX0gejtDJsTd72cHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504815_6856956fca508b77fdf25.png!small?1750504808276](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKrywiahl2LlTQUZbIwd6Mfd2WaMPq7qdsBTT2o3qfXb6KZ1cH8MIXBlJ3A/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504828_6856957c78018ee8cfb23.png!small?1750504825688](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKrySjkf5fPPVZbeytmttd3zX3DCy1LGSnRr9IXLQHQZuaeFZMkgQWjI6g/640?wx_fmt=jpeg&from=appmsg "")  
  
3.调用encrypt方法传递实例对象并进行AES加密  
  
![1750504849_68569591189b28970daf3.png!small?1750504847308](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryrtNPDChyLvZCbiaViacmMrhicTp8XCN2nlA6dSAZJY1xpDYCfJFFiblyZg/640?wx_fmt=jpeg&from=appmsg "")  
  
4.调用get方法获取key  
  
![1750504870_685695a633ad6739e7f70.png!small?1750504862039](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKrynWMdBruG6zptNuaQvicswvAM8sRhS8F73Uy2Pn2skbRs0ATbTMMfHqw/640?wx_fmt=jpeg&from=appmsg "")  
  
5.Get方法返回encryptionCipherKey  
  
![1750504895_685695bf293be4ac34927.png!small?1750504887312](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKrydHtiaxRYaL6RicibXicic8C42lTI4dAiba6vdRicDCHafPhCl9MNicxBz0IQAg/640?wx_fmt=jpeg&from=appmsg "")  
  
6.encryptionCipherKey通过set方法初始化成员变量  
  
![1750504920_685695d822f398c964da7.png!small?1750504911989](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryezHypjo8y7OicNbhvBgLiaIZXH9bbRia0twfahLdH1Z9pTdOXZWNpVuPw/640?wx_fmt=jpeg&from=appmsg "")  
  
7.获取默认key传递给setEncryptionCipherKey再赋值给成员方法，最后由get方法返回key  
  
![1750504939_685695ebc7d99a1f5fe88.png!small?1750504931529](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryO5s8aK6ys8ysAwI6hibC6KDfSokPNvbU5n6ub6L9O1DJsPQSbnhSU3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504947_685695f3d0b0a10f90fc1.png!small?1750504942245](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryD2AwBToFHZBNTxlfYanEjYNlJI7TiaLDRMR9XPibIFf8F11sZ85BTMiaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504959_685695ff2e6e6ab2bbf91.png!small?1750504951706](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKrynazic1F4vq4Q6nxQOT3eq1RQ3HibVULiauq1JHGrrficOghP3523vZN4qw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750504966_68569606e7ec837bb5c0d.png!small?1750504963750](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryClZic5uydD6Wiax6gRIfnsODQa8vVmZbyvm6UbTVRhicicvtXrL37c1tBA/640?wx_fmt=jpeg&from=appmsg "")  
  
8.调用子类中的rememberSerializedIdentit获取EAS加密后的数据  
  
![1750504988_6856961c337491dbf85f2.png!small?1750504980752](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryYrjRSCgVBZXKS5PrJvCBqf6myV8teuZaNOWFUlozibibG7IwHPrrCDdA/640?wx_fmt=jpeg&from=appmsg "")  
  
9.最后进行base64编码  
  
![1750505008_6856963010ecb128a0e98.png!small?1750505006078](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryn39c4URSGKKLPPf2gSkUIMYFDSjibkyXiaegW0TZS3f6gooE0cibzC47A/640?wx_fmt=jpeg&from=appmsg "")  
### 反序列化过程：  
  
1. getRememberedPrincipals调用getRememberedSerializedIdentity传递SubjectContext实例  
  
![1750505049_6856965982f653efeb286.png!small?1750505041881](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryhzkqeeFib8LYhKGLd33MlmjQLMoQEmUSp4kMKm8tjET7vxmev6v1rBQ/640?wx_fmt=jpeg&from=appmsg "")  
  
2.getRememberedSerializedIdentity调用decode方法进行base64解码返回decode  
  
![1750505069_6856966dcd71c4f9fa36a.png!small?1750505062346](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKrymYnb25WCjNHB3DsIoyjbVUzn10fVoBHnTyV2NZb0tPsicXicaKL481icg/640?wx_fmt=jpeg&from=appmsg "")  
  
3.返回一个byte[]类型实例  
  
![1750505088_68569680a766e4523f644.png!small?1750505081238](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryN3ib2kocY8PCfQz3d2lFRCAiaribyicm8iacibGesubpLtLNWuY9JRvdEHibw/640?wx_fmt=jpeg&from=appmsg "")  
  
4.调用convertBytesToPrincipals方法传递bytes  
  
![1750505106_6856969220c0f5dffea29.png!small?1750505107475](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryyez4icUTkQASoFeb2PQZRTAO1anyBOxJwhmoXab4ljPepeqJ1zEvQMA/640?wx_fmt=jpeg&from=appmsg "")  
  
5.convertBytesToPrincipals先调用decrypt方法传递bytes  
  
![1750505172_685696d455dcf99f30021.png!small?1750505164767](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKry8paw4ia6ryrDscTXU12CBmA4DT0epVrjtSxEAExS3IVR9hvxDdB7jGg/640?wx_fmt=jpeg&from=appmsg "")  
  
6.通过decrypt方法进行AES解密  
  
![1750505189_685696e5d35a36064f518.png!small?1750505181644](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryEqSTan6N0NTOtVUYLEoCamiaUAJIED21SVtaU83abw0eCPlKAJQTZpA/640?wx_fmt=jpeg&from=appmsg "")  
  
7.获取key  
  
![1750505217_68569701640dccc1fe43a.png!small](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryB7dzJCDr40RLIa3pNhBIx4yicbicD0nibcUsH415BeFzo1iblj8EiaxxZlw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1750505232_68569710269b9e4324080.png!small?1750505238416](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryml2nVruWeGicKX2Q9gwLzDwoqM04jfoZKzlBXITrHsB3UOTW7oDgc5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
8.convertBytesToPrincipals调用deserialize方法传递bytes  
  
![1750505255_68569727b7e963a80d369.png!small?1750505247631](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKrytyzu199SZbvibDgNg9uz7eehTeaGtmaAVeibSPUnOOGqBZ8Kh5pCsDYA/640?wx_fmt=jpeg&from=appmsg "")  
  
9.最后调用readObject方法进行反序列化  
  
![1750505277_6856973d2775dab72ac6f.png!small?1750505269412](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryOcfqvTlMMjSJR67t6acNBsViagwWBBHQmzAmcXzS2ID97HDsgElZ9yg/640?wx_fmt=jpeg&from=appmsg "")  
## 结论：  
  
1.根本原因是AES加密的过程中使用了默认的密钥  
  
2.序列化过程为：序列化 ->  AES加密 -> Base64解密  
  
3.反序列化过程为：Base64解密 ->  AES解密 -> 反序列化  
## 漏洞利用：  
### URLDNS链：  
1. urldns链测试漏洞是否存在![1750505360_685697909e81cbc036c90.png!small?1750505352676](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKry68bfZbicMuRAJzOWGvrYsMZTECLKFOpDy1AutoTibMsBGqC6QXpRr7dg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1. 断点调试之后可以看到在此处进行反序列化调用readObject方法实际上是调用hashmap里边的readObject发起dns请求  
  
1. -84 -19 0 5 → 十六进制为AC ED 00 05，这是Java序列化流的魔数标识  
  
1. 106 97 118 97 46 117 116 105 108 46 72 97 115 104 77 97 112 → "java.util.HashMap![1750505430_685697d6e37329ef4fec6.png!small?1750505426199](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKryianKK0EouecmcshqwjJ2ib9wORgOU9aic2RbJM55IHEhHQoOwXf5pRs0g/640?wx_fmt=jpeg&from=appmsg "")  
5.利用成功：![1750505479_685698073cedfdd919542.png!small?1750505478676](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicMv7OxOHdK4YcwrgePWKKrypLhicpibvzEHGSlyx7G3PGAKibSLgoQmkicJ209PgXDxw2XaaQXH6IpIpA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
转自：  
https://www.freebuf.com/articles/vuls/435798.html  
  

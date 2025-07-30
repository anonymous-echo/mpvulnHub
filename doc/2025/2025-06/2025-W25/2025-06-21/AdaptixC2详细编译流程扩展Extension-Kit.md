> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3NDc3NDQ3NA==&mid=2247485225&idx=1&sn=1c6e03e4fe3aa979433ab6b054fae634

#  AdaptixC2详细编译流程扩展Extension-Kit  
原创 深潜sec安全团队  深潜sec安全团队   2025-06-21 09:29  
  
关注公众号，输入“学习交流”加入交流群  
  
觉得不错的话，可以多点赞、分享、关注  
## server端  
  
这里推荐使用ubuntu20或者ubuntu22编译，因为方便，而且这两个安装虚拟机也快，不像debian那样子麻烦。  
  
环境配置这两个  

```
sudo apt install golang-1.23 mingw-w64 make
sudo ln -s /usr/lib/go-1.23/bin/go /usr/local/bin/go
```

  
然后将这三个文件复制到ubuntu中，当然也可以使用git clone直接下载到ubuntu都行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE13JsEKHpoEY4aiaXDSLIMNicsQQoCyuOiaJJ8HnEiceRicaDaDhJ0wSnHceg/640?wx_fmt=png&from=appmsg "null")  
  
建议设置GOPORY，不然可能部分go的库会下载失败。  
  
export GOPROXY=  
https://mirrors.aliyun.com/goproxy/[2]  
  
然后直接编译就好了，生成好就是有这些文件，证书需要我们自己生成，运行ssl_gen.sh就可以了  

```
make server
make extenders
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1e0Vyo1wkSBAnMQibl8VwOdBWT9b4ywRp8dLOJKPFTQkTSyNZBlgpPUA/640?wx_fmt=png&from=appmsg "null")  
## clent端  
### 1.安装QT  
  
首先去  
https://doc.qt.io/qt-6/qt-online-installation.html[3]  
这里注册账号，安装QT。  
  
安装的时候，注意自定义这里，安装我们需要的模块  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1rxdGFCVdC5nISOqUYtf3RGQacPEsJWzpAI4iaib14t1BIU7ia4p4xpqcQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1HWDJIptucZBG71bqd5kmoeAsF95Mg1hZz2IIvk42fW0dxYtYuJbMXQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1NUW63XC0XuKPAgmlCG0D5hnFNcZoJtz1c3cPtwwJSJUY6LtrdmUhOA/640?wx_fmt=png&from=appmsg "null")  
### 2.构建  
  
然后来到AdaptixClient，选择Qt Creator加载CMakeLists.txt文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1t8CFsrxSYeH4Q2DicSUnZ3ED6OKSPicEAUcQ15COj2aicuK6MMTyVyOAw/640?wx_fmt=png&from=appmsg "null")  
  
打开后，选择Release，然后点击下面的configure Project  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1kmK7fdUh8smD20bNcv2LUkSpp1vXtbEAevUMGqmkp8H2bFl0Fia596w/640?wx_fmt=png&from=appmsg "null")  
  
然后选择构建  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1GkCQj5EHMCfMebHEcsibG6PAERJoiaWfzXgQJKWbp6CkMqXSibCDONvtw/640?wx_fmt=png&from=appmsg "null")  
  
等待这里编译好  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1uGDgcW6XNSAC49QLwiceTOIXE5gCqHxlKmL1Yw59SHia4TEgCK5X6kicQ/640?wx_fmt=png&from=appmsg "null")  
  
来到对应的文件中，看到该exe文件，这时候还不能用，因为没有对应的dll，单独将该exe拿出去，到一个文件夹中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1m0QFFXW5aiaA6UoKb6ia3qBfzyjiaibAv8aHYsOEiamu6AMjic6VWVJrhSsQ/640?wx_fmt=png&from=appmsg "null")  
  
找到QT的安装目录，我是D:\common\Qt，找到D:\common\Qt\6.8.3\mingw_64\bin\windeployqt.exe文件，然后后面跟着对应的编辑出来的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1UESXk6e7CBp91OMeiacubo1MbTc691CxEoY5ib7bFdGZicdicjZSibGJumw/640?wx_fmt=png&from=appmsg "null")  
  
这时候AdaptixClient.exe就可以打开了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE15CicicN5vg0gZibK2TXfPBl5Q0R5YOYk9owKZKZiaojMfz7QeBMfgStGjA/640?wx_fmt=png&from=appmsg "null")  
## 测试上线  
### 1.获取信息  
  
来到server端的profile.json的文件，这里就是我们连接的信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE11dVibZtuWHcsPg3DEeQuR7ucGG5QWGice4u5icllqpW34eCHxhWoU5yTA/640?wx_fmt=png&from=appmsg "null")  
  
通过启动server端  

```
./adaptixserver -profile profile.json
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1zvnnCtSERic43JR0M0Z1OEgA0c2D4MQs07P97oppbG2U3iaDQEFJYzSQ/640?wx_fmt=png&from=appmsg "null")  
### 2.clent端连接  
  
根据对应的信息填写，password就是上面json中的password字段内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1bplPufscJTb081fjXtjgLWKvx2TpDjBYaPKzKnx6Fz8xBN2ofazKSQ/640?wx_fmt=png&from=appmsg "null")  
  
点击耳机，然后创建一个listener  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1jC3JKNgZFLyAA6cBNIo7DjtzianicsE1b5Ou8p3sl9m6CYhI8654cX2A/640?wx_fmt=png&from=appmsg "null")  
  
然后右键，创建paylaod  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1FHavGeDzJuXrdoRBibnw83GV2zUwBL68jcEJwkO5QcEeJLNbrg7STdA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1z1ND7HiaMZrJCU649ospcFIQUV3ibUWEGocy8VibvsU77CUzFmxoxV5Mw/640?wx_fmt=png&from=appmsg "null")  
  
复制到虚拟机中，看到测试上线没有什么问题  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1Wq4fLOa23uibG8Rv2BoGh75mhZ9EJGXcpMxzib3b2cQBoTWpzlOOTxTg/640?wx_fmt=png&from=appmsg "null")  
## 安装扩展Extension-Kit  
### 1.编译  
  
将内容  
https://github.com/Adaptix-Framework/Extension-Kit[4]  
 复制到ubuntu  
  
然后再改文件夹中，输入改命令，进行编译  

```
for d in */ ; do (cd &#34;$d&#34; && make); done
```

### 2.导入  
  
然后将编译好的文件，放到clent端，打开Extender，通过loadnew导入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdzcPs3CVhHJw9lCa271NEE1jzTgibYr3rwWyHROEPHjsaxUNia4d37GSSVtEpJIye7m7HgldQRWEphw/640?wx_fmt=png&from=appmsg "null")  
### References  
  

```
[1]
```

  
: https://github.com/Adaptix-Framework/AdaptixC2
```
[2]
```

  
: https://mirrors.aliyun.com/goproxy/
```
[3]
```

  
: https://doc.qt.io/qt-6/qt-online-installation.html
```
[4]
```

  
: https://github.com/Adaptix-Framework/Extension-Kit  
  
  

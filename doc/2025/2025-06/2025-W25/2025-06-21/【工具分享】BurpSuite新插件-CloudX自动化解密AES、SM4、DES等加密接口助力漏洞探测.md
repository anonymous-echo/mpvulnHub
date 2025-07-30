> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzODQzNDU5NQ==&mid=2247486368&idx=1&sn=593e0636fcc4db1bee46051ad2903fdf

#  【工具分享】BurpSuite新插件-CloudX自动化解密AES、SM4、DES等加密接口助力漏洞探测  
秀龙叔  黑客之道HackerWay   2025-06-21 02:30  
  
![FnGmEPRISjpE8nAUYFvrsr-FeU0A](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDWdibXddJ2fEc4740GMuCQzYrdR0WIvXgNzmM205KSRCSySdny7p7OiaQ/640?wx_fmt=png&from=appmsg "")  
  
简介：  
  
推荐一个可以在  
渗透测试中加密、防重放与签名问题的  
BurpSuite插件CloudX，可自动化解密AES、SM4、DES等。  
  
使用须知：  

```
本工具基于Burp最新版本开发，采用Montoya API构建，不再兼容旧版Burp及Oracle JDK/JRE环境。其核心设计理念是：所有进入Burp的流量均为明文，向外发出的流量则自动加密处理，整个过程对用户透明。
工具不依赖传统意义上的“加解密”或“破签”逻辑，而是通过规则驱动的方式处理流量。用户只需配置好规则，即可实现对接口加密流程的自动化适配。
请注意，不要将明文数据包直接发送给CloudX处理模块，以免引发异常。如发现规则执行效果不符合预期，可通过Logger标签页查看实际发出的加密请求，辅助调试。
```

  
核心功能及亮点：  

```
基于规则的动态处理引擎：
所有操作（如加解密、签名生成/校验、防重放、字段替换等）均由用户定义的规则驱动。
规则即逻辑，理论上可适配任意结构的数据包转换需求，具备极强扩展性。


透明的请求/响应处理机制：
所有进入 Burp 的数据包自动被解析为明文；
所有从 Burp 发出的数据包自动还原为加密格式；
整个过程对用户完全透明，无需手动干预。


无缝集成主流模块：
支持在 Repeater、Intruder、Scanner、Proxy 等核心模块中直接使用明文进行测试；
自动完成前后端加密转换，大幅提升测试效率。
```

  
使用：  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDhPicIe7FpuzxEyTicRA92Yicpe5niaw4wy35YnZiceSgGJ0RJD4ygkEY73A/640?wx_fmt=png&from=appmsg "")  
  
![FnGmEPRISjpE8nAUYFvrsr-FeU0A](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDWdibXddJ2fEc4740GMuCQzYrdR0WIvXgNzmM205KSRCSySdny7p7OiaQ/640?wx_fmt=png&from=appmsg "")  
  
使用提示：  

```
可能会发现这样一个现象：响应包已显示为明文，但请求包看起来仍是密文。
这其实是 Burp 的默认行为所致 —— Proxy → HTTP History 中展示的请求，默认是“原始请求”内容，也就是尚未经过插件处理前的原始数据。
实际上，规则已经生效，只是你当前查看的是未经处理的“原始视图”。
```

  
解决方案：  
  
A方案：  
  
手动切换为“已编辑请求视图” ，如下：  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDq9JYp2TNOaiax3bsWhIb3FRrUraONDuaHrLdibEx3kRlicTIJWPSc2ykQ/640?wx_fmt=png&from=appmsg "")  
  
B方案：  
  
(推荐)设置默认展示“已编辑请求视图”，如下：  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDDvfY8yb7Y9e4l6LZE0kvCG1CrBwh6iaBJZ8soo4xUuU4vLSaU2Ogicjg/640?wx_fmt=png&from=appmsg "")  
  
视频演示：  

```
https://www.bilibili.com/video/BV13EjGz2Ers
```

  
- 公众号回复“  
8889  
”获取下载链接  
  
**用您发财的小手点个赞鼓励一下吧❥(^_-)**  
  
**关注公众号便于更好的为您分享(#^.^#)**  
  
  
  
  
**免责****声明**  
  
本公众号“黑客之道HackerWay”提供的资源仅供学习，利⽤本公众号“黑客之道HackerWay”所提供的信息而造成的任何直接或者间接的后果及损失，均由使⽤者本⼈负责，本公众号“黑客之道HackerWay”及作者不为此承担任何责任，一旦造成后果请自行承担责任！  
  
  
谢谢 !  
  
  

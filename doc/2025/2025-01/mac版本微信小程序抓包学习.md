#  mac版本微信小程序抓包学习   
原创 crowsec  乌鸦安全   2025-01-02 04:08  
  
✎ 阅读须知  
  
  
  
乌鸦安全的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。  
  
乌鸦安全拥有对此文章的修改、删除和解释权限，如转载或传播此文章，需保证文章的完整性，未经允许，禁止转载！  
  
本文所提供的工具仅用于学习，禁止用于其他，请在24小时内删除工具文件！！！  
  
  
  
# 1. 环境准备  
- macos intel  
  
- 微信 Version. 3.8.9 (28564)  
  
- proxifier V3.12  
  
- burpsuite pro  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDN99iclnrl8cocYnBFszZuulYK1LprKus5JWJosFT9WLDicWH5icvkGD3A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDzcRXicOXt4wQHZ77iboemXtJn7ILw9FkdHMTezXpNziajJaa5yTGtNVUg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDU2WxpR2Z2d5IsqdDNuJwU4GcvfIO4VfC6gsvV2b6LTRJOOricADibCNQ/640?wx_fmt=png&from=appmsg "")  
# 2. 环境配置  
### 2.1 坑点  
  
在去年的7月的时候，其实我在文章里面介绍过几种抓微信小程序的方法，在文章里面我也介绍了使用proxifier和burpsuite抓包的方法（因为我环境配置错了，菜），但是因为我配置有问题，导致抓包不顺利。（菜）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/HficxWTTwt1AECLlTYY0lGmHOs3CGnylD2bJc0mEAONhlchK9GEKuyggKzicUuB164eqDrxcDjtI9qGLOcM8mPdQ/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDYAPhzTxAMktaN7cYTcoZ9loXiaGG1BxssEoVj2rka5yLKiaEbjpkQu9Q/640?wx_fmt=png&from=appmsg "")  
  
当时确实是我的本地环境有问题：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDDLcRgVuo7s16wkCKlicmyaWQAoQ3nLpNjNFKxBqQqVVNwU6Zx97Zbrw/640?wx_fmt=png&from=appmsg "")  
  
前一段时间，学习其他的师傅发了很多关于这个的文章，但是到我这里，果然不出所料，我还是抓不到包。。。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDylVbiapZPHAmlTvQUR6fdGrx5tPruHUtDJ5J1CQAGFGx5Yialf91gEibw/640?wx_fmt=png&from=appmsg "")  
  
其实在这个代理链流程里面，其实很简单了：  
  
小程序的流量被proxifier  
转发给burpsuite  
，burpsuite  
再将流量转到外面，其实就是上面文章里面师傅画的拓扑图。  
  
但是问题就出在burpsuite将流量转到外面这个过程上，我测试的过程中发现burpsuite收到从proxifier转发过来的流量之后，没有返回包，经过测试才发现，**如果你有隧道类工具的话，记得关闭你的系统代理功能**：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylD0xPye7N5pXW813ibiaKLh8cc1lyvJHXdZMPPeo2ERYCPYsSyYTZdqTyQ/640?wx_fmt=png&from=appmsg "")  
  
### 2.2 环境简单配置  
  
直接按照这个师傅文章里面的配置就行了：  
  
[https://mp.weixin.qq.com/s/xaqlShbuCdwani10BJ8dIQ](https://mp.weixin.qq.com/s?__biz=MzU3ODI3NDc4NA==&mid=2247484403&idx=1&sn=740b1a72b916db626b4554f3e69ae878&scene=21#wechat_redirect)  
  
  
burpsuite：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDsjNO4ic4iceBPE6sNBQQGQvMbnCAFHPCVFUf8GibDWVIu1yiacWJlJ7dJg/640?wx_fmt=png&from=appmsg "")  
  
proxifier：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDdLicQkuU2pCpichMLicQwSCrvWAty5fbB2vnlJgicHArtDq5KiaRedurcOg/640?wx_fmt=png&from=appmsg "")  
  
  
至此，环境准备工作就结束了了。  
# 3. 小程序简单抓包实战  
  
前段时间，小*书某博主在推一个租房的小程序，经过其授权同意后，对其进行简单的漏洞挖掘：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDhiazOtqCDQmhVz8X8sQHU8EOSmfmzibCw0SYtjrtkV6G1IhMgKjstyqA/640?wx_fmt=png&from=appmsg "")  
  
这个小程序的逻辑如下：  
- 求租客可以免费发布租房需求，可以留下电话号码给房东联系，请注意，这个号码不会对外展示  
  
- 房东需要注册认证，认证通过之后，就可以查看求租客的需求，如果有需要的话，可以通过求租客留下的电话联系求租客  
  
- 房东获取电话这一步是需要收费的，有次数限制  
  
### 3.1 小程序反编译  
  
直接在mac的文件夹下获取到小程序的文件，然后直接进行反编译即可：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDJfcicx0IKxMg241fxyxnZicjWzYbjyN9zAASLSJT28QALRANNbCOeohg/640?wx_fmt=png&from=appmsg "")  
  
至于反编译的过程，可以看我[以前的文章](https://mp.weixin.qq.com/s?__biz=MzI3NjA4MjMyMw==&mid=2647788698&idx=1&sn=a32d8f31f4b5ed2d70e02684df77189d&scene=21#wechat_redirect)  
，也可以从网上找一下教程，教程满天飞，非常多。  
### 3.2 简单漏洞1—小程序地图ak泄露  
  
这个ak泄露甚至都不算是漏洞，在小程序案例里面太多太多了，大部分src甚至都不收。  
  
定位ak泄露，分别在小程序源码和url中泄露：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylD9BQullVZbOINRM4F2oVqRwX6icQ0pIVicicDFFfBtt1BwibSehiaU0sE5Rg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDbibxMcZweGhQRibP2dFqpOSD6AQ12vlwGS1icxoibY5siaqjVWpTCYZGYVA/640?wx_fmt=png&from=appmsg "")  
  
随意修改坐标：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDpd7UibibkzAhOuico2UnicP6BBpFVBlqnJLzmGLx5VmqFLYoswMrxfMayw/640?wx_fmt=png&from=appmsg "")  
  
### 3.3 简单漏洞2-任意文件上传漏洞  
  
通过反编译的源码存在文件文件上传的点：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDsczmD2eh7F4vxgOlKyrBiaHNzKqlSibYGOdLqyM1kicxaCM9vDMvickLDw/640?wx_fmt=png&from=appmsg "")  
  
  
burpsuite抓包看下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDr673b0SGoJIkvorUYcZzOye4tDib9b1IibZRNc7pq0X0dddaZxib4G0rQ/640?wx_fmt=png&from=appmsg "")  
  
  
但是在这里面对文件做了限制，应该是非图片类文件，无法解析的话，直接让你下载下来了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylD9Yr3JaByk41W6dJsBQdSp2UMbHAsLOyTTlCfplhBbYpUXSHxjA3orQ/640?wx_fmt=png&from=appmsg "")  
  
  
但是突然想起来这后端是一个java部署的，修改为jsp试试看：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDXSMnrAKfkUZTYiamOSFVKr0BxyT2RVjXicVKlB9moCnnaSR63aM3QjGQ/640?wx_fmt=png&from=appmsg "")  
  
至此证明，该小程序存在任意文件上传漏洞。  
### 3.4 简单漏洞3-求租客敏感信息泄露  
  
在小程序的逻辑里面，房东是需要认证通过之后，通过充值获取求租客电话的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDUd3lEXx9qw6MqZ197A310WJ5HHOiaSTdR9HcnE9erK61s6PBkiacmyTQ/640?wx_fmt=png&from=appmsg "")  
  
但是通过直接抓包求租客模块，可获取到求租客的电话信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDn1LqicDAJwicG0Jic2pZa1oZoEqtnmA7w6k7BnSAiadeiczicXrrECzCJFSQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDbicsS9VuurxTBPzLVJ18MYGngnHzV6Hm1icnGR3ibNNDMvFqwymSibsNTQ/640?wx_fmt=png&from=appmsg "")  
  
  
提取url地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDSUIjykcePFGU7bYLQS43WzhrCFnCmV5vbvBMKmpmJM9cd9WG8YP2IQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过遍历url的id值，即可获取到所有用户的电话号码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HficxWTTwt1AECLlTYY0lGmHOs3CGnylDAorichnib1DtF8sdvN8UOzp06Pcia0iclo6DIhOwNLEyXnKfiaqemyC2jvA/640?wx_fmt=png&from=appmsg "")  
  
  

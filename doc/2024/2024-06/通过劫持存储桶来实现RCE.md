#  通过劫持存储桶来实现RCE   
原创 richardo1o1  迪哥讲事   2024-06-07 17:30  
  
通过劫持存储桶来实现RCE  
## 正文  
## 过程简要  
  
1.在官方安装脚本中发现文件是从Amazon S3存储桶（s3://rocketchatbuild）下载的  
  
2.尝试访问指定的S3存储桶，但发现该存储桶不存在（错误信息为“NoSuchBucket”）。这意味着任何人都可以创建这个同名的存储桶，并上传任何内容。  
  
3.攻击者可以创建这个存储桶，并上传一个自定义的rocket.chat-develop.tgz文件。由于安装脚本未对下载的文件来源进行验证，这使得攻击者可以通过脚本在任何使用该安装脚本的用户机器上执行任意代码。  
## 整个流程  
  
环节一：检测存储桶不存在  
  
首先尝试访问install.sh脚本中引用的S3存储桶URL。这通常是通过AWS命令行界面（CLI）或编程方式来完成。  
  
检测存储桶是否存在的AWS CLI命令:  
```
aws s3 ls s3://rocketchatbuild #rocketchatbuild在原安装脚本中是存在的

```  
  
这条命令会尝试列出存储桶中的内容。如果存储桶不存在，AWS CLI会返回一个错误，通常是“NoSuchBucket”。  
  
当看到类似这样的错误时，攻击者可以确信这个存储桶名目前没有被任何AWS账户注册。  
  
环节二：注册并控制存储桶  
  
一旦确定存储桶不存在，攻击者可以通过自己的AWS账户去注册这个存储桶名。这一步骤通常在AWS管理控制台或使用AWS CLI完成。  
  
创建存储桶的AWS CLI命令:  
```
aws s3 mb s3://rocketchatbuild

```  
  
这条命令会创建一个名为rocketchatbuild的新存储桶。创建成功后，攻击者就可以上传自己的文件到这个存储桶。  
  
环节三：上传恶意文件  
  
攻击者接下来会创建并上传一个恶意的压缩文件（如rocket.chat-develop.tgz），替代原本应该由官方发布的文件。  
  
上传文件的AWS CLI命令:  
```
aws s3 cp localpath/rocket.chat-develop.tgz s3://rocketchatbuild/rocket.chat-develop.tgz

```  
  
在这里，localpath/rocket.chat-develop.tgz指向攻击者本地准备的压缩文件，该文件可能包含恶意代码。  
  
环节四：脚本下载并执行恶意文件  
  
当任何用户的install.sh脚本执行并下载rocket.chat-develop.tgz时，它实际上是从攻击者控制的存储桶下载。一旦下载并执行，恶意代码就会在用户的服务器上运行。  
  
脚本中的下载和执行命令:  
```
curl -fSL "https://s3.amazonaws.com/rocketchatbuild/rocket.chat-develop.tgz" -o rocket.chat.tgz  #下载文件

tar zxf rocket.chat.tgz && rm rocket.chat.tgz  #解压缩并删除压缩文件
cd $ROOTPATH/bundle/programs/server #改变当前工作目录
npm install #安装npm依赖
pm2 startOrRestart $ROOTPATH/current/$PM2FILE  #使用PM2启动或重启应用

```  
  
在这个环节中，恶意代码的具体行为取决于攻击者的意图，可以是安装后门、盗取数据、破坏系统或其他恶意活动。  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
## 参考  
  
https://hackerone.com/reports/399166  
  
  

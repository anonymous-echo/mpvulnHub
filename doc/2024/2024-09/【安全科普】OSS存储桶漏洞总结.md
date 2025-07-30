#  【安全科普】OSS存储桶漏洞总结   
学网络安全到  开源聚合网络空间安全研究院   2024-09-19 16:53  
  
****  
网  
安  
教  
育  
  
培  
养  
网  
络  
安  
全  
人  
才  
  
技  
术  
交  
流  
、  
学  
习  
咨  
询  
  
  
**简介**  
  
  
  
OSS，对象存储服务，对象存储可以简单理解为用来存储图片、音频、视频等非结构化数据的数据池。相对于主机服务器，具有读写速度快，利于分享的特点。  
  
OSS工作原理： 数据以对象（Object）的形式存储在OSS的存储空间（Bucket ）中。如果要使用OSS存储数据，您需要先创建Bucket，并指定Bucket的地域、访问权限、存储类型等属性。创建Bucket后，您可以将数据以Object的形式上传到Bucket，并指定Object的文件名（Key）作为其唯一标识。  
  
  
**介绍几个概念：**  
  
Bucket：用户用来管理所存储Object的储物空间。  
  
Object：OSS存储数据的基本单元。  
  
Key：当存储文件（Object）时，需要指定此Object的名称（Key），后续您将通过这个Key来获取该Object的内容。 Key也可以用来模拟文件夹的一些属性。  
  
Data：存储的数据本体。  
  
  
**参考**  
  
  
  
  
阿里云 OSS对象存储攻防https://zone.huoxian.cn/d/918-oss  
  
对象存储(OSS)攻防案例https://www.freebuf.com/articles/others-articles/356583.html  
  
  
**环境搭建**  
  
  
  
购买某里云的OSS存储，很便宜一年9块钱。  
  
创建一个Bucket。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqIlK7UHz5deKfUweBvJsEW4W25pdn1FKnzkqxzUcicfVF7QtpQnETiabQ/640?wx_fmt=png&from=appmsg "")  
  
默认情况下，Bucket是私有权限（private）。  
  
  
**相关漏洞及其成因**  
  
  
  
  
**OSS遍历漏洞**  
  
Bucket Object遍历  
  
因为将读写权限设置为了公共读（ listobject），便会导致可存储桶遍历。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqvgiaqx9Rgq0ic2ZzsXFEuC3rRT244KcU9ibhNFGN7icfmle1KSjczktb8A/640?wx_fmt=png&from=appmsg "")  
  
这里设置了权限为listobject，直接访问存储桶域名就能看到存储桶中的所有文件的列表。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqalGuQKPO2ziaj90wf1icFo5LC6VUOT0gIJ6SRlyqMUMRq5UeVZ2pGVJg/640?wx_fmt=png&from=appmsg "")  
  
使用ossx工具可以遍历下载全部文件，工具地址：https://github.com/source-xu/oss-x  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqoHOI31LE665qHibtWnvOoLfKjOxcsLhmR5VRkicpC4cKjFXFjmib7hicQQ/640?wx_fmt=png&from=appmsg "")  
  
  
**Bucket桶爆破**  
  
当不知道 Bucket 名称的时候，可以通过爆破获得 Bucket 名称，这有些类似于目录扫描，只不过目录一般通过状态码判断，这里通过页面的内容判断。  
  
NoSuchBucket：存储桶不存在。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqicq18obdDtg5xrXrXUWtxnx9YVxIvQbXeicy80RicKBkIgmwLqyk8Kx7Q/640?wx_fmt=png&from=appmsg "")  
  
  
InvalidBucketName：存储桶的名称不符合规范，属于无效的存储桶名称。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqb00CT6KjqQ24fxpbh9y4SialWwFdppC5Criaoug5AbMibtoEfnH91ic3MA/640?wx_fmt=png&from=appmsg "")  
  
  
AccessDenied：存在，但无权限访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqyHoNtvPrNC0kGkibySnU8oJz2CXMx1Rb5xlIkAxamZ340gZcwShpiarw/640?wx_fmt=png&from=appmsg "")  
  
  
成功访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEq6OKWRNScmsSx0DiaEEzMdWfF7SWnshYhTqFdKFGKIlickDicsia7Toic8lw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**任意文件上传与覆盖**  
  
  
  
当存储桶的配置存储桶权限为可写，会导致攻击者可上传任意文件到存储桶中，或覆盖已经存在的文件。  
  
使用PUT方法进行上传，任意覆盖文件。  
  
上传。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqnJZeGgbAFebzN3o1POVvBtkPkRWNSInWQ26KyFCtZcpQUBBtng2DTQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqyUJ0H1yuMf2qOIK8I1mJUO70q0FibuqArxIYbJjDpo6WKibtuWIO2lAQ/640?wx_fmt=png&from=appmsg "")  
  
  
覆盖。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqBBd1QyUsekRLeSUrautXwqRS4Y6icb0SFcasYiaiaicnMN5WSibWEdVvhlQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqzGlqaTiaWZSKY7Am45PbGjicyovicxXp160F1Rs56tEkhEfibaXzibAHUkQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**Bucket 接管**  
  
  
  
  
利用条件相对苛刻一些，需要域名曾解析并绑定了一个存储桶也就是网站托管，存储桶被删除，但域名解析的 CNAME未删除，此时访问时会显示NoSuchBucket。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqCN3mhybz68fwz5Rkxf3vviaOMTyXia3GOGahR6WNKct4HIxLbvaicvWJw/640?wx_fmt=png&from=appmsg "")  
  
  
利用方法是新建一个同样的Bucket，储桶名称相同，并且启用网站托管（域名托管）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqVEdaGUtMicdX2QSut6asSqIMPzjGHzTSticJEEJxEZvCQungcEpgvY4g/640?wx_fmt=png&from=appmsg "")  
  
  
利用的例子：Amazon S3 Bucket桶接管教程  
  
大致就是按照流程接管，开启读取权限，然后上传一个文件。  
  
  
**AccessKeyId，SecretAccessKey泄露**  
  
  
  
  
获取目标的 AccessKeyId、SecretAccessKey 泄露，便能获取到目标对象存储的所有权限。  
  
主要来源如下：  
  
1、通过GitHub等开源平台中的源码可发现存在泄露的Key。  
  
2、通过反编译APK，找到敏感信息。  
  
3、在目标网站源码中找到。  
  
这里用到的工具就是ossbrowser，参考官方文档安装连接即可控制。  
  
安装并登录ossbrowser  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqQ81VmvB6G59tCssBibELfnq50sN56ibda41DdaFfjG2QZYDA8v0lXPiaA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**Bucket 策略配置可写**  
  
  
  
  
若拥有Bucket Policy 的编辑权限，可以通过上传或修改一个新的配置。涉及的权限如下图。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEq16VzdEZ389JcibCL8kHY1lWsNzalPAN65T9eLzShSZYQchUjxXRbQDQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**修复方法**  
  
  
  
存储桶相关的漏洞基本都来自权限管理的问题。  
  
  
修复方法如下：  
  
1、应做好存储桶的权限管理。OSS鉴权详解  
  
2、注意存储桶过期后及时关闭域名与存储桶的绑定。  
  
3、避免敏感信息泄露。  
  
  
**最佳权限**  
  
  
  
官方建议是使用私有权限，对文件的所有访问操作需要进行身份验证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rCukMxCXicnaAdiaWCfpB4yRZn6mG5jicEqAZBS0kuR15KnZzDibRplvyXX6nsYbPTnhDWxoYTvnT8BkTibVFm6ozSg/640?wx_fmt=png&from=appmsg "")  
  
  
  
版权声明：本文为博主原创文章，遵循 CC 4.0 BY-SA 版权协议，转载请附上原文出处链接和本声明。  
  
原文链接：https://blog.csdn.net/RMC131/article/details/140086454   
  
  
  
**END**  
  
  
  
  
  
  
**精选文章**  
  
  
  
环境搭建  
  
Python  
  
学员专辑  
  
信息收集  
  
CNVD  
  
安全求职  
  
渗透实战  
  
CVE  
  
高薪揭秘  
  
渗透测试工具  
  
网络安全行业  
  
神秘大礼包  
  
**基础教程**  
  
我们贴心备至  
  
**用户答疑**  
  
 QQ在线客服  
  
**加入社群**  
  
QQ+微信等着你  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rCukMxCXicnbaLbcYgxPEznaLZeyyXugCM0jZW8xpLygice6Qnle72W2jFDsr0V8VTsf4otSh7jEH5lJH9icdiaKpQ/640?wx_fmt=jpeg "")  
  
  
**我就知道你“在看”**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/rCukMxCXicnaJbqicEeFlobznozfm72D79VrDP7Z5o6icc8SVia8haOeSC8wakd8Wo4LboXV8DFgJP5Xf0fcPD1BHA/640?wx_fmt=gif "")  
  
  
  

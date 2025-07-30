> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486558&idx=1&sn=e150a399f701a2a8c0b490ea631bfa05

#  代码审计-Java项目-反序列化漏洞  
原创 xiaoheizi  小黑子安全   2025-07-16 12:49  
  
java  
序列化和反序列化的概念：  
  
序列化：把Java对象转换为字节流的过程。  
  
反序列化：把字节流恢复为Java对象的过程。  
  
序列化  
函数接口：  
  
Java  
：Serializable Externalizable接口、fastjson、jackson、gson、ObjectInputStream.read、  
  
ObjectObjectInputStream.readUnshared、XMLDecoder.read、ObjectYaml.loadXStream.fromXML、  
  
ObjectMapper.readValue、JSON.parseObject等  
  
PHP  
：serialize()、 unserialize()   
  
Python  
：pickle  
  
java  
序列化特征：  
  
1、  
java  
序列化功能特性  
  
  
反序列化操作一般应用在导入模板文件、网络通信、数据传输、日志格式化存储、对象数据落磁盘、或DB存储等业务场景。因此审计过程中重点关注这些功能板块。  
  
2、  
java  
序列化数据特性  
  
  
一段数据以rO0AB开头，你基本可以确定这串就是JAVA序列化base64加密的数据。  
  
或者如果以aced开头，那么他就是这一段java序列化的16进制。  
  
3、  
java  
反序列化使用场景  
  
  
http参数，cookie，sesion，存储方式可能是  
base64  
(  
rO0），压缩后的base64  
,  
MII等  
  
  
Servlets  
 http  
,  
Sockets  
,  
Session  
管理器，包含的协议就包括：JMX  
,  
RMI  
,  
JMS  
,  
JND1等  
  
xm lXstream  
,  
XmldEcoder  
等（http   
Body  
:  
Content  
-  
type  
:  
 application  
/  
xml）  
  
  
json  
(  
jackson  
,  
fastjson  
)  
http请求中包含  
  
4  
、利用类别  
  
引用库包调用反射（如：ysoserial），自身框架组件特性（如：  
Fastjson  
）  
  
5  
、利用工具  
  
jndi，ysoserial，marshalsec，  
FastjsonExploit  
等  
  
5.1  
、框架组件  
  
fastjson，shiro，jackson，  
CommonsCollections  
等  
  
6  
、挖掘思路  
  
  
-  
原生态的关键函数搜索  
  
  
-  
框架组件的引用查看获取  
  
案例：  
Java  
项目  
-jspxcms-shiro  
框架反序列化漏洞  
  
1.  
源码导入  
idea  
，搭建好环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCib5Szeprg4PXx60NLMTQgcMAHlGux2cBIFyEiaI4ARyRC6NtP9bSDBAg/640?wx_fmt=png&from=appmsg "")  
  
2.  
在  
idea  
查看依赖包发现使用了  
 Apache Shiro   
并且版本小于  
 1.4.2  
，存在  
s  
hiro-721  
漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCw6uFu6fa42ibDFtWnPSicUaqEo4KL0FxafyAq0tDVYmOfQ5iaWZzFXXpw/640?wx_fmt=png&from=appmsg "")  
  
3.  
根据网上的  
s  
hiro-721  
漏洞利用方法，使用  
ysoserial工具  
-  
选择  
CommonsBeanutils1   
利用链，  
  
因为项目中引用了下图的三个库，符合  
CommonsBeanutils1   
利用链  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCWwKsiaCbvSTe6Kw4ypAUGdVk6SoWbS58tiampg6EBklUTAKm4DlhWuMw/640?wx_fmt=png&from=appmsg "")  
  
4.  
ysoserial工具根目录启动  
cmd  
，输入：  
java -jar ysoserial.jar CommonsBeanutils1 "calc" > payload.class  
    
生成  
payload  
。意思：  
  
调用  
ysoserial.jar  
和这个利用链  
CommonsBeanutils1  
，  
"  
calc  
"  
这个就是要执行的命令，输入到  
payload.class  
文件里  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCiaMXKGzDLL98xiapNRdqyRHfpCibibU0E8Yddltv4JMyUo4xHMr1VjpjSA/640?wx_fmt=png&from=appmsg "")  
  
5.  
然后利用  
Shiro  
的  
Exp  
爆破出可以攻击的  
 rememberMe Cookie  
：  
https://github.com/wuppp/shiro_rce_exp  
。  
  
填充  
rememberMe  
字段：登录网站时勾选  
--  
自动登录，即可在数据包  
cookie  
中生成。最后加上个  
payload.class  
文件，最终可获得加密的  
payload  
。  
  
输入：  
python  
2  
 shiro_exp.py   
目标地址  
  
rememberMe  
字段  
   
payload.class  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCjl1WQCaSRqDWINGJO7y0DL99ZX4WNAme0nzGlJGuXAIm0IUDu0bHOw/640?wx_fmt=png&from=appmsg "")  
  
6.  
注意：爆破时间较长（一小时左右），  
payload  
长度决定爆破速度快慢。  
  
爆破成功，返回  
payload  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCgPpTjNygWRLuJarnEaic31dflZOT3OYOW3czfRll8YOtc49ZLvFj9hg/640?wx_fmt=png&from=appmsg "")  
  
7.  
再次访问目标地址，使用  
burp  
抓包，修改  
cookie  
中  
rememberMe  
字段的值为刚刚生成的  
payload  
，  
  
发包成功执行命令——弹出计算器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCW7iaRJOTLw4NbIQDLFSaEzraj6ZJ6kBJbKXEKIYBvhHpY8wSjXPmv6Q/640?wx_fmt=png&from=appmsg "")  
  
推荐一下作者最新研发的yakit被动漏洞检测插件，可挖掘企业src漏洞。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavtzDPaxIm6PXM8IuzuAB6ViceOVwpEMvHH403GNQp59nju2Q49TvqOpg/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
以上漏洞都是不需要任何技巧的，作者只是开启插件在目标网站用鼠标“点点点点”就挖掘出这么多漏洞，完全  
  
“零基础”“  
  
零成本”挖洞  
  
目前一共开发了四个插件：  
  
被动  
sql  
注入检测  
  
被动  
xss  
扫描优化版  
  
被动目录扫描好人版  
  
被动  
ssrf  
及  
log4j  
检测  
  
插件使用效果：[记一次企业src漏洞挖掘连爆七个漏洞！](https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486552&idx=1&sn=41c4e4a40fd104f53e22f5a7143c88ad&scene=21#wechat_redirect)  
  
  
插件使用教程：  
[新一代SQL注入检测技术，小白也能轻松挖到漏洞！](https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486516&idx=1&sn=8ce41df1c1c32eddb5762dc6c362a85b&poc_token=HEcld2ij2mPrmNUdYokG5LVG3B9lMQFCmGocR1XA&scene=21#wechat_redirect)  
  
  
知识星球——小黑子安全圈  
[  
精华版  
]  
    
开业大吉！  
  
每一个插件都是非常实用的，有没有用作者也已经通过  
  
企业  
src   
漏洞的挖掘来证明了，并且只需要开启插件  
  
点击鼠标就可以全自动挖掘漏洞。  
  
需要获取插件的小伙伴可以扫描下方二维码加入我的知识星球，星球  
 99  
元  
/  
年  
  
，前  
50  
个加入的  
 77  
元  
/  
年。  
  
加入知识星球的同学会提供  
  
yakit  
  
安装  
  
和  
  
插件  
  
使用教程。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavyafDg4ZciajrrTwTH4VWgO5MnmzRk1FMbiaZT2mQxbjb1JJicMDQLXDlw/640?wx_fmt=jpeg&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
本星球只提供精华内容，没有烂大街的东西。会持续更新  
yakit  
插件和各种漏洞漏洞探针和利用工具，哪怕你是什么都不懂的小白用了插件点点鼠标就能挖到漏洞。  
  
注！！！红包返现！！！拉新活动！！！  
  
星球接受使用插件挖到漏洞的投稿，我审核通过会返  
30  
红包，直接微信转，文章我会发公众号  
(  
每人仅限一次  
)  
。  
  
拉新人加入星球待满三天也会返  
20  
红包  
(  
微信直接转  
)  
。插件会一直优化和上新，欢迎大家加入星球。  
  
  
  
  

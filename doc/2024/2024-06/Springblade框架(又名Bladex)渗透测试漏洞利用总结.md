#  Springblade框架(又名Bladex)渗透测试漏洞利用总结   
 FreeBuf   2024-06-03 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
## Freebuf知识大陆帮会HackingWiki渗透感知已上线，同步更新各类安全文档、漏洞信息和渗透实战技巧  
##   
##   
## 一、前言  
  
**Springblade**框架（又称为**BladeX**）是基于spring微服务二次开发的框架，主要应用于java后端的开发中。之前在公众号文章中分析过框架相关漏洞，这里就总结渗透测试遇到该框架的利用方法。  
  
  
## 二、资产收集  
  
如何查询使用该框架的网站呢？  
  
bladex会使用自带的/blade-auth/oauth/token接口进行登录，因此可以根据接口这类关键字搜索资产  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9f24cUyPicg9lO7ydxxzqpvNtjQOSf7iasLnylm2wJ44EOZew91y8YTkEA/640?wx_fmt=png&from=appmsg "")  
  
或者根据下面bladex未授权请求返回的信息：**缺失令牌,鉴权失败** 来查询  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9f9eQ7pPdrrpTVwWIGldFHKgbUpDicqG89SI1qO5rSpO8EybUBCsWE84Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fv9NicicalD7Vwx2xlInJNo2mlibYtZaMKibheN4tDV6Ov9r3qqCyc0jDsA/640?wx_fmt=png&from=appmsg "")  
  
此外还能通过关键字Failed to handle request来查询可能开放在公网上面的blade-gateway服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fzPcNyC7aXbAWaYSgwQhH2IbXOpoaJ17huxZib1LQq3FlribDHe8oibXjQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9flctA33RtvE0nwTQMlBUR8fPMHeiahgRmO9DgZlDZHoPmrl5O7dcewfg/640?wx_fmt=png&from=appmsg "")  
  
  
## 三、不同模块的利用方法  
  
  
下面我根据Springblade的不同模块，分别分析利用的方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fuibaHqiceR1rV0owkvuZccZNDo8SgibMia34uZnOceRoE3FKMl3J7UZU0w/640?wx_fmt=png&from=appmsg "")  
## 框架主要是由GatewayApplication分发请求到不同模块上，因此渗透测试时直接访问前端页面抓包即可，因为前端是直接和GatewayApplication对接的  
  
## Blade-gateway  
  
对应GateWayApplication模块  
  
直接在网页中请求端口会显示如下语句：  
  
Failed to handle request  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fzPcNyC7aXbAWaYSgwQhH2IbXOpoaJ17huxZib1LQq3FlribDHe8oibXjQ/640?wx_fmt=png&from=appmsg "")  
  
GateWayApplication基本就是基于spring-cloud-gateway开发的，因此也就继承了Spring Cloud Gateway的RCE漏洞  
  
攻击者可以通过创建路由，造成命令执行  
  
这里post请求  
```
/actuator/gateway/routes/hacktest1
```  
  
返回包显示201 created则创建路由成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fiaMmWTcJ5jZ09AbbnpuVvObmCvoaEtFXTPQITFT2MkNvficINywiaQviaQ/640?wx_fmt=png&from=appmsg "")  
  
创建恶意路由如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fD9cuAfkaet5OoJYNibN2ibdHvMiavUm7BZrWu0O7nRqxicL2fib402cP5Pg/640?wx_fmt=png&from=appmsg "")  
  
请求刷新路由  
```
/actuator/gateway/refesh
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fj9cuZ6GxP27ydGDymY6PdejHiaXUqm5wNa8BMLnHbPoSIDIX5sk0IibA/640?wx_fmt=png&from=appmsg "")  
  
之后成功执行命令，在返回包中显示whoami执行结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9f9nFD2tTia8ZFq5XNtVFzeE4mBo1O4pfKPLnq0QUKhDCLUchoHw4nZ1A/640?wx_fmt=png&from=appmsg "")  
  
这个漏洞出现在bladex的3.1.0版本之前，往后的版本就被修复了  
  
  
**Blade-auth**  
  
****  
  
对应AuthApplication模块  
  
此处涉及到JWT Token验证身份漏洞，默认的jwt加密密文默认写死，值如下：  
```
bladexisapowerfulmicroservicearchitectureupgradedandoptimizedfromacommercialproject
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fUygD3CpL9AB6VkxbsibaY67Gw7HzK3SBg6c7n7zAYU7mOde0wiceHHYw/640?wx_fmt=png&from=appmsg "")  
  
对应的是jwt加密时的密钥  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fKLx8N45Amy6FTDu75licVLkH4ibic9vHaia5RVq4ic4zickMNticiaibuOo4YsQ/640?wx_fmt=png&from=appmsg "")  
  
这里在payload中写入身份验证参数，填入**user_id**、**name**参数（参数只要有值就行），**role_name**指定为**administrator**即可，左边就生成了伪造的jwt token  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fGSvTkWXoswMZ9DITR4Wj6oBCs63tfLFymxhDRZbIHY5KlZx9cyPyNw/640?wx_fmt=png&from=appmsg "")  
  
添加如下验证请求头  
```
Blade-auth: bearer 伪造的jwt token
```  
  
访问下面接口  
查询所有用户信息  
```
/blade-user/user-list
```  
  
接口有对请求用户身份的验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fIVibtQFGh2QJzr0M0soEGvXVZMvriaWstlZLNOOVnF6QyD004GmFktkw/640?wx_fmt=png&from=appmsg "")  
  
判断当前role_name是否为administrator，由于之前伪造jwt时候添加了administrator身份字段，此处可以直接绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fAITgbEH2flxvOeiczYtyScPxPRMCx27ib2BOv0gPbddwbbeUygL5UkNg/640?wx_fmt=png&from=appmsg "")  
  
请求获取所有用户的信息，包含用户名、手机、密码等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9faXwtHqEbWKAEEW7sUAj9DWRoQwDAkTyTVAib7iar2ofBk9rdpnKtf5tQ/640?wx_fmt=png&from=appmsg "")  
  
该接口请求的是**blade_user**表  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fTAz0tXiconbKcSVoHxOl39NwSnUIeNjUAvAmGF5rIPHRaatGrqEvL5A/640?wx_fmt=png&from=appmsg "")  
  
##   
## Blade-log  
  
对应LogApplication模块  
  
此处查询出所有登录成功、失败的日志  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9frTyk4RKVsibEsOiamUBAaGiasrxCPCHJVDVuSyzuIwx6rH2wmjIGO7fzA/640?wx_fmt=png&from=appmsg "")  
  
对应查询的**blade_log_api**表  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fQWuUQS7eVMvJzhIwMHWHaWUPOe82RNKFe0RqCR6AdPRLGAyZ0loRjA/640?wx_fmt=png&from=appmsg "")  
  
请求该接口，响应中的**params**参数中会记录接口请求的参数，因此可以直接拿到登录接口中使用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fbLnTcRL7ChywTom4K0YvJBk6OzeUymxazibQ7ibvJIFJIlG5u5G3hNsw/640?wx_fmt=png&from=appmsg "")  
  
请求登录接口传参登录成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fI0yMNlakxibwJQxjd841qcsnUuPwYsBF8hVZ6JVUnWyO8nvjTJ7Oj4g/640?wx_fmt=png&from=appmsg "")  
  
  
**Blade-resource**  
  
对应ResourceApplication模块  
  
结合JWT token伪造来请求获取oss配置信息，一般是minio  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fePLMrbrCjxCd4ibc2ibvWQK69s8eUOyqibl2zpvpiaEibqolPaPc7ZJX9IA/640?wx_fmt=png&from=appmsg "")  
  
查询分页接口，获取blade_oss表中的oss配置信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fnAUAVWicQicU4p0C3X8hydvYBfmhM40wTDXibyouibicE3Xqg2BGchiaJR6Q/640?wx_fmt=png&from=appmsg "")  
  
请求获取数据如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fFAFmBMQnF6KJVweBdgUAtIwN1avJbP9YH8mB71fUMDZOu9aFDo9OMQ/640?wx_fmt=png&from=appmsg "")  
  
根据accessKey和secretKey登录minio等OSS，可以进一步获取敏感信息和权限等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fZLp4V0TQds5Lw91OfaFkUGTyE7r7vM9M3O3ZR7n9OZrX5v8GgsCCZg/640?wx_fmt=png&from=appmsg "")  
  
  
**Blade-develop**  
  
对应DevelopApplication模块  
  
此处接口查询数据库中保存的数据库信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fXia8rrxib9JRicXbc9ppUqbOlGZcjXBkn44MOUR3lby9rZcgqQdXQlOFA/640?wx_fmt=png&from=appmsg "")  
  
对应查询的表为**blade_datasource**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fCzvpht4zZR5zFSBicuzibfMeHLkhLoK0Ep1yxYG5aSsP06DjgaXA1pxA/640?wx_fmt=png&from=appmsg "")  
  
泄露数据库账号密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fuIiazibteAibOoichYYHJCFhibgPNliaBBVU9V21XCh8Q5TWI9VwRD4DZgNg/640?wx_fmt=png&from=appmsg "")  
  
  
**SQL注入**  
  
****  
  
在Mapper中导出用户信息excel表格时，想要根据当前页面筛选条件来导出结果，就会传参当前的SQL条件  
  
代码中使用了如下语句接收用户的SQL  
```
${ew.customSqlSegment}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fq4Bb5Hwmmbp1nZBM7gQBHNfPmqfpuERQFHejIdMPfftwz1Pliblat9w/640?wx_fmt=png&from=appmsg "")  
  
对应接口如下  
```
/blade-user/export-user
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fctQom4skJnIibHibAEKxKANuP0Zm4y26DJCicbxNnqO0Aib4ibaaMwVy8Lw/640?wx_fmt=png&from=appmsg "")  
  
在Blade-auth伪造身份的前提下可以拼接报错查询，获取数据库字段名称  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fvSjtSeVicqIfAicQN0Jmgv4ibwr1zXxLRMRUTuEOicaYnmNbrzHKpDHIwA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识大陆帮会同步更新渗透经历文档、漏洞利用研究信息、代码审计、利用工具等**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fMa9B90a6ff9KvOeU7zq7Jial4IHCCNttuf70WZ2ohJBcUmVGgeeMSUQ/640?wx_fmt=png&from=appmsg "")  
  
**不定时更新实战思路总结**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fTwJ12az5P9ibwnf92IaDwWjUptmMh1trQcVxRqmiaMtlJNruG5icalqxQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fJh0tib66vwicLR7liaL2pib03jqbFrY044FwqVwB8zicUSqPXknMaNgOXrw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSKY8dQ8zub3UN1yvs3yu9fib1AFgVL9oLAfocGoHGkribuDficSVDM7fIbEShIbZ1u1GLpdyVibKtjAA/640?wx_fmt=png&from=appmsg "")  
  
**等等安全工具、安全文档，帮会入会优惠价：29.9元永久会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493904&idx=1&sn=762560e15729d3a8be68f51c5d846733&chksm=ce1f138ff9689a99f74af688d5eb5dadb7ac5d3639a1a97e47b38e09958df19df7b35eb39a25&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493836&idx=1&sn=618ec2e0ea830222e8c14ea4c912ef27&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

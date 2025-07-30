#  SRC漏洞挖掘--并发   
 迪哥讲事   2024-03-28 20:30  
  
## 简介  
  
并发漏洞是一类涉及多线程、多用户或多进程环境下的安全漏洞，其独特性质在于攻击者能够利用系统同时处理多个请求的特点，以获取未授权访问、篡改数据或实施拒绝服务攻击。相较于传统漏洞，它们的复杂性在于在同一时间内处理多个请求可能导致数据不一致性和竞争条件。  
## 危害  
### 数据不一致性  
  
并发漏洞可能导致系统中的数据不一致性。当多个请求同时修改共享数据时，如果没有合适的同步机制，数据可能会处于不一致的状态。这可能导致应用程序基于不正确或过时的数据做出决策，从而引发严重的业务逻辑问题。  
### 拒绝服务  
  
恶意攻击者可以通过利用并发漏洞引发拒绝服务攻击。通过大量的并发请求，攻击者可能使系统资源耗尽，导致正常用户无法访问服务。这种情况下，系统可能变得不稳定，甚至崩溃，影响整体可用性。  
### 信息泄露  
  
如果并发操作没有适当的隔离和控制，攻击者可能通过竞争条件或并发请求的执行路径，获取未授权的敏感信息。这可能包括用户数据、系统配置信息或其他敏感数据。  
## 利用场景  
### 优惠券  
  
在领取优惠券时，截取领取的报文，并发，可能领取到多张优惠券。  
### 提现  
  
在账户中留1.00余额，提现时并发，可能提现出更多金额。  
### 签到  
  
在签到领取积分处，通过并发领取多次积分。  
### 抽奖  
  
只有一次抽奖机会，并发，可能会抽奖多次。  
### 越权  
  
通过高权限账户找到高权限才能访问的接口，切换到低权限账户，访问接口，一般会访问失败，通过并发进行多次访问，可能会访问成功。  
### 其他  
  
点赞，添加地址，存在限制的地方就有可能存在并发漏洞。  
## 防护方法  
### 原子操作和事务  
  
通过原子操作和事务确保操作的原子性，从而避免竞争条件的可能性，保障数据一致性。  
### 同步机制  
  
在编码中采用合适的同步机制和锁定机制，以确保多线程或多用户操作时的数据安全，防范并发漏洞的潜在威胁。  
### 安全编程实践  
  
实施安全编程实践，包括有效的输入验证、权限控制和错误处理，以减缓并发漏洞的攻击表面。  
### 使用并发控制工具和框架  
  
部署先进的并发控制工具和框架，如分布式锁服务、事务管理系统等，提高系统的整体安全性。  
## 实例  
  
首先访问主页，看到有部分文章：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LwqCMsTTXoL6Y6Azwic53ShTLoEl4PWcdmeBic32nybticRSrmpmCsdNXUBhlcgWUY31JibbhG9C9bE3GfQJJ3Rn3w/640?wx_fmt=png&from=appmsg "")  
  
点击之后，发现有点赞的功能点，抓包查看如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LwqCMsTTXoL6Y6Azwic53ShTLoEl4PWcdw6FMKzRtVRc1nAnlBmmrfpgJdqHkPRomibPzj0B7A8UaY59xajff0Lw/640?wx_fmt=png&from=appmsg "")  
  
首先尝试repeater模块，发现只会改变返回包中thumbed的值。1代表点赞成功，2代表取消点赞成功。  
  
尝试并发插件，并发之后是一样的结果。  
  
观察请求包中到此处有contentType参数，起始为1，尝试改变参数，发包，发现点赞数量增加。  
  
使用intruder模块进行测试，设置3s左右的延时（间隔时间过短会请求失败），对contenttype进行爆破，即可无限制刷赞：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LwqCMsTTXoL6Y6Azwic53ShTLoEl4PWcdaOoPgGLgkCgqGOOLeuDFLIBol61skefhfexKG1DLEjhr4wkjoGhktw/640?wx_fmt=png&from=appmsg "")  
  
置顶文章点赞变成70，成功。  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  

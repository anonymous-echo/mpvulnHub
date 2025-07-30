#  实战 | 记一次X站逻辑漏洞到到管理员后台   
 迪哥讲事   2024-07-13 22:55  
  
**前言：**  
  
闲来无事，在群里发现有人推这玩意，一看居然是个cps平台  
  
这就有意思了  
  
我们先去找大哥开一个代理账号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2E9JQRnAaTF90icm36ScziaXZxIqZibuOlVibtjUkCg3W9mWQc2yFOQp6xKg/640?wx_fmt=png "")  
  
拿到账号之后，登录看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2E0zBXng0S58E5h6YRqOXMLQKuLePichzCDBZfh90yXJcjLibVxc7O98tg/640?wx_fmt=png "")  
  
js也看了下没啥东西，套了cdn，也没上传点  
  
可以添加下级渠道，尝试添加  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2ECA9tBJB7dQgicLBcQS9vMHiaiclwtmEZIst9gFGHtuplHmcLicF0RMdZZA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2E9oLhiarZmSCkaibvo7ic6MpCnmvKfPT4mwyGR3vJVCAs7uE2RGJnvhHCg/640?wx_fmt=png "")  
  
添加抓包看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2ExkicEFayDRI2ZaTqRw4KGvAc1ffGhC5E9puEa6VNNxS2wNhpAicY7nxQ/640?wx_fmt=png "")  
  
是能添加，添加的时候会返回用户详细参数对吧  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2EbdKUOAeJia3KJibpaKfv0HYTJxIUA3SOdWVZDYpMvDcy2bEz9ZX2rLlw/640?wx_fmt=png "")  
  
点击修改抓包看看，没返回数据  
  
在修改看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2El2SqYAC1GHKdkwfsy01ThrHQVHxdDWUA03TfsWwngmqehwdp84USug/640?wx_fmt=png "")  
  
  
这里127.0.0.1是我没登录这个账号，所以没获取我的ip  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2EfbuWFAticU63VdmexBl2ADn3ejUraiam5ibmt2wazh9RGuUmHhDOqLF7A/640?wx_fmt=png "")  
  
然后可以看到pk这个参数是不是对应的返回参数的id  
  
我们尝试修改id越权别的用户id（赌的就是他没做检测，赌的就是他id是遍历的）  
  
首先我们把不用的参数删掉，看看能不能返回，不然修改了别人就容易被发现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2ETYBMa1wnianEpjNLIiaZYpkMulNicj4yIbD4LdStUZaMiarvwnTfKibXkvQ/640?wx_fmt=png "")  
  
正常返回，然后我们在随机改一个  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2EWIMj5q9Hbn6ATcVWBkvnKOwHp4cZLNibZyZZGVIqExQLPEwH5RIyQIg/640?wx_fmt=png "")  
  
可以没毛病，那么我们改成id是1的，id为1基本上都是管理员  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2EuGiamP7W9lLkbwVGeQjLhHEEcbrHuw1JT5CLJgoQKFTLa0tuYK4GC0g/640?wx_fmt=png "")  
  
获取了管理员账号开始爆破试下（失败告终）  
  
然后我发现，发过去的参数能和返回的参数对得上  
  
我就想看能不能改  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2EXRHc8RFeSxPhKmTGEWY9DTHo2pJzMoKAbq9NOYOjwiaRU6k1Z3mjibNA/640?wx_fmt=png "")  
  
这里我们的role_id是4对吧  
  
我们改成1发包看下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2EczKKjctIaFgica549ApxAT9ib54xyiczF2JEQtYl4gLltsQWDu5YjHuOw/640?wx_fmt=png "")  
  
还真可以，roleid就是用户权限组  
  
我们直接登录我们添加的那个账号看看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouiciaSuXCcF2qZKcS35eFLy2EpTP7Bicr0wrjdiaiafmZrKW7gpHOdMib6hRa4fZrtnKTo8iamRPM9PDVEkQ/640?wx_fmt=png "")  
  
Ok，成功上去了，由于上传都是强制转换成png格式，我就懒得研究了  
  
**总结：**  
  
有些开发会偷懒，把后台添加用户（包含管理员）用一个接口，但后台功能肯定是全面的，但还是同一个接口，为了偷懒把前台用户也用这个接口，只是明面上把东西进行阉割处理，但只要进行正确的传参还是可以的，当然这个有运气成分，侥幸而已。  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
  
  

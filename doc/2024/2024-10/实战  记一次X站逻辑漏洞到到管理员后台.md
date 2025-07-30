#  实战 | 记一次X站逻辑漏洞到到管理员后台   
 Z2O安全攻防   2024-10-10 21:02  
  
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
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
# 技术交流  
  
  
### SRC专项漏洞知识库  
  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCOPMibnJIeBT6Yv0RwBJT9AFHKEbo3BxYkLnE00jVuoLicSOBCIzMiaJKQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuYbBtKotHSdHiakQJhjAQibJtibuWIrLXodxuZpTKwAl2zOz70DLbiaj5QTlExdjoHvvtZHufxHkuZU6g/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIx3z6YtXqmOkmp18nLD3bpyy8w4daHlAWQn4HiauibfBAk0mrh2qNlY8A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI5tZcaxhZn1icWvbgupXzkwybR5pCzxge4SKxSM5z4s9kwOmvuI3cIkQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIstia27YLJFBtC5icJO6gHLLgzRDqib6upI3BsVFfLL02w6Q8jIRRp0NJA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
  

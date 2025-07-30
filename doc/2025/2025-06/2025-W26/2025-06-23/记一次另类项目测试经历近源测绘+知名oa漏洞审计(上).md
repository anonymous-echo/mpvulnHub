> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTU2NzMwOQ==&mid=2247485256&idx=1&sn=856da5d054aa072ae0a0a8ab75da3390

#  记一次另类项目测试经历||近源测绘+知名oa漏洞审计(上)  
 梅苑安全   2025-06-23 15:06  
  
>   
> 目标厂商主营线下实体店面，虽然规模不算太小，但是线上资产较少  
> 测试难度并不大，但是考究综合利用  
  
## 战前准备  
  
甲方主营的是线下设备，通过web测绘几乎查不到啥资产  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQic5ulibpjx2r9jiaibecQQFCxdqzbrVbC9VQ2L2Sibttwm9cXyS86ctmGibpA/640?wx_fmt=jpeg&from=appmsg "")  
  
但是我们肯定要找一个入手口  
  
反向推测，既然主营的是设备，那么我们就通过产品名进行查询  
  
因为是可以直接在设备上进行充值操作的，我们打开美团查询  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicCo3XDhC23mJmGquHWF3ehXiaMhoeibIOusZsU7Am7jW73OvVZQvcicY3g/640?wx_fmt=png&from=appmsg "")  
  
  
大概看了有近百处店面  
  
接下来转移到抖音，用店面名找宣传视频和直播信息  
  
在视频信息中找到一处设备二维码，微信扫描后跳转到链接  
## 开始测试  
  
完整不截图了哈，被利用就完球了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicA8lL4QCicuk3sNgptaBwt6YJe1ZcBuKx99OltJPKmPXxSibvVxqibefsQ/640?wx_fmt=png&from=appmsg "")  
  
找到一处功能点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQic4WVl33IOZqUynTPmHeKU6yVNZNldnSs92fic2WTZrRysSe2Kw1ib5flw/640?wx_fmt=png&from=appmsg "")  
  
列出了所有的门店信息  
  
门店详情中存在手机号，稍微看一眼流量包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicvgpl4iaYGX3DoibuYnWSJl2ibbmTJXrxcFVnd0aLOCh9Nko0Pd6h4nXLw/640?wx_fmt=png&from=appmsg "")  
  
哦豁，部分门店存在账户泄露，但是该域名下没有找到登录接口  
  
(但是没啥用，测试过，几乎没有系统可以利用)  
  
在此文章内，会把测试过程中一部分漏洞均指出  
  
无论漏洞是否有用，测试不是一帆风顺的  
  
介绍漏洞情况，贴切实际的测试流程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQic0U5H0j1HtEIKRSpzJ3pfc7jNaickgB9wDJwP66e0O7DIPgpY0CpAWpQ/640?wx_fmt=gif&from=appmsg "")  
  
为了利用这些账户，根据域名苦苦测试许久，甚至开始怀疑是供应链  
  
  
因为资产过多，登录系统更是数不胜数，而且不是同一家厂商  
  
  
知道找到一处二级域名  
  
  
很常规的登录框  
  
  
打码，称它为"张三平台"  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicH6wlquBmhhdCuttHpsLORE1WDlrJMtRiacFYCnGnibTYwSQIWT9NGuiag/640?wx_fmt=png&from=appmsg "")  
  
  
用之前的账号测试一下，无果  
  
喷洒一下弱密码，依旧无果  
  
但是冥冥之中告诉我这里一定存在弱口令  
  
"张三平台"存在弱口令漏洞  
  
都叫这了，键入账户  
  
zhangsan   123456  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicNYsiaHpGp5SIH9P0buW4o6Zia5jUJmjvGZGhrrIicBvxGZevHJEobzA2g/640?wx_fmt=png&from=appmsg "")  
  
Surprise，还真叫这玩意，开发赏鸡腿  
  
这没话说，直接查看一下shell功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicustmQvQtXd2A9meusjyZREWJhRP0AuGbMxDbc2F1KClicZKugfNE92A/640?wx_fmt=png&from=appmsg "")  
  
直接连本地主机？？？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicKpuWcS4b9BSn7W4dyZL1akcnSacD4gk2toQ0eJ2lLpbS338iaGEgojg/640?wx_fmt=png&from=appmsg "")  
  
还牛魔是root权限  
  
欣喜三秒就是冰冷  
  
ping了一个dnslog，发现和目标厂商根本就不是同一个c段，甚至不在同一个机房  
  
简单的扫了下内网，也是啥也没有  
  
测试哪有一帆风顺的，虽然备案正确，但是对我们来说依旧是打歪的状态  
  
翻一下文件内容，啥也没有  
  
之前有注意到存在mysql按钮，回去看看，没准可以碰到一个共用的云数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicLkQKQOR1o5Hfun5bI33ezbIDxEwso9kJ2lpib3BoBTia95xVYlFux1xg/640?wx_fmt=png&from=appmsg "")  
  
在本地，而且是弱密码，测试账户，没什么意义  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicqV7dM1M8RKbSTegaEUSuRAIWeStNC6JibLIyhU8dG98hrLpRcsjKmOw/640?wx_fmt=png&from=appmsg "")  
  
测试哪有一番风顺，都是艰辛，都是狗运；  
  
回到微信，继续测试那个链接  
  
早就注意到这个图标了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicY5AKfgYuXQbLbSmjutb0QibicOHcz7Ntx1PvjqOeySdywAHjZCa1RgEw/640?wx_fmt=png&from=appmsg "")  
  
前端审计找到一处接口，访问后跳转到了一处搜索界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicwKTFibVLmGtkADcJwawevVDvRxjdGwoRRmFgStUXCSwyaalxp0QRIYg/640?wx_fmt=png&from=appmsg "")  
  
搜索一个1试试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQickPWZDBicKT0llMPnkofsVF6e2CISXYia8DLqcNZicicWJkHiapsAicibr3uQw/640?wx_fmt=png&from=appmsg "")  
  
师傅来瞪眼法判断注入位置  
  
没错就是优先测试keyword，因为本身就有字符，不容易过滤闭合字符  
  
参考文章：[夺命大SQL，看完包出洞 || 内带新鲜统一前台sql案例](https://mp.weixin.qq.com/s?__biz=MzkzMzk5MTM2NA==&mid=2247484225&idx=1&sn=fc202e2c721c9ad0fd72d780a010083f&scene=21#wechat_redirect)  
  
  
太有意思了，师傅再来瞪眼法试试，瞪出闭合方式  
  
太棒了，就是")闭合  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicM7CRibooTc19458cr71He8L5WhvR0K457UtN7icPaMdMwibl0icqFWkRHw/640?wx_fmt=png&from=appmsg "")  
  
说实话，当时手测没fuzz的打算  
  
这个闭合方式真不常见，要不是我胆大心细，差点就漏了  
  
简单测试发现没waf后，也是放心的跑了  
  
经典的布尔，时间，报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicEue6IFdxPBzP71HAp0W9x7aqFOGVTTW2glYHew5FIBqzRwlpubAibNA/640?wx_fmt=png&from=appmsg "")  
  
其实看到mysql的时候，就知道靠这一个洞rce的概率不大了  
  
想翻数据库，结果sqlmap爆破的速度极慢  
  
老奶奶下床都比它燃  
  
看看有报错还这么慢，看看是什么鬼情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicR4ZnvWX5DUrMZA3pScx803hTV76gBjicB3v1fobZwRkvvlG3nwIE6Hw/640?wx_fmt=png&from=appmsg "")  
  
感觉注入包也没啥问题  
  
等等，会不会就是因为这个闭合方式的问题  
  
补全")*  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQic6wRwQBVAzyxjCLQWcfG5POUn9G7m2k40mkc39CQu2icpUZoibibWwibEww/640?wx_fmt=png&from=appmsg "")  
  
注入速率正常了  
  
翻了一圈没获取什么重要的数据  
  
我们的目标就是两个：  
  
<1>拿下管理，所有设备和店面权限  
  
<2>拿下shell，直接远程命令执行日穿内网  
  
拒绝甲方的拷打，谁说没啥经验就测不出啥洞的  
  
后面也是一直没啥进展，主要是因为站太乱了，上百个离奇的站点，感觉测试都迷茫了，就怕又和之前那个shell一样无用  
  
两天后就到五一，出去散散心  
  
和女朋友去趟重庆给自己放放假  
  
(好地方，这学期去三次了，有几个商场很大，玩不完，东西很好吃)  
  
买柠檬水送的二筒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQiccVvNy4fuBkTrznlxhEeZ0PyMpwAWsfs4glJRsuIEiaetP96oLNTDGnQ/640?wx_fmt=png&from=appmsg "")  
  
  
咳咳，不扯远了  
  
当时就在商城玩的时候，心血来潮，上美团团搜了下店铺位置  
  
！！！！  
  
距离124m  
  
很难不去看  
  
直接找到一家店铺位置，悄咪咪的观察了设备  
  
扫描二维码下发指令处也存在漏洞，有机会在后面写文章讲  
  
然后花了200在店里diy了一下午  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQic0MmCaWjoMYlmJhnlQs5SQv5ClzokZDqoqmXVFHazSHZ28NmU1feJsw/640?wx_fmt=gif&from=appmsg "")  
  
没产出就算了，还贴了200，当然是不服气的  
  
观察店面  
  
前台存在一处暗房  
  
需要刷指纹，明显的进不去  
  
难道就没戏了嘛？  
  
突然有一个前台进去了，坐在电脑前，没关门！！！！！！  
  
发现前面的墙上面摆了大量商品，直接贴上去偷瞄  
  
直接用5.0的视力往死里瞅  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQic2ybsp8caXETfMSQSKa1HqPKicTAK6PAwqsjJh3VVicQWt8pp3OA7BpFg/640?wx_fmt=png&from=appmsg "")  
  
距离太远了，说看到url就是纯扯淡的  
  
但是看到了页面的UI  
  
狠狠的记住了界面的样式，次日回去直奔电脑  
  
在数百个站点里面找到了后台的地址  
  
登录框？  
  
爆破！！！！！  
  
无果..........  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicR18oXpQSrpWG2VpIwb0cMrxStb4Iyclu2NPDaEGDdFOdf0vSBwmnrA/640?wx_fmt=gif&from=appmsg "")  
  
太燃了哥们，悄咪咪的告诉你，我记住了店长的工牌  
  
之前挖到了一个sql，找到姓名对应的表，在其中找到一个用户的列  
  
直接把所有的账户名抓了下来，狠狠的喷洒密码，势必要轰出弱口令  
  
功夫不负有心人  
  
超管，管理，店长，财务，店员....  
  
极多的账号都没有轰出  
  
爆破出了一个测试账户，权限极低  
  
最难受的是，html的界面是由权限返回的，连测试的接口都没有  
  
都到这一步了，当然是不服输  
  
用赛博女保安姐的一句话：越权是程序员的原罪  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicCP9Vicmz39HxVTVVHvqjeeYFWjKJ9CCncP0p3Vvm41zeDCAu3p8ORLg/640?wx_fmt=png&from=appmsg "")  
  
经过测试，发现存在一处功能点：  
  
注销  
  
分析接口/user/logout  
  
很常规的猜测  
  
/user/list  
  
直接列出所有人的身份信息  
  
太棒了，又是一个没鸟用的漏洞，都有sql了  
  
拓展一下思维  
  
猜测接口/user/edit  
  
返回包为空状态码为200  
  
再猜测接口/user/editasdfjiuoasdhfiouashdfioasdf  
  
返回包为404  
  
确认存在接口/user/edit  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicGK5uyjnWt982FWKGea7bHm62Z3egLicLmrBGFKZEAV3R8tL5gINowfg/640?wx_fmt=gif&from=appmsg "")  
  
post请求  
  
啥信息也没有，接口是我猜出来的，没有任何传参  
  
爽了，没完全爽  
  
但是好歹有点头绪  
  
直接在yakit的history全局查找路径/list  
  
发现存在一处/goods/list  
  
列出商品信息  
  
火速在页面中定位到功能点  
  
在查找后，对于商品信息有着编辑功能  
  
编辑？这不巧了  
  
抓到他/goods/edit的包内容  
  
制作一个相仿的json请求包  
  
耐心的逐步猜测payload  
  
最后成功利用参数passwd设置账户密码  
  
开发加鸡腿，虽然管理修改用户密码很常见  
  
我们一跃到管理账户，接管所有店面设备  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/WSO4EkOYO5VH7wiaEIBOwBksJzQvMBzQicYhvA6PVjYeUosAYtzxEKuic4hxEs6rBjgjQbsHse6VvrjS0uzVYM7tA/640?wx_fmt=gif&from=appmsg "")  
  
  
篇幅太长了，0day的挖掘过程就留在下次了  
  
  
php审计，怎么节约时间精力快速产出  
  
  
碰到系统怎么去获取源码  
  
  
  

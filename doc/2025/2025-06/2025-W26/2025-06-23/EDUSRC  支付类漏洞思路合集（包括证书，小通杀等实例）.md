> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247550548&idx=1&sn=5d090a175300dfc30b660bba80a88403

#  EDUSRC | 支付类漏洞思路合集（包括证书，小通杀等实例）  
原创 zkaq-badland  掌控安全EDU   2025-06-23 04:00  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  badland 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
  
# 前言  
  
**文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担！**  
# 原因  
  
众所周知支付漏洞基本都是逻辑漏洞，此类漏洞往往思路比较多，而且支付漏洞在edusrc中起码都是中高危，rank自然不会低，小编先总结一下造成的原因把：  
1. 1. 大部分都是参数验证不足，支付金额等参数在传参过程中未进行加密或者编码加密过于简单，未与数据库记录比对，攻击者可修改数据包中的参数（如价格、数量）以绕过支付逻辑导致很容易被篡改金额参数等数据  
  
1. 2. 然后就是可能存在接口安全缺陷，导致某些敏感信息泄露，支付接口暴露订单号、价格等关键信息，且未加密传输，使得攻击者可截获并篡改数据  
  
1. 3. 最后基本是权限控制不严，普通用户可能通过接口越权修改订单信息或支付状态，系统设计缺陷，流程控制不严密，支付流程（提交订单→生成订单→付款）各环节间缺乏有效验证，攻击者可篡改中间步骤的数据，异常处理不足，系统未正确处理支付失败或异常订单，导致逻辑漏洞被利用等  
  
这里注意edusrc中的支付类漏洞需要支付并且产生有效订单，报告里必须提供相关依据和订单哦！  
# 思路  
  
总结以下：  
1. 1. 抓包直接修改价格，运费，小费，积分，优惠券，商品编号，币种，订单号，支付状态（注重**参数**  
）  
  
1. 2. 修改商品**数量**  
，改成负数/小数  
  
1. 3. 价格中添加或者前移**小数点**  
，  
  
1. 4. 价格**溢出**  
，价格四舍五入，优惠或者退款**并发**  
  
1. 5. 用他人钱，id卡，积分（**越权**  
）  
  
技巧方面：  
1. 1. 注重整个支付流程，可能前面几个包只是验证用户信息（虽然存在商品金额或者商品号不用修改），但实际订单支付最后存在修改支付价格的漏洞，整个流程都尝试抓包修改，敢于尝试，不要嫌麻烦  
  
1. 2. 可以看看最后的支付接口，说不定改成一个不存在的支付接口，如果没有进行严格验证，你会发现直接支付成功  
  
1. 3. 抓包订单中的参数敢于去猜，说不定有些补贴金额，减款金额，优惠金额等  
  
1. 4. 替代支付，生成两个商品订单，商品不同，订单价格不同，如果后端没有相关验证，直接抓包替换成另一个订单的订单参数，你会发现最后支付金额变成了另一个商品的价格  
  
1. 5. 有一些支付成功的请求包可以反复重放提交，说不定重复支付可以生成不同的订单号，或者说支付时，多线程请求确定付款，如果余额为负，则说不定存在条件竞争  
  
1. 6. 并发漏洞，burp插件Turbo Intruder测试，漏洞产生的位置：领取优惠券、使用优惠券、积分领取、抽奖、转账、提现、下单、限购、签到、点赞  
  
1. 7. 小数点四舍五也可以试试，0.009=0.01，0.019=0.02，0.099=0.10，我们支付前者，但系统提交后者  
  
1. 8. 优惠券或者优惠id可注意，尝试可以反复使用，或者有些特价限购商品号可以重复支付  
  
1. 9. 修改支付类型，paytype=数字，可以尝试fuzz，说不定直接免支付  
  
# 实例  
  
小编也是近半年才开始挖呀挖，所以下面的漏洞也是近半年的，还算是比较新，有些师傅总以为这种没啥难度的逻辑洞早就被挖没辣，实则不然，耐心一点总会有收获  
### 某学校文创商店  
  
选好商品提交订单时抓包，修改请求包的数量prodcount，可设为负数，也可加小数点，然后放行可生成订单  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYmz5K6tocGHZAgiaFZqKUkLHp7s1BmK36d82LNRpKZ7ppGWDypEAwkQQ/640?wx_fmt=png&from=appmsg "null")  
  
  
直接改成了数量为负数的订单，我记得当时价格改不了，存在验证，但是商品数量可以为负数，一为负数，总价直接变成一分钱，应该是该程序的支付最小值，这也是小编第一次挖到支付漏洞捏  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYVeEOxibBLibMff63BzqKqa7GGV2P8F57LBb2CG9MKz3Imrx2gDOGgWJQ/640?wx_fmt=png&from=appmsg "null")  
  
  
数量可为0，但要运费  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYNlXZEzRicHLsgO7Ic66XtxHPhYl7l8fLEqkaAc0rJWa0Phumy7QECPw/640?wx_fmt=png&from=appmsg "null")  
  
  
最后注意一定要支付成功，截取支付订单才算，第一次挖只敢申请中危，但一般来说都是高危  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYF8ShlhhE8JYdLIHlQsrqkrEyPv2OLP8ibZao7c5S0f9mHmicP8vyib1Jw/640?wx_fmt=png&from=appmsg "null")  
  
### 某大学证书站1（当时挖的时候不是，后面上证书了，算是捡了一个）  
  
前面一样的填信息，然后选项目提交订单  
  
发现可直接修改money，可修改任何大于0元的金额  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYBNgnrkUNVqdfgjEdRP5Uia5OJJibOz4L5mG8kTVE8v8rcKT3I6ozPGtQ/640?wx_fmt=png&from=appmsg "null")  
  
  
当时感觉金额挺大还不敢支付哈哈，所以分就有点低  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYoA6EYz7L3fy5JS75uMWCXa5WlTCWdRFvm2ib0tCbthBR47ObyUz4zqQ/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYibBBVPy4KIQiajLrZkQTAEtufy89icnwywKLdCQuPfhEJySRRPia9nTMfg/640?wx_fmt=png&from=appmsg "null")  
  
### 某大学证书站2  
  
说实话是本校学生，我老早就注意到了此处的赠送金额，开始挖洞后也尝试过，但是发现bp抓不到最后支付的请求包，最后才知道必须要手机端才能抓（小程序很多都必须要手机端才能支付）改改代理连连热点就行了，不会记得网上搜搜  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYsLatPnibgOkf4SHpSzQBJR1zH4Er0ibd91T0NfYW2WiajptKxXAUWft3g/640?wx_fmt=png&from=appmsg "null")  
  
  
这里注意这两个参数&totalSubsidy，&charge  
  
&totalSubsidy翻译可知这是补贴金额，尝试后可以直接改成正数（是直接额外赠送给你的补助金额）  
  
&charge这可以理解成是优惠金额的参数，可以改成负数，直接在付款金额上进行优惠  
  
这是当时一点点试出来的，毕竟就算多充了学校也可以用嘛，所以师傅们可以大胆猜一猜参数涵义  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYyT34LjsQ6MspdiaDXBkmSFYutPY3vIRCE5P18icHETibNAfBpibgzOzApQ/640?wx_fmt=png&from=appmsg "null")  
  
  
最后支付了1r，实际充了10r，因为会额外送5r的补助金额  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYxsAibrjHY5lxZTH2uXV1RhdnckEVZCmW97ZCb89TxOStwueBbEfZrnw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYzQKcqcetVCIibx0AotsHeZwU3ibLsCXGgicLwqB3K7DwIRC0TD3YzQjmg/640?wx_fmt=png&from=appmsg "null")  
  
### 某学校水电系统小通杀  
  
前面一样的填信息，选房间绑定，然后选金额提交订单  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIY8mLQA57beoGz13icDLNyyR78JAGHxzib9u2rwypLFClr3BA4ohNhk1DQ/640?wx_fmt=png&from=appmsg "null")  
  
  
支付程序比较繁琐，这里你会发现超级多的请求包，于是我一个一个请求包去尝试，发现前面的请求包全部都有验证，根本改不了一点，有些甚至加密了，正当我准备放弃时，最后却弹出来一个新的支付页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYKqVWF49eklGH8iaypQibDXNLia3jVDEK4BPMoycWXG4oUuxscOWcrKIdg/640?wx_fmt=png&from=appmsg "null")  
  
  
此时拦截你会发现此请求包甚至连订单号都生成了，但他依然可以修改支付price金额，甚至没有加密，果断修改放包最后支付成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYNaNd4Tu2tz8iah2moAiawweTicOukv34K8dYj4Aj9QX4Uzs3hBsAq3JtQ/640?wx_fmt=png&from=appmsg "null")  
  
  
还好有点小耐心，因为是学校小程序不太好找哈  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYnt24Ym8AY3wn7rmdUrEfI9jYLyjh0GHHdSxFiadG5ZXdqtl2ArhsCxw/640?wx_fmt=png&from=appmsg "null")  
  
### 某学院缴费系统  
  
因为没修复直接码死了  
  
给大家看看请求包，因为最好找的是固定金额的缴费，大部分学校那种交水电费的系统都是可以任意金额的充值，感觉改不了一点，请求包充值的price就是你充值的钱  
  
这里其实也是运气好，一眼看出了处理数据是base64解码，直接解码后修改即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpD40PLHLibAAxYpJzA8dLIYSEm0BSpV6nDSu6BepibzmvovlqB9yWGolMG7GX7Gomwuscia83MtTFgg/640?wx_fmt=png&from=appmsg "null")  
  
# 结语  
  
其实支付类漏洞没啥操作难度，这里实战你会发现小编很多思路没用上，都收获不小，因为是EDUSRC，大部分学校没啥商店那些，不过相信各位师傅以后在其他SRC上能遇见，感谢师傅们赏脸！  
  
   
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**没看够~？欢迎关注！**  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+交流群+靶场账号**  
哦  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******分享后扫码加我！**  
  
**回顾往期内容**  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[重生HW之感谢客服小姐姐带我进入内网遨游](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247549901&idx=1&sn=f7c9c17858ce86edf5679149cce9ae9a&scene=21#wechat_redirect)  
  
  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  

#  SRC漏洞挖掘之评论区CSRF   
 迪哥讲事   2023-11-28 19:50  
  
****  
**评论区CSRF1**  
  
**入手点为某资产个人中心修改头像处：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MOo8PzZ1YbE5iawia50pAhaKN6eLN5qyFplvRoE0EeibLPNEKoqSfnjbsEdgQ5SMlsggCJA2d8G2aLGA/640?wx_fmt=png "")  
  
**下面这个数据包发现头像参数url可控：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MOo8PzZ1YbE5iawia50pAhaKNrLhPwHB2kaIvMEwNdYqHZKKJEWXuLquLcReYhweCcoibX6lLqiam37Tg/640?wx_fmt=png "")  
  
**在url前加上登出payload：**  
```
xxxxx.xx.com/server/api/user/logout#
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MOo8PzZ1YbE5iawia50pAhaKNrLtW2d5jMOhumlRW8eFCP4aLPjF7facVsnCXT2YKWEuM7LAOT8kvzw/640?wx_fmt=png "")  
  
**然后使用A账号访问B账号评论过的文章：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MOo8PzZ1YbE5iawia50pAhaKNGNZibXWBicOJU5JcNZ2lqfDrvc1dUCcdNIZiczaSn6PexzDb6YTcq6UGg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MOo8PzZ1YbE5iawia50pAhaKN0cQp0eSlhG86Ut3fKP4UZTf1tHDictTibRmBNjicibmhHDjz5oSbYLy1Uw/640?wx_fmt=png "")  
  
**可以看到已经加载了登出链接。**  
  
**评论区CSRF2**  
  
**入手点为评论区：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MOo8PzZ1YbE5iawia50pAhaKNPd0gmopUylIdw5mEuiaDq8BgJvnM3TQD6iaxmCFTyoDfw7II1P7p4eTg/640?wx_fmt=png "")  
  
**登出payload：**  
```
<img src=https://logout>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MOo8PzZ1YbE5iawia50pAhaKNer1iawspOib97qPrPW7tVtlLibaGb85OlUAVhvMccvaq0mFN0IibeU3VXQ/640?wx_fmt=png "")  
  
**可以看到已经插入进去了，刷新一下页面：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MOo8PzZ1YbE5iawia50pAhaKNtlvQIgCSD2f6YIFjb2QXj7KBletwGEu6XLWZ2qiaxibkuicsTicZL9z2rw/640?wx_fmt=png "")  
  
**可以看到已经加载了登出链接。**  
  
**如果你是一个长期主义者，欢迎加入我的知识星球(优先查看这个链接，里面可能还有优惠券)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款**  
  
****## 往期回顾  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
## 福利视频  
  
笔者自己录制的一套php视频教程(适合0基础的),感兴趣的童鞋可以看看,基础视频总共约200多集,目前已经录制完毕,后续还有更多视频出品  
  
https://space.bilibili.com/177546377/channel/seriesdetail?sid=2949374  
## 技术交流  
  
技术交流请加笔者微信:richardo1o1 (暗号:growing)  
  
****  
****  

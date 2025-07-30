#  【0 day】鸿运主动安全监控云平台存在任意文件下载漏洞   
 迪哥讲事   2023-10-14 21:39  
  
# 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54jWmTQ7yqAdbacsBYh59FkXSzDzOKVicicXDTww4u6tCWtXlknOiaNEmng/640?wx_fmt=jpeg "")  
# 一、漏洞描述  
  
  
深圳市强鸿电子有限公司鸿运主动安全监控云平台存在任意文件下载漏洞，攻击者可通过此漏洞下载敏感文件信息，获取数据库账号密码，从而为下一步攻击做准备。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7fgxqcxvWqRzx9iaYicR4kzmdqgPuzsvmickZZ1sWlCN1VfTXQ8OaDQKXhPlJo06n72vP4srfbPgo9A/640?wx_fmt=png "")  
  
# 二、网络空间搜索引擎查询  
  
  
fofa查询  
```
body="./open/webApi.html"
```  
  
# 三、漏洞复现  
  
  
例：读取数据库配置文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7fgxqcxvWqRzx9iaYicR4kzmoqsaEkQuRaVAKOHdibZPGFJmUyQucoePqJL78BGaysxu0sgX1v4FN1A/640?wx_fmt=png "")  
# 四、批量检测与利用  
  
  
单个检测  
```
python .\ReadFile.py -u http://ip:port
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7fgxqcxvWqRzx9iaYicR4kzmLBLMjAZ4SYpU6rm627ECEsTUyPqiaMIbhHJn2dIuZBHpSicicptQUVe6A/640?wx_fmt=png "")  
  
  
批量检测  
```
python .\ReadFile.py -f  filename
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7fgxqcxvWqRzx9iaYicR4kzmmRV51gyHWXuFeGlibmibynPCodgZ7Txia5I8Ekd4DCYMzY3OR5oPic5lDw/640?wx_fmt=png "")  
  
**回复20231014可以获取脚本**  
  
****  
  
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
  
  
  

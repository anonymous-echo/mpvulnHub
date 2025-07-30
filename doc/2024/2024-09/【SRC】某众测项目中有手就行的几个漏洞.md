#  【SRC】某众测项目中有手就行的几个漏洞   
 Z2O安全攻防   2024-09-04 21:43  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
### 1、多处存在水平越权漏洞  
  
点击地址管理，抓包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8ZNa38TGkEmdZSwMvCf7ibql0jOQeLTJPvwc55Irgbvo9xUHib7HzfRzg/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904212923246  
  
遍历userId即可  
  
例如改为2206：（当前用户为2207）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8S1uhfawHKlibYcoTLR6P2DgH9Is56TcqEndhZFy2HxraWhASI6PDrMg/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213010799  
  
个人资料处：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8NUI7ckwljSiczm0rxHNtwoYynmqGCRI9P50NkMY41Vbhrj2iamWP7yfw/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213031138  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8eWHMwyticB3sTMRKHUNzmd3twC2jTiaJjFQ0GicfrPu3BRpOpcnPYibaicg/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213103203  
### 2、任意手机号绑定  
  
点击完善资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8pdicFTefmXNia3iaZLELSNl55sAPrS0tVRm5IrRLIPOib9BszdJjguWxbw/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213131444  
  
点击获取验证码，抓包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8vhIzoN4rCic85rU5Dfop0xnFLErMic3w2rIX85VqmmeYlds2oHDP9p0w/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213200034  
  
验证码显示在返回包中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8LBBlxO71o8CSiaEsMBXzbIZ9IPKMZC7FzOkWC8BfHviaGdEKvnyBibpxw/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213215011  
  
输入验证码提交，成功绑定：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8eeKnRd8AibbfHwWliapQRsMRd0HpJ4RVaQicZG939QzR5ral9MPP0P7yw/640?wx_fmt=png&from=appmsg "null")  
  
image-20240529105108433  
### 3、SQL注入  
  
挂上burp，访问首页  
  
会加载如下数据包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8LFvejy4FAR9Sk88pTouFuwrW3FrUeia5hEMsiaAatQlkJJlFUHdEGKQQ/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213656790  
  
发送到repeater , 拼接sql语句，可以发现存在注入：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8ktKiclRJibtvfxuWbciaicQCjgbzNr1oYLXjC7tFbwrDEZ1ztkofuqGFiaQ/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213536554  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8nCke3S7D61cnxeUVAM8ib0EqpE1mS31qUKniajolHQRe55QFzxwVMibVQ/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213557735  
  
通过报错注入获取数据库版本：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8INUFjmZuQuDQBfBbWttvGicPr1LYMicCPJAHWIV9vT2iaA4b980A4aoibA/640?wx_fmt=png&from=appmsg "null")  
  
image-20240904213619460  
### 4、  
  
建立了一个  
src专项圈子，内容包含src漏洞知识库、src挖掘技巧、src视频教程等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例  
  
2、分享src优质视频课程  
  
3、分享src挖掘技巧tips  
  
4、小群一起挖洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuYibiaSVoU6JrMTQOaJtjVwjic48bP80nsb3nk52NkhoCPd8Rxicibma7J9wJRZHkJElKpOIfXaK0ia0JqA/640?wxfrom=12&tp=wxpic&usePicPrefetch=1&wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8SJxJJnibwZZ90X2lqa5Vz6hSDmZGic05icehib38Po1JsHd1uyahmC9mAA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYODY5bOdObv8wfzFQ52oz8ETvmJHX0UAk8pD3Z0OLU1veCNXpPhgGMvhas7wAz9eYjAicJiaCYJYng/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuYibiaSVoU6JrMTQOaJtjVwjicgaTVSpKN5VzczX01QicLP2S7aKYcWGZ73pjXqOUm12z5wlLGCDNQXJw/640?wxfrom=12&tp=wxpic&wx_fmt=jpeg "")  
  
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**书籍****" 获取  网络安全书籍PDF教程**  
  
**回复“**  
**字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档合集**  
  
****  
点个【 在看 】，你最好看  
  
  

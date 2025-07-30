#  api漏洞挖掘   
 迪哥讲事   2025-04-21 12:24  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4183  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkPyjiaVpaz5BKkFiaZRlT44HLpWkTkp77YJVib1O0ulhP3j7ySaXgSfzvFKnPiaobVamjVibjuYa9LiccQ/640?wx_fmt=png&from=appmsg "")  
  
  
“不是总想着找突破口,有时，是在找他们忘记上锁的东西。”  
# 什么是隐藏的 API ？  
  
🚫 未记录（不在 Swagger 或公开文档中）   
  
👻 过时的（由旧应用或开发面板使用）   
  
🤫 被遗忘（意外留在生产环境中）  
  
**为什么它们很重要？**  
  
✅ 常常缺乏身份验证   
  
✅ 绕过现代安全控制   
  
✅ 可能泄露敏感数据   
  
✅ 很少被‘白帽’测试  
# 我是如何找到那个被遗忘端点的  
##  被动侦察   
  
通常通过waybackurls 、 gau 、 hakrawler 和 github-dorking 开始：  
```
cat domains.txt | waybackurls | tee all_urls.txt
```  
  
然后过滤掉类似 API 的端点：  
```
grep "/api/" all_urls.txt | sort -u > api_endpoints.txt
```  
##  高级技巧（大多数'白帽'都会错过这个）：   
```
grep -E "v1|v2|internal|beta|admin"
```  
  
这些版本或内部端点通常保护较弱。  
##  寻找旧APP或 JS 文件   
  
可以通过诸如 APKMirror 上搜索了旧历史版本的 Android APK，使用 jadx 打开。  
  
可以在 Java 代码中找到了一些硬编码的有趣端点。比如：  
  
https://api.targetsite.com/v1/user/details_internal  
  
大多数开发者会忘记关闭在旧版APP中使用的 API，始终检查 APK 文件和 React Native 包。  
##  尝试访问端点   
  
可以利用 Burp Suite 配合 Curl：  
```
curl -X GET https://api.targetsite.com/v1/user/details_internal -H "Authorization: Bearer <token>"
```  
  
比如上面这个端点它甚至没有检查Token，就有了响应包。  
  
包含了完整用户信息，包括：  
- 姓名  
  
- 邮箱  
  
- 内部状态  
  
- 角色 等等  
  
API 还可以显示任意用户 ID 的敏感信息：  
  
https://api.targetsite.com/v1/user/details_internal?id=1001 https://api.targetsite.com/v1/user/details_internal?id=1002   
  
...  
  
这意味着任何人都可以在不登录的情况下爬取整个数据库。  
  
最终，白帽小哥收获 500 美元赏金奖励。  
  
你学到了么？  
  
原文：https://infosecwriteups.com/uncovering-hidden-apis-how-one-forgotten-endpoint-made-me-500-424e6388c406  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
  
  
往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
[‍](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
  

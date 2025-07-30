#  [含POC]紧急测试!PHP CGI Windows平台远程代码执行漏洞爆发!   
原创 网络安全自修室  网络安全自修室   2024-06-11 19:15  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lFubSBSogFqgicIHO1h77GiafPiaUPNMaqGFbhlVt4xgfibicIs2HQl7fUgltjzDdMtOWLmXcfiaticRwYHA4qohl55xA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/B2EfAOZfS1j0P2KhxNF226xt1M5SKuS7QzH64vfmiaqnJhbmgxWLlxDRYgE1SXmgvZ9F0wgFmibBHsIJgR9DX0ibndoby6FWbK3/640?wx_fmt=svg "")  
  
点击上方  
蓝字关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/I1YzhXxW8YCmS3UnN2FuDSNMViapCreWzUpaL8YgOTzLHsLIYzEicsNaJxrXpegibgFtSZHaros5M4C9NkMOFh7aiaEtbQoQibiaqH/640?wx_fmt=svg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lFubSBSogFqgicIHO1h77GiafPiaUPNMaqGFbhlVt4xgfibicIs2HQl7fUgltjzDdMtOWLmXcfiaticRwYHA4qohl55xA/640?wx_fmt=png "")  
  
  
1  
  
  
免责声明  
  
        
本公众号提供的工具、教程、学习路线、精品文章均为原创或互联网收集，旨在提高网络安全技术水平为目的，只做技术研究，  
谨  
遵守国家相关法律法规，请勿用于违法用途，  
如果您对文章内容有疑问，可以尝试加入交流群讨论或留言私信，如有侵权请联系小编处理。  
  
  
  
2  
  
  
内容速览  
  
  
## 0x01 前言  
  
**声明：本文提供的信息和工具仅供学术交流和教育目的。****我们强烈反对任何形式的非法测试行为。读者若因使用、传播本文内容或工具所引发的直接或间接后果和损害，需自行承担全部责任。文章作者不承担任何由此产生的法律责任或连带影响。请您在遵守法律法规的前提下使用本文内容**  
## 0x02 漏洞描述  
  
在PHP语言的设计过程中，未能充分考虑到Windows系统内部对字符编码转换采用的“最佳匹配”（Best-Fit）机制。特别是当PHP部署在Windows平台，并处理如繁体中文（代码页950）、简体中文（代码页936）、日文（代码页932）等特定语言环境时，存在安全漏洞。此漏洞为攻击者提供了可乘之机，允许他们通过精心构造的恶意请求来规避CVE-2012-1823的安全措施，进而通过参数注入等手段在受影响的PHP服务器上远程执行恶意代码。  
### 利用条件：  
  
1、用户认证：无需用户认证   
  
2、前置条件：默认配置   
  
3、触发方式：远程  
## 0x03 影响范围  
  
PHP 8.3 < 8.3.8PHP 8.2 < 8.2.20PHP 8.1 < 8.1.29  
## 0x04 资产测绘  
- fofaapp="XAMPP"  
  
- 特征  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CJmsUqkbd34sgiafVfLYp5Dias9QwNadTXWWp3MZtNWpMcR5GsTNJ92DVBPxKrbO3AiaiadrlFpp5whw5VOhWemPbA/640?wx_fmt=png&from=appmsg "")  
  
o1szx  
## 0x05 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CJmsUqkbd34sgiafVfLYp5Dias9QwNadTXsicVicqZuM8MrwAv04k5XjHVyOwqkv4tBllzpsT4WtsFqXRbbKlXv38w/640?wx_fmt=jpeg&from=appmsg "")  
  
o4ryj  
### 0x06修补建议  
- 更新到PHP官方发布的最新PHP版本  
  
- 如无法更新建议编写Rewrite 规则阻止攻击  
  
> 注意：**此份规则只作为繁体中文、简体中文及日文语系中的暂时性缓解机制，建议以更新版本进行修复**  
  
```
RewriteEngine On
RewriteCond %{QUERY_STRING} ^%ad [NC]
RewriteRule .? - [F,L]

```  
  
  
3  
  
  
获取方式  
  
测试POC获取  
  
  
关注公众号，回复如下消息获取  
  
口令：20240611  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MiboTSicicER4Eu7bB0t77eQS4XrwHJicY59XmxRFM03aTILrkecux30UkrUeSkUiajAiaezO5OyxJ7l3CQiaQtDgMuxg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CJmsUqkbd36pMnUu9lMvf40F3JN5FUKOSrpHCAw9seVEGicB71ibdv5ibQYGjJhm9jjwsQicqpudhktuEib9nJwuRAg/640?wx_fmt=png "")  
  
  
如果想要系统学习网络安全技术  
  
不妨加入知识星球课程**《60天入门网络安全渗透测试》**  
  
从入门到案例，贴合实战  
  
轻松易懂、好玩实用  
  
限时领取  
  
[超值 | 一起学网络安全! 授人以鱼不如授人以渔!](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247496309&idx=1&sn=14e7e4ef7429582856b49a7a7f8dded9&chksm=e959a45ade2e2d4ccfaf1f149e46fc0f31822497baafaae90bcbedf3aff7d28271449a314126&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NuIcic2jibgNJzwoZYCo6ThfOoeX410mwuDxnOnv5za18VZJ7ib30pic2NSNnicziaONicvs1C9yMDr6zV40ADD9yPP7Q/640?wx_fmt=gif "")  
  
**知识星球**  
优惠券****  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CJmsUqkbd35TZpQbIich3DEsfKIZRLKYkjg2ZdsVOczf0CSg4gqI01aqpPFocwdmr912KMJDd85tics46QqYTBiaw/640?wx_fmt=png&from=appmsg "")  
  
  
跟着[60天路线（点我查看）](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247485451&idx=1&sn=5bc1f942ce151ba3bfc623dd2dd9c7d8&chksm=e95a5e24de2dd732f9b03547ebe7b7e5860c1fe5bfc0696e477bfdefbdb07db8d5baf830421f&scene=21#wechat_redirect)  
  
一起学  
  
期待你的到来！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaYxOy5X8RGxPAZqiaRBGicib19NaYicn41YO87QVc5QTGjGS7CtO8ibNmedthqbBFX4Kfd0XKC5tObg07A/640?wx_fmt=png "")  
  
  
往期推荐  
  
  
  
[从入门到入狱的技术，可以学，别乱用！](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247485451&idx=1&sn=5bc1f942ce151ba3bfc623dd2dd9c7d8&chksm=e95a5e24de2dd732f9b03547ebe7b7e5860c1fe5bfc0696e477bfdefbdb07db8d5baf830421f&scene=21#wechat_redirect)  
  
  
[网络安全学习方向和资源整理（建议收藏）](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486161&idx=1&sn=a59ad5f5ea0d8d4a73c5d56c49240ef7&chksm=e95a5cfede2dd5e835df2a06dadf1ea764ad17c896bd7e36a7ce4db543162ff436c6e7e8818d&scene=21#wechat_redirect)  
  
  
[一个web安全工程师的基础学习规划](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486067&idx=1&sn=7fc31c310c8990eff8507cd9ef8f57b8&chksm=e95a5c5cde2dd54a8ea5836fb918a2e75920b9d49427bbf0ba6e7d1551cbf854f1c758999701&scene=21#wechat_redirect)  
  
  
[资源 | 渗透测试工程师入门教程（限时领取）](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247485910&idx=1&sn=bc4011a1dbae5a578e778f225c6396cd&chksm=e95a5ff9de2dd6ef2c9f2b7aaf8cc27d4b01b49d52134edc34985e8068c3f5b91d130217309f&scene=21#wechat_redirect)  
  
  
[5年老鸟推荐10个玩Python必备的网站](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486066&idx=1&sn=ebebc764ff820a9ad39ca3bc76315627&chksm=e95a5c5dde2dd54bb8dca6f0c156d6dc27c86963b5d4021fc120b143e97f6087c800b8965796&scene=21#wechat_redirect)  
  
  
[推荐十个成为网络安全渗透测试大佬的学习必备网站！](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486441&idx=1&sn=ef05f9f88c27f38bc95338f6c6739d0f&chksm=e95a5dc6de2dd4d084fa141bd69c3ad173b565cd78ac3d4fcad2bc491b7722a6af0653fd3650&scene=21#wechat_redirect)  
  
  
[那些社工师不为人知的秘密。。。](http://mp.weixin.qq.com/s?__biz=MzI0NDYxMzk1Mg==&mid=2247486187&idx=1&sn=ea79686a707d97c8e97ac131441bf6b5&chksm=e95a5cc4de2dd5d2b06da67a6c9a85c303265eaf8e83e78a6c28fcbc07c587c161693554ed18&scene=21#wechat_redirect)  
  
  
  
  
更多内容请关注公众号  
  
网络安全自修室  
  
▼  
  
回复:”  
网络安全入门教程  
“,领取系统网络安全学习教程!  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CJmsUqkbd36pMnUu9lMvf40F3JN5FUKOVgHppMwndKpVt9cicTibZIX4kd1MIhlE3hibJ8icfW3gibPnWKj5LL2TjEw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pzXcQtZJNFv2HrgJ7ZwMzgeB9QByfWTxydpkuOicXKlUjZp9HpFFlT50ibBdIicCSmkW2ibibJpb1M1d5aRe9MfcXbA/640?wx_fmt=png "")  
  
点个  
在看你最好看  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/sTJptKvBQLK8kA6B8BvyhLBiaicqchp7g1uS8Rv3VRyH7IOz0icMV5eoM23cyJWbicIaSjaxhABIbHvRp2736iaFcmicTq9GXganwC/640?wx_fmt=svg "")  
  
  

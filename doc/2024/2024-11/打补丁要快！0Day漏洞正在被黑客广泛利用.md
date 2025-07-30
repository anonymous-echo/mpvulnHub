#  打补丁要快！0Day漏洞正在被黑客广泛利用   
老布  安小圈   2024-11-18 00:45  
  
**安小圈**  
  
  
第547期  
  
**打补丁  0Day漏洞**  
  
****  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPBJwyIYSDk9B1QK8O1iaTEpcB2iauvfibr9duqiabUnDIWmdWERhGuBGniarCqRjj5JX1h4ytDbcOHcUA/640?wx_fmt=png "")  
  
  
近日，美国、英国、加拿大、澳大利亚和新西兰（五眼联盟）网络安全机构联合发布了报告，公布了2023年最常被利用的漏洞清单。  
其中，零日漏洞已经成为黑客最常利用的漏洞类型。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38kicxmSKeQw5hH5XX7P9Sn5gBHud6gWfQnW07uXdl6PtawdDlU5rM1u60QU3yAG8vfnWT1EXsq8UQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
该警告强调，攻击者们正越来越多地利用零日漏洞入侵企业，与2022年相比，零日漏洞利用的有所增长。  
  
与前几年旧的、未修补的漏洞占据列表的主导地位不同的是，在2023年漏洞利用趋势中，零日漏洞利用的激增，这反映出攻击者漏洞攻击策略的变化，即  
**在漏洞公布后的几天内快速利用。**  
过去，安全漏洞被利用或许需要几个月时间，但现在，发现与利用之间的时间间隔已经减少到了几天甚至是几个小时。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38kicxmSKeQw5hH5XX7P9Sn5tDbaKVQQIXcCFbQXT171c9g1aPzuU2xapM8YkPc6j7WMRg31OQBRNg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
报告另一个数据也指出，大量漏洞在披露后的两年内被积极利用，突显了及时补丁管理的必要性。  
  
在发布的2023年漏洞利用榜TOP15中，CVE-2023-3519漏洞位居榜首，该漏洞影响NetScaler ADC和NetScaler Gateway的多个版本，包括13.0、13.1、13.1-FIPS、12.1-FIPS和12.1-NDcPP等，在修补期间被广泛利用，导致了大量的设备被攻陷。  
  
CVE-2023-20198是另外一个排在前列的漏洞，影响Cisco IOS XE系统中的Web管理用户界面，允许黑客获得设备中最高等级的Level 15权限，从而可以完全控制相关设备，执行任意命令。  
此外Log4Shell漏洞（CVE-2021-44228），影响Apache的Log4j库，由于其广泛应用于各种软件应用中，即使在最初披露两年后仍然被利用。  
  
Tenable的高级研究员Satnam Narang表示，“入选2023年最常被利用漏洞榜的漏洞有一个共同点，即它们都暴露于互联网服务或系统中，包括从VPN解决方案到远程管理界面。  
这些面向互联网的系统中往往会使用包含已知漏洞的软件，从而导致被黑客成规模利用。  
  
另外，在漏洞利用榜中最古老的一个漏洞是七年前公布的（CVE-2017-6742），即便是到了2023年，仍然有很多的黑客在利用该漏洞对企业发起攻击。  
而根据一些情报信息，仍有大约24,000个Cisco IOS和IOS XE系统可能面临CVE-2023-20198漏洞的攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbNFGhZSttuhIzVnNJAlxXcntzQT9TkmjBdPicssdjUB7XlDJeXtbFs8ygsmTkqbl0I1KWTgdmHh9Yg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
****#   
- # Windows 0-Day 漏洞-(CVSS 9.8) CVE-2024-43491  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247528131&idx=1&sn=ee17bfc91d1275e5a25a8ac88e775324&chksm=ce22397bf955b06dbab2cbeebf6a2f9ba2bb2e364f2651879c3b66d93a4cc9265c12c0cd0197&scene=21#wechat_redirect)  
- [腾讯【微信】存在可能导致远程代码执行【漏洞】](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247528131&idx=1&sn=ee17bfc91d1275e5a25a8ac88e775324&chksm=ce22397bf955b06dbab2cbeebf6a2f9ba2bb2e364f2651879c3b66d93a4cc9265c12c0cd0197&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247525096&idx=2&sn=d1467825e0d943445aa7437f8fa9916c&chksm=ce223550f955bc4687eab62af06027a266a6c7fd068413e62e7ca85aa51fa28bc16075b37201&scene=21#wechat_redirect)  
- [CVE-2024-7262（9.3）WPS【漏洞】已经被武器化](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247525096&idx=2&sn=d1467825e0d943445aa7437f8fa9916c&chksm=ce223550f955bc4687eab62af06027a266a6c7fd068413e62e7ca85aa51fa28bc16075b37201&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524771&idx=1&sn=fb1d9a27c4e29c56ccd88a5f981b2d8f&chksm=ce22361bf955bf0d27a75c950d19d6cbfcdf4b5796b9341aaa6551dc56cf046b2426a3c861ff&scene=21#wechat_redirect)  
- [微软披露：Office最新【零日漏洞】，可能导致数据泄露](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524771&idx=1&sn=fb1d9a27c4e29c56ccd88a5f981b2d8f&chksm=ce22361bf955bf0d27a75c950d19d6cbfcdf4b5796b9341aaa6551dc56cf046b2426a3c861ff&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524688&idx=1&sn=86e599b109e7188ccf652be2fd32b30b&chksm=ce2236e8f955bffef66fa55c274018570ce65982369f4760cb1a5250bbd8f7692b86b0a8222b&scene=21#wechat_redirect)  
- [【微软警告！】OpenVPN存在【漏洞】| 可能存在漏洞链](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524688&idx=1&sn=86e599b109e7188ccf652be2fd32b30b&chksm=ce2236e8f955bffef66fa55c274018570ce65982369f4760cb1a5250bbd8f7692b86b0a8222b&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524560&idx=1&sn=0ef4d3371f0d6374894ad5259e45ac63&chksm=ce223768f955be7e49bfe14375d3fb22a0718b0474ca42dbafe5c21c15047f40a57e8c82abf7&scene=21#wechat_redirect)  
- [【爆！】堪比Windows蓝屏危机！| Linux被曝12年史诗级漏洞，“投毒者”是谷歌？](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524560&idx=1&sn=0ef4d3371f0d6374894ad5259e45ac63&chksm=ce223768f955be7e49bfe14375d3fb22a0718b0474ca42dbafe5c21c15047f40a57e8c82abf7&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524560&idx=1&sn=0ef4d3371f0d6374894ad5259e45ac63&chksm=ce223768f955be7e49bfe14375d3fb22a0718b0474ca42dbafe5c21c15047f40a57e8c82abf7&scene=21#wechat_redirect)  
- [0.0.0.0 Day【漏洞】曝光 | 谷歌、Safari、火狐等主流浏览器面临威胁](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524229&idx=1&sn=46ad42b4a0f5f4d8a0cce1552ba62b7f&chksm=ce22c83df955412b3e8501a9ac056c1330bc269026a2366fedc91e8a5a5bd083ad650fe0eed9&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524025&idx=1&sn=d71c239f2b207cc5d31dd2ff74bf9ce2&chksm=ce22c901f95540172b025e9306778f4066cde3c6150400af01fe22a3e693845263944eefb4d6&scene=21#wechat_redirect)  
- [核弹级【漏洞预警】Windows 远程桌面 | 授权服务远程代码执行漏洞(CVE-2024-38077)](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247524025&idx=1&sn=d71c239f2b207cc5d31dd2ff74bf9ce2&chksm=ce22c901f95540172b025e9306778f4066cde3c6150400af01fe22a3e693845263944eefb4d6&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247520585&idx=1&sn=35cdaeef004b4615fb052326c8594c26&chksm=ce22c6f1f9554fe705c05a9534506a615cb539c264dd5a12cbbe7cedd831507503cd65936826&scene=21#wechat_redirect)  
- # 【0 day】阿里 NACOS 远程命令执行漏洞  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247520860&idx=1&sn=0b6114b76495de68dba79b87b520da16&chksm=ce22c5e4f9554cf2ae8ff183dcb6d7249d8ea9fb4244f5b1d8b9950b3d8035faf8e45ef2a03a&scene=21#wechat_redirect)  
- # 【盘点】最严重的39个硬件安全漏洞  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247519816&idx=1&sn=74414bf876b016b3efafca086603e4dd&chksm=ce22d9f0f95550e6234cffca5e7008763bf538a48deb8fd6e500060c7364075ea9975ab9a90f&scene=21#wechat_redirect)  
- # 如何防护0-day漏洞攻击  
  
#   
- # 【风险提示】OpenSSH 远程代码执行漏洞（CVE-2024-6387）  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247519305&idx=1&sn=7611fef93e007338b538c92d84cb717a&chksm=ce22dbf1f95552e76ab3441d0d4364fc1cb55ec1b199919ad13735577fc2f1e0e6d9cb34a75b&scene=21#wechat_redirect)  
- # 【漏洞预警】Apache HTTP Server 信息泄露漏洞  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247517435&idx=2&sn=f886ee4cac082229881224ea2f978c07&chksm=ce22d343f9555a556633469c8cf9a18ed91f34ea3c04f90939b9c9a120385f6e724990b5fa4d&scene=21#wechat_redirect)  
- # 红队视角！2024 | 国家级攻防演练100+必修高危漏洞合集(可下载)  
  
#   
- # 【干货】2024 攻防演练 · 期间 | 需关注的高危漏洞清单  
  
  
  
**【原文来源：FreeBuf****】**![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546866&idx=1&sn=efc6e9e0da5cb112c035c0489e1f580c

#  Nessus严重漏洞允许覆盖任意本地系统文件  
 安小圈   2025-07-02 12:08  
  
**安小圈**  
  
  
第699期  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbMMAicPhNGAMfKu1AWpxcPJdvBqdN3S5yFNRbxZ41t4F0DQaPWDFBxdVVPZnLYBPGwGL7sbS0icwiajw/640?wx_fmt=jpeg "")  
  
  
  
Tenable最新发布的安全公告披露了Nessus漏洞扫描器中存在的严重漏洞，攻击者可能通过权限提升攻击危害Windows系统。  
  
  
这些安全漏洞影响10.8.5之前的所有Nessus版本，包括一个关键的Windows特定漏洞(CVE-2025-36630)以及第三方组件libxml2和libxslt中的两个额外漏洞。  
  
  
**Part01**  
  
## 漏洞概要  
  

```
1、CVE-2025-36630
```


```
CVSSv3评分：8.4，
CVSSv3评分：8.4，
```


```
2、CVE-2025-6021
```


```
CVSSv3评分：6.5，
CVSSv3评分：6.5，
CVSSv3评分：6.5，


```


```


```


```
3、CVE-2025-24855
3、CVE-2025-24855
CVE-2025-24855
```


```
CVSSv3评分：7.8，
CVSSv3评分：7.8，
CVSSv3评分：7.8，
Nessus 10.8.4及更早版本，Nessus XSLT转换操作使用的libxslt第三方组件漏洞  
  
  
```


```






```

  
这些漏洞的CVSS评分介于6.5至8.4之间，对依赖Nessus进行安全评估的组织构成重大威胁。  
  
  
  
**Part02**  
  
### Windows权限提升漏洞  
  
  
最严重的漏洞编号为CVE-2025-36630，影响10.8.4 及之前版本的Windows系统Nessus安装。该高危漏洞使非管理员用户能够利用日志内容以SYSTEM权限覆盖任意本地系统文件，实质上允许权限提升攻击。该漏洞CVSSv3基础评分为8.4，属于高严重性级别，具有重大潜在影响。  
  
  
该漏洞的攻击向量被描述为需要本地访问且复杂度低(AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H)，表明攻击者需要低级别权限但无需用户交互即可利用该漏洞。影响范围标记为"已更改"，意味着该漏洞可能影响超出其原始安全上下文的资源。安全研究员Rishad Sheikh于2025年5月10日向Tenable报告了该关键漏洞。  
  
****  
  
**Part03**  
  
### 第三方组件更新  
  
  
除Windows特定漏洞外，Tenable还修复了为Nessus平台提供核心功能的底层第三方软件组件中的安全缺陷。该公司已将libxml2升级至2.13.8版本，libxslt升级至1.1.43版本，以修复已识别的漏洞CVE-2025-6021和CVE-2025-24855。  
  
  
CVE-2025-24855的基础评分为7.8，需要本地访问且攻击复杂度高，但无需用户权限(AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H)。  
  
  
CVE-2025-6021的CVSSv3基础评分为6.5，攻击向量需要网络访问和低权限凭据(AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H)。  
值得注意的是，针对CVE-2025-6021的修复已专门反向移植到Nessus 10.8.5中的libxml2 2.13.8版本实现中。  
  
  
  
**Part04**  
  
### 缓解措施  
  
  
运行受影响Nessus版本的组织应优先通过Tenable下载门户立即更新至10.8.5或10.9.0版本。漏洞披露时间线显示Tenable处理效率较高，在报告后18天内确认问题，并在初始披露约两个月后发布补丁。  
  
  
系统管理员应验证当前的Nessus安装情况，并在计划维护窗口期间实施安全更新。鉴于高严重性评级和权限提升的可能性，组织应将这些更新视为关键安全补丁，需要加速在所有基于Windows的Nessus安装中部署。  
  
  
  
**参考来源：**  
  
Nessus Windows Vulnerabilities Allow Overwrite of Arbitrary Local System Files  
  
https://cybersecuritynews.com/nessus-windows-vulnerabilities/  
  
  
  
  
  
END  
  
  
  
****  
****  
**【内容**  
**来源：FreeBuf】**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeeR4VInT56J0KCLD3HkiaRxjMLLV6rricOadHohJB1sOtPT02fETAxr4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
- [2024年网安上市公司营收、毛利、净利润排行](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
- [突发！数万台 Windows 蓝屏。。。。广联达。。。惹的祸。。。](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
  
  
#   
- # 权威解答 | 国家网信办就：【数据出境】安全管理相关问题进行答复  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247539649&idx=1&sn=8858b449c89d21240e1f522e92be4fbd&scene=21#wechat_redirect)  
- # 全国首位！上海通过数据出境安全评估91个，合同备案443个  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544405&idx=2&sn=a961d43ca4a9ed667fccbbab758d9196&scene=21#wechat_redirect)  
- # 沈传宁：落实《网络数据安全管理条例》，提升全员数据安全意识  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
- [频繁跳槽，只为投毒](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
- [【高危漏洞】Windows 11：300毫秒即可提权至管理员](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
- [针对网安一哥专门的钓鱼网站](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
- [为什么【驻场】网络安全服务已成为大多数网络安全厂商乙方不愿再触碰的逆鳞？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOYPldtHVUmKQJ2WtL12GUnHRyzBiaKosLNicTZ2QkDFSRPUha2Eiaqk8R5fPdXc75zxprkTRB0ib5hUw/640?wx_fmt=jpeg "")  
- [HW流程以及岗位职责](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=3&sn=97e6083dbfbdd896680e24770a10d319&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247543989&idx=1&sn=2821b91efdd626e1a38ec6b2b439186b&scene=21#wechat_redirect)  
  
- # 网络安全【重保】| 实战指南：企业如何应对国家级护网行动？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542929&idx=1&sn=8cf6f15ddca44e343a494eea0fa619b2&scene=21#wechat_redirect)  
- **DeepSeek安全：AI网络安全评估与防护策略**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542701&idx=1&sn=567674aa12d861c3561d453268badb91&scene=21#wechat_redirect)  
- **虚拟机逃逸！VMware【高危漏洞】正被积极利用，国内公网暴露面最大******  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542458&idx=1&sn=d81d049331d175a2176f0978d7f032a8&scene=21#wechat_redirect)  
- **挖矿病毒【应急响应】处置手册******  
  
****- **用Deepseek实现Web渗透自动化**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542225&idx=2&sn=244a465fab183f4fa91a284b92a920e6&scene=21#wechat_redirect)  
- **【风险】DeepSeek等大模型私有化服务器部署近九成在“裸奔”，已知漏洞赶紧处理！**  
  
****- **关于各大网安厂商推广「DeepSeek一体机」现象的深度分析**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
- [Deepseek真的能搞定【安全运营】？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540432&idx=1&sn=b9e7e6103e86b9966f29d7eacf8e3d1e&scene=21#wechat_redirect)  
- **【热点】哪些网络安全厂商接入了DeepSeek？**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540206&idx=2&sn=300737ad84f684e622fdde03da0fc1a7&scene=21#wechat_redirect)  
- **【2025】常见的网络安全服务大全（汇总详解）**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540343&idx=1&sn=59d6f592f71a7f1e3a18fd082aa3de40&scene=21#wechat_redirect)  
- **AI 安全 |《人工智能安全标准体系(V1.0)》(征求意见稿)，附下载**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMbfUY7RtO1t6ZAxjoibZoZ8DSVPU0yI9v2nXpiat0oN8eLia5jiaoWOhlib5GiaPWQJeCsUmShI4QOqaGg/640?wx_fmt=png "")  
- **2025年 · 网络威胁趋势【预测】**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbM09kF5tXEb8PRXicFibPic4un6rwDI2CBUxrVaDINuM8ChyotgWiag4icErAHniaYNYiccQiaVkyyJUTX13w/640?wx_fmt=jpeg "")  
- **【实操】常见的安全事件及应急响应处**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbMASB7RibZ1nezrias4SvtcqzjvsJJPXhFiceJPEoVHVLhI2Soolaf8OhWQOVafycOibiaclJkT7NgG4Nw/640?wx_fmt=jpeg "")  
- **2024 网络安全人才实战能力白皮书安全测试评估篇**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeOsnl5ayrQXc0wPVutL1dQXg7BugT7vAe8qkpfszTrlhUAq4DQZFaVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  

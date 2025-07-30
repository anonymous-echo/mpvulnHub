#  刷脸登录银行 App 现他人信息，银行回应称“网络抖动带来的极小概率事件”|Windows 曝9.8分漏洞，已有PoC及利用情况   
 黑白之道   2025-01-06 01:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**刷脸登录银行 App 现他人信息，银行回应称“网络抖动带来的极小概率事件”**  
  
  
1 月 5 日消息，据“潮新闻”报道，最近杭州市民魏先生却遇上了一件意外事件，登录某银行企业客户端时，刷脸刷出来的却是别人的账号。  
  
1 月 2 日当天，他和往常一样登录某银行企业客户端，准备查看自家企业的金融业务情况。魏先生很自然地使用了刷脸登录，在程序快速响应之后，他突然发现了不对劲 ——   
客户端内显示的个人信息并不是他的公司。  
  
为了避免发生纠纷，在留存证据之后，魏先生就退出了该账号。后续他多次尝试登录，再也没有发生过相同的情况。  
  
IT之家从报道获悉，1 月 3 日晚间，银行相关负责人与客户经理上门和魏先生解释了情况。  
  
据魏先生回忆，银行称这是  
网络抖动带来的极小概率事件，并表示客户端登录使用的是手机自带的刷脸系统，金融支付用的是另外一套银行的自有系统，可靠性、安全性更高。  
  
业内人士表示，无论是指纹登录还是刷脸登录，一般上都是调用“储存在手机本地的人脸或者指纹信息”，匹配成功之后，再自动填入对应的“储存在钥匙串内的账号密码信息”，完成登录操作后，打开账号密码对应的账户信息，“这过程中，  
如果出现网络抖动，是可能造成回传的账户信息错误的情况，但是概率很小。”  
  
而对于安全性要求更高的支付系统，一般的程序开发都会调用“微信、支付宝、ApplePay”等第三方支付的端口实现支付功能，银行客户端则会自行开发相关的支付系统，“逻辑上和登录是两个系统，登录对于人脸的识别精度也远低于支付系统的。”  
  
  
**Windows 曝9.8分漏洞，已有PoC及利用情况**  
  
  
  
SafeBreach Labs的研究人员发布了关于Windows轻量级目录访问协议（LDAP）的一个关键漏洞的概念验证（PoC）和漏洞利用方法，该漏洞编号为CVE - 2024 - 49112。微软在2024年12月10日的补丁星期二更新中披露了此漏洞，其CVSS严重性评分高达9.8。  
  
  
CVE - 2024 - 49112属于远程代码执行（RCE）漏洞，会对包括域控制器（DC）在内的Windows服务器产生影响。域控制器在组织网络里是关键组成部分，负责管理身份验证和用户权限等工作。  
  
### 漏洞影响  
> 1. 让未打补丁的服务器崩溃；  
> 2. 在LDAP服务环境下执行任意代码；  
> 3. 有可能破坏整个域环境。  
  
###   
### 漏洞利用技术细节  
  
此漏洞是由于LDAP相关代码中的整数溢出问题引发。未经身份验证的攻击者可通过发送特制的RPC调用来触发恶意的LDAP查询，成功利用时可能导致服务器崩溃或者进一步实现远程代码执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hnuTWHibJxjMK8l230CfqeJ6kHGmDFRdJSsWuicAqnkr515nbCUJCbdBSg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
SafeBreach Labs开发了一个名为“LDAPNightmare”的PoC漏洞利用工具，以此展示该漏洞的严重性。该漏洞利用按以下攻击流程可使未打补丁的Windows服务器崩溃：  
> 1. 攻击者向目标服务器发送DCE/RPC请求；  
> 2. 目标服务器向攻击者的DNS服务器查询以获取信息；  
> 3. 攻击者回应主机名和LDAP端口；  
> 4. 目标服务器发送NBNS广播以定位攻击者的主机名；  
> 5. 攻击者回复其IP地址；  
> 6. 目标服务器成为LDAP客户端，并向攻击者的机器发送CLDAP请求；  
> 7. 攻击者发送恶意引用响应，致使LSASS（本地安全机构子系统服务）崩溃并重启服务器。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hndRDrgjp6MDxibriaWicmSNj7RRL3RyzX4AOvibWbHeVEcTj9XOv3rA9PEg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
SafeBreach已经验证，微软的补丁通过解决整数溢出问题有效地缓解了该漏洞。所有未打补丁的Windows Server版本都会受到此漏洞影响，其中包括Windows Server 2019和2022。利用该漏洞可能让攻击者控制域环境，所以这会成为勒索软件团伙和其他威胁行为者的主要目标。  
  
  
建议组织马上采取以下行动：  
> 1. 立即应用微软2024年12月的补丁；  
> 2. 在补丁安装完成之前，监控可疑的DNS SRV查询、CLDAP引用响应和DsrGetDcNameEx2调用；  
> 3. 使用SafeBreach的PoC工具（可从GitHub获取）来测试自身环境。  
  
  
  
> **文章来源 ：IT之家、freebuf******  
  
  
**精彩推荐**  
  
  
  
  
# 乘风破浪|华盟信安线下网络安全就业班招生中！  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575781&idx=2&sn=ea0334807d87faa0c2b30770b0fa710d&chksm=83bdf641b4ca7f5774129396e8e916645b7aa7e2e2744984d724ca0019e913b491107e1d6e29&scene=21#wechat_redirect)  
  
  
# 【Web精英班·开班】HW加油站，快来充电！  
  
  
‍[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650594891&idx=1&sn=b2c5659bb6bce6703f282e8acce3d7cb&chksm=83bdbbafb4ca32b9044716aec713576156968a5753fd3a3d6913951a8e2a7e968715adea1ddc&scene=21#wechat_redirect)  
  
  
‍  
# 始于猎艳，终于诈骗！带你了解“约炮”APP  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575222&idx=1&sn=ce9ab9d633804f2a0862f1771172c26a&chksm=83bdf492b4ca7d843d508982b4550e289055c3181708d9f02bf3c797821cc1d0d8652a0d5535&scene=21#wechat_redirect)  
  
**‍**  
  
  

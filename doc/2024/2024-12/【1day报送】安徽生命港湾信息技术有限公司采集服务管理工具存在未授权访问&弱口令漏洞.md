#  【1day报送】安徽生命港湾信息技术有限公司采集服务管理工具存在未授权访问&弱口令漏洞   
原创 hongzh0  Hacking Group 0434   2024-12-08 08:07  
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任  
  
今天下午闲着没事看了下CNVD报送  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jZReoHLb66xXxKxFRt52IP87IYkejGBwGP726Uw6M0CvVCibyL6Z3H1Ss9vPliaB0bO0QNkp5zamUTBKWNV8ZRCQ/640?wx_fmt=png&from=appmsg "")  
  
本来想顺着打一下，报告写完一看和大哥撞上了，1day就1day吧  
  
安徽生命港湾信息技术有限公司采集服务管理工具存在未授权访问漏洞  
#### 漏洞描述  
  
安徽生命港湾信息技术有限公司是一家以从事软件和信息技术服务业为主的企业。  
  
安徽生命港湾信息技术有限公司采集服务管理工具平台存在未授权登录漏洞，攻击者可利用该漏洞获取管理员权限。  
#### 攻击方式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jZReoHLb66xXxKxFRt52IP87IYkejGBwXX5XRWo13pH7oaYsmUK5xiazGxM1iaqRfffPbxwbzHOZVX1ayHfUlW4g/640?wx_fmt=png&from=appmsg "")  
  
  
   
  
输入admin/admin，抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jZReoHLb66xXxKxFRt52IP87IYkejGBwqvME6Ne2TSckUznAMXNQMDWupPB8ECuuAuCIBtjeGvV24YI0icRvRaw/640?wx_fmt=png&from=appmsg "")  
  
  
   
  
抓响应包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jZReoHLb66xXxKxFRt52IP87IYkejGBw4L3DU3y6sJDZUduhhKcpmyuukBJWib8Vtxm5RFYGjTWjooM5c28phBQ/640?wx_fmt=png&from=appmsg "")  
  
  
   
  
改成true  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jZReoHLb66xXxKxFRt52IP87IYkejGBweCZz4JVJ8dbUIrA7S2jsrct2ibL8GLdvXbPJNzFAynl5tmQ0LaWqv1A/640?wx_fmt=png&from=appmsg "")  
  
安徽生命港湾信息技术有限公司采集服务管理工具存在弱口令  
  
admin/admin  
  
  
(如呼吸  
  
  

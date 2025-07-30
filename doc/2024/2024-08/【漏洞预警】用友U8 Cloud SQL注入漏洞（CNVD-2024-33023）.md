#  【漏洞预警】用友U8 Cloud SQL注入漏洞（CNVD-2024-33023）   
原创 聚焦网络安全情报  安全聚   2024-08-11 20:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Icw1mW4eH3fGjq28SHy79SEcdRGT7ZsCxicdkcJevVicIVGdZBR0dYjze8G3YwUEkcH9WgQ1KhficepoIpSk64Atw/640?wx_fmt=gif&from=appmsg "")  
  
  
**高**  
  
**危**  
  
**公**  
  
**告**  
  
  
  
近日，安全聚实验室监测到用友网络科技股份有限公司 U8 Cloud 存在SQL注入漏洞，编号为：CNVD-2024-33023，漏洞评分：7.8  此漏洞允许攻击者在ReleaseRepMngAction接口构造特殊的SQL请求，以获取数据库敏感信息。  
  
  
**01 漏洞描述**  
  
  
  
**VULNERABILITY DESC.**  
  
  
  
  
用友U8 Cloud是一款基于云计算技术的企业管理软件，为企业提供全面的财务、人力资源、供应链管理等解决方案。通过云端部署，用户可以随时随地访问系统，实现灵活办公和协同工作。U8 Cloud具有高度定制化和可扩展性，能够满足不同行业和规模企业的管理需求，帮助企业提升运营效率、降低成本，并提升竞争力。该漏洞攻击者可以通过ReleaseRepMngAction接口构造特定的SQL请求，利用系统SQL注入漏洞获取数据库中的敏感信息。  
  
**02 影响范围**  
  
  
  
**IMPACT SCOPE**  
  
  
  
  
1.0 <= U8 Cloud <= 5.0sp  
  
  
**03 安全措施**  
  
  
  
**SECURITY MEASURES**  
  
  
  
  
目前厂商已发布漏洞补丁，建议用户尽快安装用友U8 Cloud 的漏洞修复补丁：  
  
  
官方补丁下载地址：  
  
https://security.yonyou.com/#/patchInfo?identifier=72552b33577848fc852a98071d59efe6  
  
  
**04 参考链接**  
  
  
  
**REFERENCE LINK**  
  
  
  
  
1.https://www.cnvd.org.cn/flaw/show/CNVD-2024-33023  
  
  
**05 技术支持**  
  
  
  
**TECHNICAL SUPPORT**  
  
  
  
  
长按识别二维码，关注 **"安全聚"**  
 公众号！如有任何问题或需要帮助，随时联系我们的技术支持团队。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Icw1mW4eH3fGjq28SHy79SEcdRGT7ZsCBTiaicF2ia4P7iaZMaM3OPbrLG64Lia2tjS9TrSyn4FOS5D2o1vIfCEf8Cw/640?wx_fmt=jpeg&from=appmsg "")  
  
**联系我们**  
  
微信号：SecGat  
  
关注安全聚，获取更多精彩文章。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Icw1mW4eH3fGjq28SHy79SEcdRGT7ZsCRtb8nIoYiadnGwptIJHdeGVOEEFuibuXZBhMvw8OmlsMJB7kG0zuazgA/640?wx_fmt=gif&from=appmsg "")  
  
**END**  
  
  
  
  
**HISTORY**  
  
/  
  
**往期推荐**  
  
[【漏洞预警 | 已复现】Windows 远程桌面授权服务远程代码执行漏洞（CVE-2024-38077）附POC](http://mp.weixin.qq.com/s?__biz=MzkyNzQzNDI5OQ==&mid=2247486589&idx=1&sn=db8f0d9996059fb6b9e0d6a04d0ef819&chksm=c2295f29f55ed63ffdec5fc047374da2052e7542a99e4319b323ce758e4acc2daa491b3046d0&scene=21#wechat_redirect)  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkyNzQzNDI5OQ==&mid=2247486420&idx=3&sn=3bd4ad9b9aa9e27629eef92cc1a0e00e&scene=21#wechat_redirect)  
[【漏洞预警 | 已复现】Apache OFBiz远程代码执行漏洞（CVE-2024-38856）](https://mp.weixin.qq.com/s?__biz=MzkyNzQzNDI5OQ==&mid=2247486484&idx=1&sn=3e0f106d2ce17f16075690444c6ad16d&scene=21#wechat_redirect)  
  
  
  
[【漏洞预警 | 已复现】Splunk Enterprise 未授权任意文件读取漏洞（CVE-2024-36991）](http://mp.weixin.qq.com/s?__biz=MzkyNzQzNDI5OQ==&mid=2247486420&idx=3&sn=3bd4ad9b9aa9e27629eef92cc1a0e00e&chksm=c2295880f55ed1964f7229ce709929430b9a56882028fa882a69bca86e0c0bac01fde5de06bb&scene=21#wechat_redirect)  
  
  
  
[【漏洞预警 | 已复现】Rejetto HTTP File Server 模板注入漏洞（CVE-2024-23692）](http://mp.weixin.qq.com/s?__biz=MzkyNzQzNDI5OQ==&mid=2247486420&idx=2&sn=6c8f1e5428b1c3713ad1aa32231c1de8&chksm=c2295880f55ed1961e9c9e36cc89c9e1c4377ce7b755e3c85b5475fc8a97dcfbe0d68db96264&scene=21#wechat_redirect)  
  
  
  
  

#  Kibana原型污染漏洞可导致远程代码执行   
 FreeBuf   2025-05-07 10:27  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
Elastic公司针对Kibana发布了一项重大安全公告，警告用户注意编号为CVE-2025-25014的漏洞。该漏洞CVSS评分为9.1分，属于原型污染（Prototype Pollution）类型漏洞，攻击者可通过向Kibana的机器学习（Machine Learning）和报告（Reporting）接口发送特制HTTP请求实现任意代码执行。  
  
  
![Kibana漏洞示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icBnQs7RjsvmjN6fKjWHPxohJUwicelXaAx0Gm1FV5CiayAib0gnhsfMhpYwXf8ic22Z6sbU2M98Q8oCA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**01**  
  
  
  
## 漏洞技术细节  
  
  
  
公告明确指出："Kibana中的原型污染漏洞允许攻击者通过精心构造的HTTP请求对机器学习和报告接口实施任意代码执行"。原型污染漏洞通过操纵JavaScript对象原型链，使攻击者能够注入恶意属性覆盖应用程序逻辑。在本案例中，该漏洞可升级为远程代码执行（RCE），这对通常处理敏感遥测数据和分析结果的监控环境构成最严重威胁。  
  
  
**02**  
  
  
  
**受影响版本范围**  
  
  
漏洞影响以下Kibana版本：  
- 8.3.0至8.17.5  
  
- 8.18.0  
  
- 9.0.0  
  
无论是自建部署还是Elastic Cloud云服务，只要启用了机器学习和报告功能，均存在风险。  
  
  
**03**  
  
  
  
**修复方案**  
  
  
Elastic强烈建议用户立即升级至以下修复版本：  
- 8.17.6  
  
- 8.18.1  
  
- 9.0.1  
  
对于无法立即升级的用户，Elastic提供了两种缓解措施：  
  
  
1. 禁用机器学习功能  
- 在  
kibana.yml  
配置文件中添加：  
xpack.ml.enabled: false  
  
- 或仅禁用异常检测功能：  
xpack.ml.ad.enabled: false  
  
2. 禁用报告功能  
- 在  
kibana.yml  
配置文件中添加：  
xpack.reporting.enabled: false  
  
Elastic强调，短期内禁用机器学习或报告任一功能均可有效缓解漏洞风险。建议受影响用户立即安装补丁，若暂时无法升级，应通过禁用相关功能模块阻断攻击路径。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319938&idx=1&sn=8b4f45b0d0c45643793a84ad8bca2a13&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319699&idx=1&sn=127e9ca1a8d55931beae293a68e3b706&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319086&idx=1&sn=e2ff862babd7662c4fa06b0e069c03f2&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

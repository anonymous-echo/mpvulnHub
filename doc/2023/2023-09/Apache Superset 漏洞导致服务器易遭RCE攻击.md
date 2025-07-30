#  Apache Superset 漏洞导致服务器易遭RCE攻击   
THN  代码卫士   2023-09-08 15:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Apache Superset 修复了两个漏洞，本可导致攻击者在受影响系统上获得远程代码执行权限。**  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMT8XqYSWgGfB0E0gKI28A7K4ZMfr5GCVLeNqIww6FLFUiaazr0LlrFLga3cjEtBqmwonrKU731jsqw/640?wx_fmt=png "")  
  
  
Apache Superset 更新版本 2.1.1 修复了两个漏洞CVE-2023-39265和CVE-2023-37941。一旦恶意人员获得对 Superset 元数据数据库的控制权限，就能够利用这两个漏洞执行恶意操作。  
  
除了这两个漏洞外，Superset 最新版本还修复了一个 REST API 权限不当问题CVE-2023-36388，它可导致低权限用户执行服务器端请求伪造攻击。Horizon3.ai 公司的研究员 Naveen Sunkavally 在一份技术详情中指出，“Superset 从设计上课使权限用户连接到任意数据库并使用强大的 SQLLab 接口在这些数据库中执行任意SQL请求。如果Superset 可被诱骗于连接到自身的元数据数据库，则攻击者可直接通过SQLLab 读或写应用配置，从而收割凭据并远程执行代码。”  
  
CVE-2023-39265和连接到用于元数据存储器的 SQLite 数据库时绕过URI有关，可导致攻击者执行数据操控命令。该CVE漏洞还包括从文件导入 SQLite 数据库连接信息缺乏验证的问题有关，该漏洞可被滥用于导入恶意构造的ZIP压缩文件。Sunkavally 表示，“Superset 1.5到2.1.0 版本使用Python 的 pickle 程序包存储某些配置数据。对该元数据数据库具有写权限的攻击者可在存储中插入任意 pickle payload，触发反序列化，从而导致远程代码执行后果。”  
  
Superset 新版本还修复了如下缺陷：  
  
- MySQL 任意文件读漏洞可被用于获得对元数据数据库的凭据。  
  
- 滥用superset load_examples 命令，从用户界面中获取元数据数据库URI并修改存储在其中的数据。  
  
- 在某些 Superset程序中使用默认凭据访问元数据数据库。  
  
- 以权限用户身份查询/api/v1/database API 时，泄露明文形式的数据库凭据（CVE-2023-30776，已在2.1.0版本中修复）。  
  
  
  
四个多月前，Apache 披露了位于该产品中的一个高危漏洞CVE-2023-27524（CVSS评分8.9），可导致未授权攻击者获得对服务器的管理员权限并执行任意代码。该问题是因为使用默认的SECRET_KEY导致的，攻击者可借此认证并访问暴露在互联网上的安装程序的未授权资源。  
  
Horizon3.ai 公司提到，自2023年4月公开披露后，在3842个Superset 服务器中有2076个仍然使用SECRET_KEY，其中72个实例使用非常容易被猜测到的SECRET_KEY如superset、SUPERSET_SECRET_KEY、1234567890、admin、changeme、thisisasecretkey和your_secret_key_here。  
  
Sunkavally 表示，“用户应当设置Flask SECRET_KEY，这就导致一些用户设置了弱密钥”，因此督促维护人员增加对自动生成密钥功能的支持，“很多漏洞的根因在于，Superset web 接口可使用户连接到元数据数据库。”  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Apache Ivy 注入漏洞可导致攻击者提取敏感数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517437&idx=2&sn=b43eb67509ce31f1726c7bb953adb331&chksm=ea94b597dde33c816cc6b6b60429447908b3cbafd3b5194aa4e547412a0c05805aa001546707&scene=21#wechat_redirect)  
  
  
[未修复的 Apache Tomcat 服务器传播 Mirai 僵尸网络恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517295&idx=1&sn=7f61402b12fbd46cb399a19ff93ca28e&chksm=ea94b505dde33c13b5e70aa9fdbdf02fc8dc58ac05568e19c5af6385458348da2464e9fa4c8b&scene=21#wechat_redirect)  
  
  
[Apache Jackrabbit 中存在严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517243&idx=3&sn=aec30860da6f2a9d9af2ea532a32b258&chksm=ea94b551dde33c4713eeba8084b8b9a9eff3f5fb6ef34ea6ac25267f911bc21fd317e9ca8c8d&scene=21#wechat_redirect)  
  
  
[Apache Superset 会话验证漏洞可导致攻击者访问未授权资源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516346&idx=2&sn=c84ae42d9a4eab4b30b8eba4a27130a5&chksm=ea94b1d0dde338c6da3cc189e548d10cc3511c1ef2d59f067bd428a6efae2df174b66c93b0f6&scene=21#wechat_redirect)  
  
  
[Apache Linkis 修复多个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516234&idx=1&sn=ba72ac437de85dff898598d11ce97f6d&chksm=ea94b120dde338367ba09290193fddc80c82805257f0aac35587dafcb63dd98f43f418cc767f&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/09/alert-apache-superset-vulnerabilities.html  
  
  
题图：  
Pexels  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

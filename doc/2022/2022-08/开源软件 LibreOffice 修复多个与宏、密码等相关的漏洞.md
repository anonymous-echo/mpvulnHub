#  开源软件 LibreOffice 修复多个与宏、密码等相关的漏洞   
Bill Toulas  代码卫士   2022-08-02 18:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
LibreOffice 套件已更新，修复了多个和宏执行以及web 连接密码防护相关联的漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQCicCePUtnL62cOib1NxRm557aXGAyzo5hx4j8OhibGFZNHul5ibmSQDiaSEb7sYNLEK5kd5ibfnlCFGPA/640?wx_fmt=png "")  
  
  
LibreOffice 的开发人员已在稳定版本 LibreOffice 7.2 和不稳定版本的分支7.3中执行了修复方案。  
  
本次共修复三个漏洞。第一个是CVE-2022-26035，可导致宏代码在目标设备上运行，即使用于签名宏的证书不匹配用户配置数据库中的条目也不例外。  
  
LibreOffice 的检查特性可判断宏是否由用户信任的其他人（如同事）创建和签名，如此在匹配不当的情况下不会执行宏代码。安全公告指出，“攻击者可创建带有序列号的任意证书以及类似于可信证书（由LibreOffice 向可信作者展示）的发行机构字符串，从而可能导致用户执行包含在不当信任的宏中的任意代码。”  
  
第二个漏洞的编号为CVE-2022-26307，和对用户配置数据库中存储web连接的密码的主钥编码不良有关。密钥的不良编码将其熵值从128位降为43位，导致攻击者可实施暴力攻击并访问所存储密码。在更新版本中，存储密码的用户将被自动提示，使用固定方法重新加密。  
  
第三个漏洞是CVE-2022-26306，可导致对用户配置数据拥有访问权限的攻击者，在无需知道主密码的情况下检索web连接的密码。  
  
  
**缓解措施**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQCicCePUtnL62cOib1NxRm55OzLnoWfI59GG2mmWFS0WkDljhPFx0F4SR4nPaUaCDicMfLud7C6fx9w/640?wx_fmt=png "")  
  
  
  
LibreOffice 提供了关于宏的安全选项，从“低”到“非常高”不等，根据用户愿意接受的信任级别来激活不同的执行策略。例如，如果将安全选项设为“低”，则即使这些宏未签名，则仍然会被执行。中等安全级别会显示一个对话框，要求用户批准宏执行。  
  
在CVE-2022-26307案例中，如果宏的安全级别设置为“非常高”或者用户未维护可信证书数据库，则该缺陷是不可利用的。要检查自己的宏安全设置，则可导航至工具→选项→LibreOffice→Security，点击“宏安全”，并将级别设置为“非常高”。  
  
LibreOffice 预计拥有2亿名用户，其中很多用户是查找 Microsoft Office 替代品以及威胁更小的办公生产力软件套件的学生和 Linux 用户。  
  
官方下载门户网站上的最新可用版本是7.3.5.2，已修复上述缺陷；如用户需要更加稳定的性能，则可获取7.2.7版本。  
  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513172&idx=1&sn=5c228a525bd6eb94d24f697d88af3c6d&chksm=ea94853edde30c2897319ed8aac13685ecca7d05bf4ecdee1d9b30c9d7f4faf24df0c1a993d2&scene=21#wechat_redirect)  
[在线阅读版：《2022中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513174&idx=1&sn=e474d1ea23ed7cce10e2ae2f872fc003&chksm=ea94853cdde30c2a963cfa00a536764ea55cdee7ba6ef4a7716a28f82a97ca630dc271ee5224&scene=21#wechat_redirect)  
  
  
[奇安信发布《2022中国软件供应链安全分析报告》 谁会成为下一个Log4j2？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513172&idx=1&sn=5c228a525bd6eb94d24f697d88af3c6d&chksm=ea94853edde30c2897319ed8aac13685ecca7d05bf4ecdee1d9b30c9d7f4faf24df0c1a993d2&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512788&idx=1&sn=e187454b1e7105eca3d4a6988c305073&chksm=ea9483bedde30aa831b27a1729e393da823f28bb3b86c526f3c936e95d2d9c1d928b50b2db9d&scene=21#wechat_redirect)  
  
[LibreOffice、OpenOffice 漏洞可导致黑客欺骗已签名文档](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508311&idx=2&sn=899f14c24e31f33cfc90889201aa3be1&chksm=ea94903ddde3192b9459d6bb8641bdbbf1603b8562da53544018a29dcc8895b7df2c33cc1223&scene=21#wechat_redirect)  
  
  
[补丁打补丁：利用3个新漏洞绕过 LibreOffice 2个严重缺陷的补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490605&idx=2&sn=eff58c7e253fd743170fc500cf54ed0e&chksm=ea972d47dde0a451f09ae849b3d65db601a52ca1bf35093546efb613d5e6e04df0cb1980222f&scene=21#wechat_redirect)  
  
  
[LibreOffice 被曝漏洞，打开文档即导致电脑被黑](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490492&idx=2&sn=34c3adb5c2c8b1946fb8ad2db49e66a3&chksm=ea972ad6dde0a3c062edccc5f5ace2b2c4b1b0773a593277f484e340e2b30da7c079e0c60799&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/libreoffice-addresses-security-issues-with-macros-passwords/  
  
  
题图：  
Pixabay License  
‍  
  
  
  
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

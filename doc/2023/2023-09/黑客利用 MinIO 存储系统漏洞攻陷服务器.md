#  黑客利用 MinIO 存储系统漏洞攻陷服务器   
THN  代码卫士   2023-09-05 18:13  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**未知威胁者利用位于 MinIO 高性能对象存储系统重的多个高危漏洞在受影响服务器上实现未授权漏洞执行。**  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMR8hkds0mRqPWfdiaDZBXnJ5qFcOHfKogHSv07RprV5qKyKiakQLQcS1qBRG5GgFdufLgk6F5x9iadIg/640?wx_fmt=png "")  
  
  
网络安全和事件响应公司 Security Joes 表示，攻击利用了公开可用的利用链在 MinIO 实例中安装后门。该利用链由CVE-2023-28432（CVSS评分7.5）和CVE-2023-28434（CVSS评分8.8）组成，而前者已在2023年4月1日被列入CISA必修清单。这两个漏洞“可能或暴露位于受陷程序中的敏感信息并在运行 MinIO 应用运行的主机上实现远程代码执行。”  
  
在所调查的攻击链中，这些缺陷被用于获取管理员凭据并借此，触发指定 MIRROR_URL的更新命令的方式，用木马版本替换主机上的 MinIO 客户端。MinIO 文档指出，“mc admin 更新命令更新了部署中的所有 MinIO 服务器。该命令还支持在不具有公开网络访问权限的部署的环境中使用非公开镜像服务器。”  
  
Security Joes 公司提到，“这些措施可使攻击者协调欺骗性更新。通过恶意版本替换真实的 MinIO 二进制，攻击系统。”  
  
对该二进制的恶意修改暴露了通过HTTP请求接收并执行命令的端点，实际上是用作后门。这些命令继承了启动该应用的用户的系统权限。值得注意的是，该被修改的二进制是对 Evil MinIO 的复制，后者在2023年4月初于 GitHub 平台发布。话虽如此，但未有证据表明两者之间存在关联。  
  
很显然的一点是，威胁行动者在 bash 脚本和 Python 方面十分熟练，更不用说利用后门访问权限从远程服务器释放 payload，通过下载器脚本用于利用后阶段。该脚本能够攻击 Windows 和 Linux 环境，作为配置受陷主机的网关，从而判断执行是否必须终止。  
  
Security Joes 指出，“这种动态方式强调了威胁者基于受陷系统预期价值优化投入的战略方法。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[数千台未修复 Openfire XMPP 服务器仍易受高危漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517466&idx=1&sn=56ec3d83af97ad62084124c205e2349b&chksm=ea94b470dde33d66e66beaa6ad53e44d25babf2e6c0517f8b86135be8ba15399ba13dcea6b78&scene=21#wechat_redirect)  
  
  
[PaperCut高危漏洞可使未修复服务器受RCE攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517335&idx=1&sn=fb6f828cad2dd147b64eb18c25e34e7b&chksm=ea94b5fddde33ceb6bbdf2cd3e5cda0f1103d555edec4b0e6008b76a45ecf4d51beda67e6305&scene=21#wechat_redirect)  
  
  
[未修复的 Apache Tomcat 服务器传播 Mirai 僵尸网络恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517295&idx=1&sn=7f61402b12fbd46cb399a19ff93ca28e&chksm=ea94b505dde33c13b5e70aa9fdbdf02fc8dc58ac05568e19c5af6385458348da2464e9fa4c8b&scene=21#wechat_redirect)  
  
  
[P2PInfect 蠕虫利用 Lua 沙箱逃逸满分漏洞攻击 Redis 服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517155&idx=3&sn=99559d56c27bee18a974051b96af05ae&chksm=ea94b289dde33b9f3a7595fb90b08a2bae25dc55c979c015f7c97232efdaf810b6fc478d2269&scene=21#wechat_redirect)  
  
  
[严重的 TootRoot 漏洞可导致Mastodon 服务器遭劫持](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516985&idx=2&sn=1314af5aa885e4849eef0319cfc6f5f1&chksm=ea94b253dde33b45266932db87448f0614dda574b5bb33e1598ef3acd97302e9bd4ab2ae157a&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/09/hackers-exploit-minio-storage-system.html  
  
  
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
  

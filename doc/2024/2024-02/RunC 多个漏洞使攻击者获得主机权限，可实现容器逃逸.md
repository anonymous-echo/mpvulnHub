#  RunC 多个漏洞使攻击者获得主机权限，可实现容器逃逸   
THN  代码卫士   2024-02-01 17:18  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**runC 命令行工具中存在多个漏洞，可被攻击者用于逃逸容器边界并执行后续攻击。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQGEhoXQliaibsbCX8AWBMwIbNqcndK5zkwYuXsG1Nc01IKY86UHfCPukerHibddq3g3VcicJo2C4ibj4g/640?wx_fmt=gif&from=appmsg "")  
  
  
这些漏洞的编号是CVE-2024-21626、CVE-2024-23651、CVE-2024-23652和CVE-2024-23653，被发现它们的 Snyk 公司统称为 “Leaky Vessels（有漏洞的容器）”。  
  
研究人员指出，“这些容器逃逸漏洞可导致攻击者获得对容器内底层主机操作系统的越权访问权限，从而可能获得对敏感数据（凭据、客户信息等）的访问权限，并发动进一步攻击，尤其是当所获得的权限中包含超级用户权限的情况。”  
  
runC 是一款用于在 Linux 上传播和运行容器的工具，它最初被开发为 Docker 的一部分，随后在2015年发展成独立的开源库。这些漏洞简述如下：  
  
- CVE-2024-21626：WORKDIR：操作容器顺序突破  
  
- CVE-2024-23651：Mount 缓存竞争  
  
- CVE-2024-23652：Buildkit 构建时间容器破坏任意删除  
  
- CVE-2024-23653：Buildkit GRPC 安全模式权限检查  
  
  
  
其中最严重的漏洞是CVE-2024-21626，可造成‘WORKDIR’命令导致的容器逃逸问题。研究人员提到，“运行一张恶意图像或通过使用恶意 Dockerfile 或上游图像（如使用 `FROM`）构建容器图像就能发生这种情况。”  
  
目前尚未有证据表明这些漏洞已遭在野利用。漏洞均已在 runC 版本1.1.12 中修复。研究人员提到，“由于这些漏洞影响广为使用的低层级容器引擎组件和容器构建工具，Snyk 强烈建议用户检查提供容器运行时环境包括 Docker、Kubernetes 厂商、云容器服务和开源社区等发布的更新。”  
  
2019年2月，runC 维护人员修复了另外一个高危漏洞（CVE-2019-5736，CVSS评分8.6），它可被攻击者破解容器并获得主机的root访问权限。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Runc 容器逃逸漏洞的 PoC 已发布，谷歌亚马逊等受影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489240&idx=2&sn=853042033ba53a27c9ca7b6a187c6da9&chksm=ea9727b2dde0aea43c5028c2f3048481a3179fe21e5d118fe584073017a8dfe4b11d3345f8f2&scene=21#wechat_redirect)  
  
  
[利用RunC 漏洞获得 Docker、Kubernetes 主机的 root 权限](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489193&idx=1&sn=f33d9f7d496ba793c2f51d8d8c46de1b&chksm=ea9727c3dde0aed537b66842d5698eca80dd20cc9e36f9fcca14b87abadb93d31713f56aa6ac&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/02/runc-flaws-enable-container-escapes.html  
  
  
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
  

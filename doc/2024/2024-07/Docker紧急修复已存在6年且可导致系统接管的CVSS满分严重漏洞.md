#  Docker紧急修复已存在6年且可导致系统接管的CVSS满分严重漏洞   
Edward Kovacs  代码卫士   2024-07-25 19:53  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Docker 发布紧急安全公告，修复了位于 Docker Engine 某些版本中的一个严重漏洞 (CVE-2024-41110)，它在一定条件下可绕过授权插件 (AuthZ)。**  
  
  
  
该漏洞的CVSS评分为满分10分，最初在2018年发现并修复，但2019年1月的补丁并未推送到主要版本，从而导致回归问题。  
  
Docker 提醒称，“依赖该授权插件来检查请求和/或响应正文来做出访问控制决策的任何人，都可能受影响。”安全公告提到，“Engine API 客户端使用特殊构造的 API 请求能够使该守护进程将没有正文的请求或响应转发给授权插件。在一些情况下，如果正文已被转发给该授权插件，则插件可能允许原本会被拒绝的请求。”  
  
Docker 指出，“攻击者可通过 Content-Length 设为0的API请求来利用绕过，导致Docker守护进程将没有正文的请求转发给 AuthZ插件，而它可能会不正确地许可该请求。”  
  
  
**受影响版本**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT9RL0fjlI2iaUerh3TqciakcBM0EpF9e1BLspJ5rhvBosFJUibSibicHDy2H1LRgtEg1MPiaaaibiamyzz4w/640?wx_fmt=gif&from=appmsg "")  
  
  
  
受影响版本包括 Docker Engine <= v19.03.15、<= v20.10.27、<= v23.0.14、<= v24.0.9、<= v25.0.5、<= v26.0.2、<= v26.1.4、<= v27.0.3以及 <= v27.1.0。已修复版本为 > v23.0.14 和 > v27.1.0。  
  
Docker EE v19.03.x和Mirantis Container Runtime 所有版本不受影响。Docker 指出，不使用 AuthZ 插件的商用产品和内部基础设施均不受影响。  
  
安全公告指出，Docker Desktop 4.32.0及之前版本虽然包括受影响的 Docker Engine，但影响仅限于生产环境。利用要求访问 Docker API，意味着攻击者通常需要获得对主机机器的本地访问权限，除非 Docker 守护进程通过 TCP 以不安全的方式遭暴露。  
  
Docker Desktop 的默认配置不包括 AuthZ 插件，提权仅限于 Docker Desktop VM，而不包括底层主机。Docker Engine 的已修复版本将包含在 Docker Desktop 4.33版本中。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[新型恶意软件利用被暴露的 Docker API 挖矿](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519800&idx=3&sn=8bd471501923e7c4f43eeea143afed58&chksm=ea94bf52dde33644296f3169c733f15846b350b5eea417c4d21a66738e0521b3abd0d09318d0&scene=21#wechat_redirect)  
  
  
[Docker Hub 仓库中隐藏超过1650个恶意容器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514727&idx=1&sn=61f1c2bed808fe96dabca210dba56e05&chksm=ea948b0ddde3021b9313980159fab8ec9b15c08ce0f2d66fc2b98baaab2342303bbc804e24e8&scene=21#wechat_redirect)  
  
  
[可蠕虫 DarkRadiation 勒索软件瞄准 Linux 和 Docker 实例](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505906&idx=2&sn=416b7bb27d26de5e22771cb22e26ccbe&chksm=ea94e698dde36f8ee5e1e663767eb25b094029846665659ca861cc07c3a694456871299cb524&scene=21#wechat_redirect)  
  
  
[Canonical 在 Docker Hub 上发布安全容器应用镜像](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247497950&idx=5&sn=8dee0b56059769dc830b7f5f0979e9cd&chksm=ea94c9b4dde340a246ec6f18e8c04a4a658bd91cae76d0885a6c5779c204ebe5b720b152bed2&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
  
https://www.securityweek.com/docker-patches-critical-authz-plugin-bypass-vulnerability-dating-back-to-2018/  
  
  
题图：  
Pixabay  
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
  

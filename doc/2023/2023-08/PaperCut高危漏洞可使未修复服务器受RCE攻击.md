#  PaperCut高危漏洞可使未修复服务器受RCE攻击   
Sergiu Gatlan  代码卫士   2023-08-07 18:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Horizon3.ai 公司的安全研究员从 Windows 版本的 PaperCut 打印管理软件中发现了一个新的高危漏洞 (CVE-2023-39143)，在特定情况下可导致在未修复 Windows 服务器上获得远程代码执行权限。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRm4tIhDlZ67XFs1C3Hj1iaBLcqn1lzcfNBdPwaVgHC629PQ0MonPubVRNv27CUrqs2SnCaQfJHYyQ/640?wx_fmt=gif "")  
  
  
该漏洞的CVSS评分8.4，影响 PaperCut NG/MF 22.1.3 之前的版本，是路径遍历和文件上传漏洞的组合，可使威胁行动者在执行无需用户交互的复杂度较低攻击后，在受陷系统上读取、删除和上传任意文件。  
  
虽然该漏洞仅影响切换外部设备继承设置的非默认配置中的服务器，但 Horizon3 在上周五发布的一份报告中提到，多数 Windows PaperCut 服务器启用了该配置。  
  
Horizon3 提到，“PaperCut 的某些版本默认启用该设置，如 PaperCut NG 商用版本或PaperCut MF。从Horizon3 从现实环境中收集的样本数据来看，我们预测大多数 PaperCut 版本在开启了外部设备集成设置的 Windows 上运行。”  
  
可在 Windows 上用如下命令查看服务器是否易受 CVE-2023-39143 攻击（响应如是200，则表明服务器需要打补丁）：  
```
curl -w "%{http_code}" -k --path-as-is https://<IP>:<port>/custom-report-example/..\..\..\deployment\sharp\icons\home-app.png
```  
  
无法立即安装安全更新的管理员，则可仅增加需要访问白名单的IP地址。  
  
Shodan 搜索发现，目前约1800台 PaperCut 服务器被暴露在互联网，不过并非所有易受该漏洞利用攻击。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRm4tIhDlZ67XFs1C3Hj1iaBTedN3WmTmQUP6Pb1ypoqz7HHHClOpPZ8gDcaKYAibGOGMUrShnsjJCw/640?wx_fmt=png "")  
  
**遭勒索团伙和国家黑客攻击**  
  
  
  
今年早些时候，多个勒索团伙组合利用严重的未认证RCE漏洞 (CVE-2023-27350) 和高危信息泄露漏洞 (CVE-2023-27351) 攻击 PaperCut 服务器。PaperCut 公司在4月19日披露称，这些漏洞遭活跃利用，提醒管理员和安全团队立即更新服务器。几天后，Horizon3 安全研究员发布 RCE PoC 利用，导致其它威胁行动者有机会攻击易受攻击的服务器。  
  
微软认为 PaperCut 服务器攻击与 Clop 和 LockBit 勒索团伙有关，后者利用该访问权限从受陷系统中窃取企业数据。在这些数据盗取攻击中，该勒索团伙利用保存所有通过 PaperCut 打印服务器发送文档的 “Print Archiving” 特性。两周后，微软披露称伊朗国家黑客组织 Muddywater 和 APT35 也发动了攻击。CISA 在4月21日将该漏洞列入已遭活跃利用漏洞清单，要求美国所有联邦机构在2023年5月12日之前保护服务器的安全。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Milesight 工业路由器受数十个RCE漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517324&idx=2&sn=148eb4867662d131943cf25c80175992&chksm=ea94b5e6dde33cf0d8a2d47cf997596fef2f4a4cce32ddcc3df68065796ee8ad4be5dc6c9d66&scene=21#wechat_redirect)  
  
  
[Apache Jackrabbit 中存在严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517243&idx=3&sn=aec30860da6f2a9d9af2ea532a32b258&chksm=ea94b551dde33c4713eeba8084b8b9a9eff3f5fb6ef34ea6ac25267f911bc21fd317e9ca8c8d&scene=21#wechat_redirect)  
  
  
[未修复的 Apache Tomcat 服务器传播 Mirai 僵尸网络恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517295&idx=1&sn=7f61402b12fbd46cb399a19ff93ca28e&chksm=ea94b505dde33c13b5e70aa9fdbdf02fc8dc58ac05568e19c5af6385458348da2464e9fa4c8b&scene=21#wechat_redirect)  
  
  
[P2PInfect 蠕虫利用 Lua 沙箱逃逸满分漏洞攻击 Redis 服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517155&idx=3&sn=99559d56c27bee18a974051b96af05ae&chksm=ea94b289dde33b9f3a7595fb90b08a2bae25dc55c979c015f7c97232efdaf810b6fc478d2269&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/new-papercut-critical-bug-exposes-unpatched-servers-to-rce-attacks/  
  
  
题图：Pexels License  
  
  
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
  

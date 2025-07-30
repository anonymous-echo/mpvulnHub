#  Arm：Mali GPU 驱动中的0day已遭利用   
Bill Toulas  代码卫士   2024-06-12 17:27  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Arm 提醒称，影响 Mali GPU Kernel Driver 的一个漏洞已遭在野利用。**  
  
该漏洞是释放后使用漏洞CVE-2024-4610，影响如下产品：  
  
- Bifrost GPU Kernel Driver（r34p0 到 r40p0 的所有版本）  
  
- Valhall GPU Kernel Driver （r34p0 到 r40p0 的所有版本)  
  
  
  
Arm 在上周发表的一份安全公告中提到，“本地非权限用户可执行不当的GPU内存处理操作，获得对已被释放内存的访问权限。”该漏洞已在 Bifrost 和 Valhall GPU Kernel Driver r41p0 中修复。值得注意的是，该版本在2022年11月24日发布，目前版本是r49p0，在2024年4月发布。  
  
Arm 并未回应该漏洞是旧漏洞且被分配新的CVE漏洞编号，还是新发现的漏洞。  
  
Arm 证实称该漏洞已遭真实利用，但并未披露任何阻止进一步滥用的信息。  
  
此前Arm Mali GPU 中的已披露漏洞CVE-2022-2270、CVE-2022-38181和CVE-2023-4211已被商用监控厂商用于高针对性的安卓设备攻击中，其中CVE-2023-4211的利用与意大利公司 Cy4Gate 有关。  
  
建议受影响产品的用户尽快更新至适合版本，以免遭潜在威胁。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Intel、AMD和Arm 告警：注意新的推断执行CPU漏洞！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510855&idx=3&sn=5ebfde6f449e166adf5d37e1ab3461bf&chksm=ea949a2ddde3133b97ff80f34174a773d2da203fa22dde34d8eee14e346d0391dd1c652afad3&scene=21#wechat_redirect)  
  
  
[英伟达发布 GPU 驱动更新，修复25个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514853&idx=2&sn=aa7edf1c528ee030b826738933440806&chksm=ea948b8fdde3029958ce600f79ba636a4b31e5e7bd11dbda3eca72604cd5ebe9f8c54899f257&scene=21#wechat_redirect)  
  
  
[NVIDIA 修复 Windows GPU 显示驱动中的10个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511827&idx=1&sn=0c10181d2e412b200c9cd60046a99042&chksm=ea949e79dde3176f2177854031582fbb7f4d695d3f451727a6cd6a168490368006e67b4a110b&scene=21#wechat_redirect)  
  
  
[黑客泄露DLSS源代码，逼英伟达开源GPU驱动](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510769&idx=1&sn=33b36edc7756b13e979de35013a06c34&chksm=ea949b9bdde3128db9913820d0af32ba947169d140309d9a5414308a4214561bce3c4fdab159&scene=21#wechat_redirect)  
  
  
[GPU产品源代码被盗？AMD 证实称仅为测试文件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492594&idx=2&sn=27e526ff731e1f9951a6248f843a87d0&chksm=ea94d298dde35b8e3f4e99d958db54656420feec1396f5842de76d913376f07b8329219964ca&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/06/arm-warns-of-actively-exploited-zero.html  
  
  
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
  

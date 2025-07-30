#  速修复！Juniper Junos OS 漏洞使设备易受攻击   
THN  代码卫士   2023-08-21 13:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**网络硬件公司 Juniper Networks 发布“周期外”安全更新，修复位于 Junos OS的 J-Web 组件中的多个漏洞。攻击者可组合利用这些漏洞在易受攻击设备上实现远程代码执行。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTRic6QPkzc7gLicr3K7T50Z4MTd5MKibeJicNU9JicwAl18siawRTKYp9U8HunKOx7hwrA4meK97AhXJZg/640?wx_fmt=png "")  
  
  
这四个漏洞的CVSS评分均为 9.8，属于“严重”漏洞，影响 SRX 和 EX 序列上 Junos OS 所有版本。  
  
2023年8月17日，Juniper 公司指出，“通过组合利用这些漏洞，未认证的网络攻击者可在设备上远程执行代码。” J-Web 接口可使用户配置、管理和监控 Junos OS 设备。这些漏洞简述如下：  
  
- CVE-2023-36844和CVE-2023-36845（CVSS评分5.3）是位于 J-Web 中的两个 PHP 外部变量修改漏洞，可使未认证的网络攻击者控制某些重要的环境变量。  
  
- CVE-2023-36846和CVE-2023-36847（CVSS评分5.3）是位于 Jniper Networks Junos OS 中的两个关键函数缺乏认证漏洞，可导致未认证的网络攻击者对文件系统完整性造成有限影响。  
  
  
  
威胁着可发送特殊构造的请求，修改某些 PHP 环境变量或者通过 J-Web上传任意文件，成功利用上述问题。  
  
这些漏洞已在如下版本中修复：  
  
- EX 系列：Junos OS 版本 20.4R3-S8、 21.2R3-S6、 21.3R3-S5、 21.4R3-S4、 22.1R3-S3、 22.2R3-S1、 22.3R2-S2、 22.3R3、 22.4R2-S1、 22.4R3和23.2R1。  
  
- SRX 系列：Junos OS 版本20.4R3-S8、21.2R3-S6、21.3R3-S5、21.4R3-S5、22.1R3-S3、22.2R3-S2、 22.3R2-S2、 22.3R3、22.4R2-S1、22.4R3和23.2R1。  
  
  
  
建议用户应用必要修复方案，缓解潜在的远程代码执行威胁。Juniper Networks 公司建议用户禁用 J-Web 或仅允许访问受信任主机，作为缓解措施。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2023中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=1&sn=8154b433ae2be87ccbae15bc0fb09a00&chksm=ea94b543dde33c55c168c44e830d62b03e9b34ca072871d10156273a3f282cab7ccc42b9b430&scene=21#wechat_redirect)  
  
  
[奇安信发布《2023中国软件供应链安全分析报告》开源软件供应链的系统化安全治理需加速落地](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517165&idx=1&sn=c9c0c224c7eb021b526c03c079891642&chksm=ea94b287dde33b912cfba6f6ea911ca71a9002d5ca0a6a099ed818f2e235940920185d993340&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Juniper Networks 修复开源操作系统 Junos OS 等中的多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494029&idx=3&sn=b6db3afe8845dee92efc83700819cf0f&chksm=ea94d8e7dde351f1a8ec5f666776a3afa7f1795e000ac8276e56d29c8e6d4a516155ee867fbf&scene=21#wechat_redirect)  
  
  
[Juniper 修复 Junos OS 中的多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488240&idx=2&sn=7e7f6d4dd4445550e20a1cd2e98ed70d&chksm=ea97239adde0aa8cde602694af95833dc831143020cd6d87601452960bbade08fa41b4c4a8ca&scene=21#wechat_redirect)  
  
  
[Juniper Junos OS 高危漏洞影响企业网络设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514366&idx=1&sn=76a62227dec3a36c7b849a06adbeb4a4&chksm=ea948994dde3008220487af4d66da9e2fe0056dcbd1c25faa88e487e8c99b443702524fd34fe&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/08/new-juniper-junos-os-flaws-expose.html  
  
  
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
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523576&idx=2&sn=cae33dc0a4154ffe056c01f3975eb200

#  ImageMagick存在栈缓冲溢出漏洞，可导致RCE  
Ddos  代码卫士   2025-07-15 10:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**使用广泛的开源图片操作套件 ImageMagick 中存在一个漏洞，在涉及图片文件名模板的某些条件下可导致栈缓冲溢出。该漏洞编号为CVE-2025-53101，CVSS评分为7.4。ImageMagick 在处理恶意文件命名模式时，利用该漏洞可使系统面临内存损坏和远程代码执行风险。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRricMILs2Q9ibO48qmFh8TmiaoE7Lh5FlLiafwwhGn3FOTMjiaLHqB01LFjebLWV59R5iaiav6KKmcq8bxQ/640?wx_fmt=png&from=appmsg "")  
  
  
ImageMagick 在安全通告中提到，“在文件名称模板中指定多个连续的 %d 格式说明符，导致内部指针算法在栈缓冲区下面生成一个地址，从而通过vsnprintf() 造成栈溢出。”  
  
ImageMagick 是一款强大的开源软件套件，可通过200多种格式创建、编辑、转换和展示图片。它广泛用于网站、云服务、内容管道和图片工具中，尤其用于通过 CLI 命令和API自动化处理图片。  
  
该漏洞位于 image.c 中的 InterpretImageFilename() 函数中，格式说明符如 %d、%0和%x用于为所处理的图片动态创建文件名称。在正常情况下，ImageMagick 使用 FormatLocaleString()以证书替换格式说明符。然而，计算在哪写入该输出的代码使用的是有问题的指针算法。  
  
安全公告提到，“偏移量变量累积递增，以修正 %d 等输出长度，但使用一个静态偏移量 +- (4-field_width) 的设计，会在 % 说明符连续出现时导致偏移量过度增加。”这就导致负索引，即写指针移动到堆栈缓冲区开头之前的位置。结果，vsnprintf() 函数的调用开始覆盖越界内存。该漏洞属于CWE-124：缓冲区写越界类型漏洞，即内存被写入所分配空间之前的地址，通常导致崩溃或可利用的内存损坏后果。  
  
虽然在正常配置下，该漏洞不容易遭RCE利用，但在在自动化环境下可被触发，不受信任的输入控制文件名称模板如web服务器、CI/CD管道或共享图形处理程序等。  
  
如遭成功利用，该漏洞可导致：应用崩溃、信息泄露、RCE（尤其是受用户控制的模板被直接传给 CLI 命令时）。该漏洞最初是通过 AddressSanitizer 检测到的，并被标记为栈缓冲溢出漏洞，证明它可能导致运行时环境不稳定。  
  
该漏洞已在 ImageMagick 7.1.2-0和6.9.13-26中修复。用户应立即升级至其中一个已修复版本。修复方案修改了偏移量处理逻辑，确保模板解析与实际的字段宽度一致，从而解决了该漏洞的核心问题。  
  
  
开源  
卫士试用地址：  
https://oss.qianxin.com/#/login  
  
  
代码卫士试用地址：https://sast.qianxin.com/#/login  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2025中国软件供应链安全分析报告》全文](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523516&idx=1&sn=0b6fc53ba92e7b5135395b67fff6a822&scene=21#wechat_redirect)  
  
  
[CrushFTP 提醒用户立即修复已遭利用的 0day 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519338&idx=1&sn=ec0b92257a640cd98dd5d59c00746548&scene=21#wechat_redirect)  
  
  
[CompleteFTP 路径遍历缺陷可导致服务器文件遭删除](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513283&idx=2&sn=1191567d5c667a5413e00d453ef8b5da&scene=21#wechat_redirect)  
  
  
[开源OS FreeBSD 中 ftpd chroot 本地提权漏洞 (CVE-2020-7468) 的技术分析](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499356&idx=1&sn=f95ec3f9ca222c3ccef3d1162af259b8&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://securityonline.info/imagemagick-flaw-cve-2025-53101-stack-buffer-overflow-allows-potential-remote-code-execution/  
  
  
题图：  
Pixabay Licen  
se  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  

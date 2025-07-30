#  Linux USB音频驱动漏洞正被恶意USB设备在野利用   
 FreeBuf   2025-04-12 10:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
Linux内核中的USB音频驱动存在一个可能导致内存越界读取的关键漏洞，该漏洞已由SUSE公司的Takashi Iwai通过最新补丁修复。攻击者若获得系统物理访问权限，可利用恶意USB设备实现权限提升、篡改系统内存或执行任意代码。  
  
  
Linux基金会Greg Kroah-Hartman于2024年12月14日提交的修复补丁，显著提升了使用USB音频设备系统的驱动稳定性和安全性。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibfHJsFO5icMuraoNACD1HJWMvAolNONSiaK3w9iafvibjUGrcfvac9NI3qeicdoIHByMXDGqicxzzibETeg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**01**  
  
  
  
**攻击原理**  
  
  
当USB音频设备提供的描述符中bLength值小于预期结构大小时，漏洞就会被触发。原始代码中驱动程序盲目假设描述符完整，并尝试读取其时钟ID或引脚数组等字段。  
  
  
若描述符因硬件缺陷或人为篡改被截断，驱动程序可能越过已分配的内存缓冲区，读取到相邻非目标区域。这种越界读取可能泄露内核内存中的敏感数据（如指针或用户信息），或通过访问无效内存地址导致系统崩溃。  
  
  
最坏情况下，熟练的攻击者可结合其他漏洞利用链实现权限提升或任意代码执行，但此类攻击需要精确控制USB设备并存在其他漏洞配合。  
  
  
**02**  
  
  
  
**安全增强措施**  
  
该漏洞源于驱动程序未验证USB音频设备提供的时钟描述符bLength字段。缺乏这些检查时，长度不足的畸形或恶意构造描述符可能触发越界内存访问，导致系统崩溃或遭受攻击。  
  
  
补丁（commit ab011f7439d9bbfd34fd3b9cef4b2d6d952c9bb9）在时钟描述符验证函数中引入了严格的完整性检查。虽然仅修改了sound/usb/clock.c文件的24行代码，但对依赖Linux进行音频处理的发烧友、开发者和企业影响重大。  
  
  
该漏洞最初由Google的Benoît Sevens报告，补丁已反向移植到稳定内核分支，确保各发行版用户都能获得安全增强。时钟选择器描述符（包含可变长度数组和附加字段）针对USB Audio Class（UAC）2和3版本进行了更全面的验证。  
  
  
用户可通过下载linux-ab011f7439d9bbfd34fd3b9cef4b2d6d952c9bb9.tar.gz更新内核获取该补丁。这一进展体现了Linux社区持续快速修复漏洞、维护系统健壮性的承诺。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317737&idx=1&sn=99fed7dcc16d21127eb031fd187b35f5&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317886&idx=1&sn=50bb777ea9b038b842812efd1d390806&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317886&idx=2&sn=d71ff253383c30e9a56386b7e7ef8f45&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif "")  
  

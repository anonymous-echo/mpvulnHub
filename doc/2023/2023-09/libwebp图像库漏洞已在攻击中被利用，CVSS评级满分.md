#  libwebp图像库漏洞已在攻击中被利用，CVSS评级满分   
看雪学苑  看雪学苑   2023-09-28 17:59  
  
近日，Google为libwebp安全漏洞分配了一个新的CVE ID（CVE-2023-5129），该漏洞获得了最高的10.0严重性评级,可能造成严重后果，如崩溃、任意代码执行以及未经授权访问敏感信息。  
  
  
起初，谷歌将此漏洞披露为Chrome漏洞，编号为CVE-2023-4863，涉及WebP中的堆缓冲区溢出，影响的是116.0.5845.187之前的Google Chrome版本。  
  
  
但Rezillion的一项分析显示，许多广泛使用的应用程序、代码库、框架和操作系统都存在CVE-2023-4863漏洞：“该软件包在尺寸和速度方面表现出色，优于JPEG和PNG。因此，大量软件、应用程序和包都采用了这个库，甚至采用了libwebp为其依赖项的包。libwebp的广泛使用显著扩大了攻击面，引起用户和组织的严重担忧。”  
  
  
然而，谷歌将CVE-2023-4863错误地界定为仅影响Chrome的漏洞，这一决策掩盖了一个事实——它实际上影响所有依赖libwebp库处理WebP图像的应用程序，其影响范围比之前预想的要广泛。  
  
  
据了解，这个漏洞存在于libwebp用于无损压缩的Huffman编码算法中，它使攻击者能够使用恶意构造的HTML页面执行越界内存写入：  
  
  
使用特制的WebP无损文件，libwebp可能会将数据越界写入堆。ReadHuffmanCodes()函数通过预先计算的大小数组kTableSize来分配HuffmanCode缓冲区的大小。color_cache_bits值定义要使用的大小。kTableSize数组仅考虑8位一级表查找的大小，而不考虑二级表查找的大小。libwebp允许使用最多15位的代码（MAX_ALLOWED_CODE_LENGTH）。当BuildHuffmanTable()试图填充二级表时，可能会写入越界数据。对较小的数组进行的越界写入发生在ReplicateValue中。  
  
  
现如今谷歌已正式将该漏洞认定为libwebp（用于编码和解码WebP格式图像的开源库）的一个漏洞。这一决定具有重要意义，因为业界最初未认识到其作为许多使用libwebp的项目的潜在安全威胁（如1Password、Signal、Safari、Mozilla Firefox、Microsoft Edge、Opera和原生Android网页浏览器）。  
  
  
  
编辑：左右里  
  
资讯来源：thehackernews  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
路由器              
  
能够实时记录网络上的数据库活动，对数据库操作进行细粒度审计的合规性管理，对数  
据库遭受到的风险行为进行告警，对攻击行为进行阻断。  
  
它通过对用户访问数据库行为的记录、分析和汇报，用来帮助用户事后生成合规报告、  
事故追根溯源，同时加强内外部数据库网络行为记录，提高数据资产安全。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  

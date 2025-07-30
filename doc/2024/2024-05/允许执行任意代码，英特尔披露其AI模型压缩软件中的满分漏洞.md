#  允许执行任意代码，英特尔披露其AI模型压缩软件中的满分漏洞   
看雪学苑  看雪学苑   2024-05-24 18:04  
  
近日，英特尔披露了其AI模型压缩软件Neural Compressor中的一个最高严重性漏洞，该漏洞可能允许未经身份验证的攻击者在受影响系统上执行任意代码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GIHyrCqRufSwZKotZHJgkVIQib0kiaaudkeTkiaDRy4CkRhZ41icia0w4bW6Iw9TVPawfoKTpE9btUPzg/640?wx_fmt=png&from=appmsg "")  
  
  
英特尔确认该漏洞（CVE-2024-22476，CVSS评分10.0）源于不当的输入验证，即未能正确对用户输入进行清理。该芯片制造商根据CVSS评分标准将这个漏洞评定为最高严重性，因其可以远程利用，复杂性低，对数据的保密性、完整性和可用性具有很高影响。而攻击者不需要任何特殊权限，也不需要用户交互即可利用漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GIHyrCqRufSwZKotZHJgkVicTsaxXHIPkzMhIl28iaAftg2oEUDYCOusBqCQe5GT9td7eGo92aa2Iw/640?wx_fmt=png&from=appmsg "")  
  
  
据了解，英特尔Neural Compressor是一个开源的Python库，旨在压缩优化深度学习模型，用于计算机视觉、自然语言处理、推荐系统等各种用例。压缩技术包括神经网络剪枝、通过过程调用量化减少内存需求以及将更大的模型提炼为性能相似但更小的模型等。AI模型压缩技术的目标是为了帮助实现在各种硬件设备上部署AI应用，特别是手机等计算能力有限或受限的设备。  
  
  
该漏洞影响英特尔Neural Compresso早于2.5.0的版本。英特尔建议使用该软件的组织尽快升级到2.5.0或更高版本。更新地址为https://github.com/intel/neural-compressor/releases。  
  
  
除了Neural Compressor的漏洞外，英特尔本周还披露了其固件中另外五个权限升级漏洞。这些漏洞（CVE-2024-22382、CVE-2024-23487、CVE-2024-24981、CVE-2024-23980、CVE-2024-22095）均为输入验证漏洞，CVSS严重性评分从7.2到7.5不等。  
  
  
  
编辑：左右里  
  
资讯来源：intel、darkreading  
  
转载请注明出处和本文链接  
  
  
  
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
  

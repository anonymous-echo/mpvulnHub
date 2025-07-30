#  ARM Mali GPU驱动程序中的零日漏洞正被利用   
看雪学苑  看雪学苑   2024-06-13 18:02  
  
前不久芯片巨头Arm披露了一个正被在野利用的零日漏洞（CVE-2024-4610），该漏洞影响广泛使用的Mali GPU内核驱动程序，可能使众多设备面临恶意攻击风险。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fez3kDvoZN8ph5zWxP0z5xMMDEmOsa2zwR06bC6FAfCBfwnBgJUIZ34lFW75MToUSH6qSlUCFgCA/640?wx_fmt=png&from=appmsg "")  
  
> Mali GPU在移动世界中无处不在，主要应用于基于ARM体系结构的各种智能手机、平板电脑及其他移动设备上，为所有嵌入式图形 IP 和视频 IP 需求提供了完善的解决方案。虽然Arm未明确指出哪些设备最易受攻击，但可以假设在补丁广泛可用之前，大量用户都面临风险。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fez3kDvoZN8ph5zWxP0z5xTYdp9aKtyYGyqPBiclia9Rf0agINMwbdPjVjmccMFrrVTKiaWZCZIIrsw/640?wx_fmt=png&from=appmsg "")  
  
  
Arm在公告中指出：“该漏洞使得本地非特权用户可以执行不当的GPU内存处理操作，以获取对已释放内存的访问权限。” 这种访问可能导致严重后果，包括未经授权的数据访问和系统操纵。受影响的驱动程序版本包括：  
  
Bifrost GPU内核驱动程序（从r34p0到r40p0的所有版本）  
  
Valhall GPU内核驱动程序（从r34p0到r40p0的所有版本）  
  
  
Arm已确认有关漏洞在现实场景中被利用的报告，并建议受到此问题影响的用户升级系统。CVE-2024-4610已在最新的驱动程序更新r41p0中得到解决，适用于Bifrost和Valhall GPU内核驱动程序。但要注意到补丁的部署取决于设备制造商和供应商在整合和分发更新方面的效率。组织仍须保持警惕，确保及时更新以减轻与此漏洞相关的风险。  
  
  
  
编辑：左右里  
  
资讯来源：Arm  
  
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
  

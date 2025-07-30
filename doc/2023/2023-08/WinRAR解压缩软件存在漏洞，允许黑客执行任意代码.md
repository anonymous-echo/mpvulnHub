#  WinRAR解压缩软件存在漏洞，允许黑客执行任意代码   
看雪学苑  看雪学苑   2023-08-21 17:59  
  
WinRAR是最为流行的Windows解压缩软件之一，据称拥有数以亿计的用户。近日，趋势科技Zero Day Initiative在该软件中发现了一个高危漏洞——打开压缩文件时会允许黑客在计算机上执行任意代码。  
  
  
据了解，该漏洞（CVE-2023-40477）存在于恢复卷的处理过程中，原因是缺乏对用户提供数据的正确验证。2023年6月8日，Zero Day Initiative的研究员“goodbyeselene”将该漏洞报告给了RARLAB厂商。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EnKARAaBew7OmHqWmDdjsNa0YicZwsavNfrKu3CTagERXeYy8yBxe3J030MFAUrLckkxtgWxGR2rg/640?wx_fmt=png "")  
  
  
ZDI在公告中写道：“此漏洞允许远程攻击者在受影响的RARLAB WinRAR安装上执行任意代码。利用此漏洞需要用户交互（如打开恶意文件）。具体的缺陷存在于恢复卷的处理过程中。问题在于缺乏对用户提供数据的正确验证，这可能导致内存访问超出已分配缓冲区的末尾。攻击者可以利用此漏洞在当前进程的上下文中执行代码。”  
  
  
从实际角度来看，攻击者欺骗用户执行所需操作并不会太过困难，而且考虑到WinRAR的庞大用户群，攻击者有足够的几率进行成功利用。对此此类安全风险，谨慎打开RAR文件、使用杀毒软件进行扫描是一个良好的安全习惯。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EnKARAaBew7OmHqWmDdjsNm69GO4pIBuaknM9lUoLJiaT8RvKvPTziaMtyvZKJ4wey3HriaSKubdmFw/640?wx_fmt=png "")  
  
  
2023年8月2日，官方在最新发布的WinRAR 6.23版本中已修复了此漏洞，建议WinRAR用户立即进行安全更新。  
  
更新地址：https://www.win-rar.com/download.html?&L=7  
  
  
值得注意的是，微软目前正在测试Windows 11对RAR、7-Zip等文件的原生支持，此后若是对其高级功能没有需求，将有可能不再需要WinRAR等第三方软件。  
  
  
  
编辑：左右里  
  
资讯来源：Zero Day Initiative、WinRAR  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
抓鸡   
  
即设法控制电脑，将其沦为肉鸡。  
  
  
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
  

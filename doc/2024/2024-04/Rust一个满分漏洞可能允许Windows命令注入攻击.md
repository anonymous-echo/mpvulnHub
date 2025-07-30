#  Rust一个满分漏洞可能允许Windows命令注入攻击   
看雪学苑  看雪学苑   2024-04-10 18:00  
  
4月9日，Rust安全响应工作组收到通知，Rust标准库在使用Command API在Windows上调用批处理文件（bat和cmd扩展名）时，未能正确转义参数。攻击者能够控制传递给生成进程的参数，通过绕过转义来执行任意shell命令。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Hibzicic5Fdjz6CQ5oQ4SPOITZCqGBgsGpfZHaKzAksSXApicySBniaazcY3trz0MBZkdIyXRbZTBo3Iw/640?wx_fmt=png&from=appmsg "")  
  
  
  
该漏洞（CVE-2024-24576，CVSS评分为最高的10分）由安全研究员RyotaK发现并报告，可被未经身份验证的攻击者在远程、低复杂度攻击和无用户交互的情况下利用。  
  
  
据公告  
（  
https://blog.rust-lang.org/2024/04/09/cve-2024-24576.html  
）  
，在Windows上，如果程序代码或其依赖项调用执行带有不受信任参数的批处理文件，则1.77.2之前的所有Rust版本都会受到影响。其他平台或Windows上的其他用途不受影响。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Hibzicic5Fdjz6CQ5oQ4SPOIT50v5jan5EEMogk06qz7bnWXqibI3CBrCZOrGibevk7dic7XCX0rrI9oUw/640?wx_fmt=png&from=appmsg "")  
  
  
由于cmd.exe的复杂性，Rust安全团队无法找到一个能在所有情况下正确转义参数的解决方案。因此，他们不得不改进转义代码的健壮性并修改Command API——如果Command API在生成进程时无法安全转义参数，则会返回InvalidInput错误。  
  
  
Rust安全响应工作组表示会在最新发布的Rust 1.77.2中修复漏洞。另外，“如果您自己实现转义或仅处理受信任的输入，在Windows上您还可以使用CommandExt::raw_arg方法来绕过标准库的转义逻辑。” 工作组补充道。  
  
  
RyotaK在给用户的建议中说，为了防止批处理文件的意外执行，用户应考虑将批处理文件移动到未包含在PATH环境变量中的目录。——在这种情况下，除非指定完整路径，否则批处理文件将不会被执行。  
  
  
  
编辑：左右里  
  
资讯来源：rust官网、securityonline  
  
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
  

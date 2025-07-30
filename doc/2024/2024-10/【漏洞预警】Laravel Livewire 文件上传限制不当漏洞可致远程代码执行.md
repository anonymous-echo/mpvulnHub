#  【漏洞预警】Laravel Livewire 文件上传限制不当漏洞可致远程代码执行   
cexlife  飓风网络安全   2024-10-10 22:45  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02DwgrW9UGrJR6lkGfiaribcP64b8F4A5zQJEWTDMAlIhibEkxB0ibv4qOntfyuXPkfmBaq0Vwkp6Asuw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**Laravel  Livewire发布新版本,修复了一处文件上传限制不当漏洞,可致远程代码执行,该漏洞是由于Laravel  Livewire文传文件时根据MIME 类型猜测文件扩展名,而不验证文件名中的实际文件扩展名,攻击者可上传具有有效MIME类型（如 “image/png”）和 “.php” 文件扩展名的文件来绕过验证,在满足一定条件下可进行远程代码执行攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02DwgrW9UGrJR6lkGfiaribcP65GZsz7woialIr2oh8Xbb1gkqqwPpq7R78ibNAwyZiaoSD1P6iblx4nTtg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02DwgrW9UGrJR6lkGfiaribcPJ1FI8c9Kda3XdIcicLJr1ticwShDHZ0X5z9ibpCSiaTl43IyKL3RNcD1Tw/640?wx_fmt=png&from=appmsg "")  
  
**修复建议:**  
  
**正式防护方案:**针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本:livewire/livewire >= 2.12.7livewire/livewire >= 3.5.2**下载链接:**https://github.com/livewire/livewire/releases安装前,请确保备份所有关键数据,并按照官方指南进行操作。安装后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。  
  

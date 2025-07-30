#  【漏洞预警】IP-guard WebServer < 4.82.0609.0任意文件读取漏洞   
cexlife  飓风网络安全   2024-04-16 19:03  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01IDd8Z6ATfVTOyBVa8JQibNE4dpt8n7PicRGDuYF2wWwaNoqKTYYXL4vd61JM5KiaxI1OSOCKLUBOBQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
IP-guard是溢信科技推出的终端数据安全防护软件,IP-guard WebServer <4.82.0609.0存在任意文件读取漏洞,由于服务器端的脚本（view.php）未正确验证用户的输入,攻击者可利用doc参数读取任意路径文件,可能导致敏感数据泄露、系统权限被获取。**影响范围:**ip-guard(-∞, 4.82.0609.0)修复方案:将ip-guard升级至4.82.0609.0及以上版本使用路径白名单来增强文件路径参数的验证**参考链接:**http://www.newcase.com.cn/cn/xw_view.asp?id=1011&xwlb_id=4  

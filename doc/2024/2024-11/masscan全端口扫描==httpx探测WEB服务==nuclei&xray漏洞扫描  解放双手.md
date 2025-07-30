#  masscan全端口扫描==>httpx探测WEB服务==>nuclei&xray漏洞扫描 | 解放双手   
 黑白之道   2024-11-24 00:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
**01**  
  
**工具介绍**  
  
# Masscan2Httpx2Nuclei&xray  
  
****  
masscan全端口扫描==>httpx探测WEB服务==>nuclei&xray漏洞扫描 解放双手  
  
**02**  
  
**环境准备**  
  
  
- 自备nuclei\httpx\xray_linux_amd64放脚本同目录(文件名请保持不变)  
  
- 自备masscan python3环境  
  
- 将要扫描的资产放在ip.txt里面  
  
- python3 Masscan2Httpx2Nuclei.py -i ip.txt -p 1-65535 --rate 2000  
  
- nuclei默认只扫描medium,high,critical级别，方便打野，如有其他需求请自行更新  
  
- 睡一觉  
  
## 没啥技术含量的脚本，能用就行  
##   
##   
  
```
https://github.com/robertdavidgraham/masscan/
https://github.com/projectdiscovery/httpx/
https://github.com/projectdiscovery/nuclei/
https://github.com/chaitin/xray/
```  
  
**03**  
  
**工具下载**  
  
****https://github.com/whoisavicii/Masscan2Httpx2Nuclei-Xray****  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  

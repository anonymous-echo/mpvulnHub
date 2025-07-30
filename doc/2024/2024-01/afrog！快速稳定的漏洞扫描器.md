#  afrog！快速稳定的漏洞扫描器   
 白帽学子   2024-01-27 08:11  
  
**工具介绍**  
  
afrog 是一款快速、稳定的高性能漏洞扫描器。  
支持用户自定义PoC，内置CVE、CNVD、默认密码、信息泄露、指纹识别、越权访问、任意文件读取、命令执行等多种类型。  
通过afrog，网络安全专业人员可以快速验证和修复漏洞，这有助于增强他们的安全防御能力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/LYy9xnADcdh9unicqLrjLhBW1unR4NLv9P4NZPltH7KgcKcdiaIODibl5glx3Ztyu8DPPVQqy8mt1o4d12gVPNicdw/640?wx_fmt=jpeg "")  
  
  
**工具使用**  
  
默认情况下，afrog 会扫描所有内置 PoC，如果发现任何漏洞，它会自动创建一个 HTML 报告，并以扫描日期作为文件名。  
```
afrog -t https://example.com
```  
  
要执行自定义 PoC 目录，可以使用以下命令：  
```
afrog -t https://example.com -P mypocs/
```  
  
  
您也可以同时扫描多个 URL。  
```
afrog -T urls.txt
```  
  
**详细信息 运行 afrog 时出现警告，如果您看到以下错误消息，这意味着你需要修改配置文件。**  
> [ERR] ceye reverse service not set: /home/afrog/.config/afrog/afrog-config.yaml  
  
  
  
  
后台回复：  
**240127**  
，获取工具  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/LYy9xnADcdhic61NkXCWKufScrUrmmsG8tztWD8fDRiatPUaljxxpKc1PpnYNFjPibU5FwJmcuO4mZoQg5aXsAcog/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
声明：该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白名单。  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与本公众号无关。  
  
✦  
  
✦  
  

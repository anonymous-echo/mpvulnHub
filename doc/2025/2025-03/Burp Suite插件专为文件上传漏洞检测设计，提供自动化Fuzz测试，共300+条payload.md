#  Burp Suite插件专为文件上传漏洞检测设计，提供自动化Fuzz测试，共300+条payload   
T3nk0  无影安全实验室   2025-03-07 20:56  
  
免责声明：  
本篇文章仅用于技术交流，  
请勿利用文章内的相关技术从事非法测试  
，  
由于传播、利用本公众号无影安全  
实验室所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号无影安全实验室及作者不为此承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把"**无影安全实验室**  
"设为星标，这样更新文章也能第一时间推送！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3GHDOauYyUGbiaHXGx1ib5UxkKzSNtpMzY5tbbGdibG7icBSxlH783x1YTF0icAv8MWrmanB4u5qjyKfmYo1dDf7YbA/640?&wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
安全工具  
  
  
  
## 0x01 工具介绍  
  
本Burp Suite插件专为文件上传漏洞检测设计，提供自动化Fuzz测试，共300+条payload。效果如图  
  
![14](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFEQZBqkBQhzwaYQzKbE0AflQSRicyCt7DHxJxjl941ric5qefjAW6ok73fsXxPLDib92Bm2tbGUx9fg5w/640?wx_fmt=png&from=appmsg "")  
### 🛡️ WAF绕过技术  
- **后缀变异**  
：ASP/ASPX/PHP/JSP后缀混淆（空字节、双扩展名、特殊字符等）  
  
- **内容编码**  
：MIME编码、Base64编码、RFC 2047规范绕过  
  
- **协议攻击**  
：HTTP头拆分、分块传输编码、协议走私  
  
### 🖥️ 系统特性利用  
- **Windows特性**  
：  
  
- NTFS数据流（::$DATA）  
  
- 保留设备名（CON, AUX）  
  
- 长文件名截断  
  
- **Linux特性**  
：  
  
- Apache多级扩展解析  
  
- 路径遍历尝试  
  
- 点号截断攻击  
  
### 🎭 内容欺骗  
- 魔术字节注入（GIF/PNG/PDF头）  
  
- SVG+XSS组合攻击  
  
- 文件内容混淆（注释插入、编码变异）  
  
## 0x02 安装方法  
1. 确保已安装Burp Suite Professional  
  
1. 在Burp Extender中点击"Add"  
  
1. 选择下载的Upload_Auto_Fuzz.py  
文件  
  
1. 点击"Next"直到安装完成  
  
## 0x03 使用指南  
##    1、拦截文件上传请求  
  
   2、右键请求内容 → "Send to Intruder"  
  
   3、Positions内将Content-Disposition开始，到文件内容结束的数据作为fuzz对象，如图  
  
![11](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFEQZBqkBQhzwaYQzKbE0AflQrzT99Mlbawc9Q7diaC3sxchsxkadtPPgxKFwfRWkRsbYghl9FW3sL3w/640?wx_fmt=png&from=appmsg "")  
  
4、在Intruder的"Payloads"标签中选择：  
```
Payload type: Extension-generated
```  
```
Select generator: upload_auto_fuzz
```  
  
  
![13](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFEQZBqkBQhzwaYQzKbE0AflQdrTuxyZsCLIhricZO21gPqKHsZcvuRjg1VFOTzMFqCKtH6auAibVkerQ/640?wx_fmt=png&from=appmsg "")  
  
5、取消Payload encoding选择框，如图![12](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFEQZBqkBQhzwaYQzKbE0AflQUfS99D6VltZZvOrCxYzYX8L4YHqiaCFpKXUI5fUsLtJ2kFfM2PgP7Ig/640?wx_fmt=png&from=appmsg "")  
  
  
  
Payload分类说明  
<table><thead><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><th style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);max-width: 100%;box-sizing: border-box !important;color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;height: auto;border-radius: 0px;min-width: 85px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">类别</span></section></th><th style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);max-width: 100%;box-sizing: border-box !important;color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;height: auto;border-radius: 0px;min-width: 85px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">样本payload</span></section></th><th style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);max-width: 100%;box-sizing: border-box !important;color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;height: auto;border-radius: 0px;min-width: 85px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">检测目标</span></section></th></tr></thead><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(66, 75, 93);background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">后缀绕过</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><code style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">filename=&#34;test.asp;.jpg&#34;</span></code></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">文件类型校验缺陷</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(66, 75, 93);background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">Content-Disposition</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><code style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">content-Disposition: form-data</span></code></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">头解析大小写敏感性</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(66, 75, 93);background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">魔术字节</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><code style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">GIF89a;&lt;?php...</span></code></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">内容检测绕过</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(66, 75, 93);background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">协议走私</span></section></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><code style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">Transfer-Encoding: chunked</span></code></td><td style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgba(204, 204, 204, 0.4);max-width: 100%;box-sizing: border-box !important;min-width: 85px;border-radius: 0px;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">WAF协议解析差异</span></section></td></tr></tbody></table>  
## 0x04 工具下载  
  
**点****击关注**  
**下方名片****进入公众号**  
  
**回复关键字【250307****】获取**  
**下载链接**  
  
  
**最后推荐一下内部小密圈，干货满满，物超所值，内部圈子每增加100人，价格将上涨20元，越早进越优惠！！！**  
  
****  
  

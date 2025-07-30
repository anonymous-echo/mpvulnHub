#  自动化JS提取与漏洞检测工具 - JSSS-Find   
kk12-30  安全洞察知识图谱   2025-04-24 00:30  
  
**免责声明**  
 由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号安全洞察知识图谱及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
## 1详细介绍  
  
JSSS-Find 是一款用于自动化提取JS文件、API接口测试以及暴露端点检测的工具。通过访问指定URL，提取并分析JS文件中的接口、路径和敏感信息，帮助开发者发现潜在的安全漏洞。该工具支持对网站进行fuzz测试、漏洞检测、真实浏览器中访问Vue接口等功能。适用于安全研究人员和开发者进行漏洞检测与接口审计。  
## 功能  
- **JS文件提取**  
从网页内容中自动提取JS文件链接(适用Webpack框架)。  
  
- **接口路径提取**  
支持精简和全量接口路径的提取，自动化识别JS中的接口路由。  
  
- **敏感信息提取**  
提取JS文件中的敏感信息，如API密钥、JWT令牌、数据库凭证等。  
  
- **Fuzz测试**  
对提取的接口路径进行fuzz测试、403bypass，发现潜在的漏洞。  
  
- **漏洞检测**  
通过规则检测每个接口的常见漏洞，如Spring Actuator、Swagger未授权等。  
  
- **Vue接口检测**  
在真实浏览器环境下测试Vue接口的状态码和标题。  
  
更新记录  
  
V3.6.0：使用AI进行JS代码审计并自动构造请求包进行测试  
  
V3.5.4：添加了两个参数 -filter int过滤重复响应的阈值，超过此数量的相同大小响应将被过滤 (default 6) -fuzznum int批量检测时，每个URL的精简接口数量阈值，超过该值则跳过fuzz测试，0表示无限制  
  
V3.5.1：新增-t参数控制并发线程，不加参数默认50  
  
V3.5：支持批量URL扫描，优化报告模板  
  
V3.4：代码重构使用高并发线程，速度提升百分之50  
  
V3.3：修复扫描https的IP地址时证书错误问题  
## 使用方法  
  
1. 提取JS文件并分析  
#### 访问URL提取JS文件  
```
JSSS-Find.exe -u <URL> [-fuzz][-v][-vueBrowser]
```  
- -u <URL>  
: 指定需要提取JS文件和进行测试的URL。  
  
- -fuzz  
: 启用fuzz测试。  
  
- -m 使用深度fuzz模式  
  
- -v  
: 启用漏洞检测模式，速度较慢。  
  
- -vueBrowser  
: 在真实浏览器环境中访问Vue接口。  
  
#### 读取本地JS文件目录  
```
JSSS-Find.exe -f <本地需要读取的JS目录> [-fuzz][-v][-vueBrowser]
```  
- -f <本地JS目录>  
: 指定本地目录，工具会自动分析该目录下的所有JS文件。  
  
- 可联动Packer-Fuzzer工具获取的js  该工具下载的js在tmp文件夹中  
2. 通过Cookie和Header进行请求  
#### 设置自定义的Cookie和Headers  
```
JSSS-Find.exe -u <URL> -cookie "SESSIONID=abcd" -header "Token:abc;User-Agent:MyUA"
```  
- -cookie  
: 设置自定义Cookie。  
  
- -header  
: 设置自定义请求Headers。  
  
3. 保存和查看结果  
  
工具会在指定的目录中保存提取结果，包括：  
- 精简正则接口提取.txt  
- 全量正则接口提取.txt  
- 敏感信息提取.txt  
- fuzz_success.txt  
(仅在启用fuzz时生成)  
  
- vuln_result.txt  
(仅在启用漏洞检测时生成)  
  
- vue_browser_result.txt  
(仅在启用Vue浏览器检测时生成)  
  
## 示例  
```
JSSS-Find.exe -u https://example.com -fuzz -v
```  
  
上述命令会从https://example.com  
提取JS文件、进行接口fuzz测试，并检测常见漏洞。  
  
项目地址  
  
https://github.com/kk12-30/JSSS-Find  
## 2免费社区  
  
安全洞察知识图谱星球是一个聚焦于信息安全对抗技术和企业安全建设的话题社区，也是一个  
**[免费]**  
的星球，欢迎大伙加入积极分享红蓝对抗、渗透测试、安全建设等热点主题  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8aia4mibs0I8I42MrYYOSE2DVEpVpPHvxufMGR0yufpgouwIXEl7H5eLm0MgolGFQMDFIrKLTxaYIQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicQq71SAtTAWic1cOJibOLQwBVW5CyLECTgGtHtUqCGvg5Rn3VicwAKZNJXmkKX9BemxOzDdzwv6cocQ/640?wx_fmt=jpeg&from=appmsg "")  
  

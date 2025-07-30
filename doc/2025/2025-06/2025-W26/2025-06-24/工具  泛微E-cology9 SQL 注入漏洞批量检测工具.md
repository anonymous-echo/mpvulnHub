> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNzQxMjQ4Ng==&mid=2247484252&idx=1&sn=5e962271608318dff0b47a2909cca7ea

#  工具 | 泛微E-cology9 SQL 注入漏洞批量检测工具  
 YuanQiu安全   2025-06-24 07:43  
  
## 免责声明  
> 由于传播、  
本公众号  
所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任！  
一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉，谢谢！  
  
## 一、漏洞简述  
  
QVD-2025-23834  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
敏感信息泄露  
  
**简述：**  
泛微E-cology9存在SQL注入漏洞，  
攻击者可利用该漏洞获取数据库敏感信息，并可能利用Ole组件导出为Webshell实现远程代码执行，进而获取服务器权限。  
  
**0x04 影响版本**  
- 泛微E-cology9  
  
## 二、工具介绍  
  
本工具用于批量检测泛微E-cology9中/js/hrm/getdata.jsp接口存在的 SQL 注入漏洞（DVB-2025-9428/QVD-2025-23834）  
  
****## 三、工具使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/w7fEMwB7GbyiaRlm4dLHudzDdp6eRxPW0oWficI2qjIib2Whn8sCCN7ZQMjWZr8X9aXXoYmdklr58nBgTGUwdxBtw/640?wx_fmt=other&from=appmsg "")  
## 功能特性  
- 支持单个URL和批量URL文件输入  
  
- 基于响应  
时间判断是  
否存  
在SQL 注入  
  
- 多线程并发检测，提升扫描效率  
  
- 自动协议补全与端口识别（如http/https）  
  
- 支持保存检测结果  
  
- 支持详细输出模式（verbose）  
  
### 使用示例  

```
检查单个目标
python ecology9_sqli.py.py -t http://example.com
批量检测目标（指定线程10）
python ecology9_sqli.py.py -f targets.txt -T 10
保存结果并显示详细信息并保存结果
python3 ecology9_sqli.py -f targets.txt -o result.txt -v
```

  
****  
****## 四、修复建议  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本**  
**：**  
  
**https://www.weaver.com.cn/cs/securityDownload.asp**  
  
## 三、下载链接  
  
  
后  
台  
回  
复  
“  
**2003”**  
获  
取  
下  
载  
地  
址  
  

#  被动流量漏洞扫描器 - fizz-poc   
 GSDK安全团队   2025-02-25 14:00  
  
01 项目地址  
  
```
https://github.com/fizzgate/fizz-poc
```  
  
  
  
02 项目介绍  
  
项目描述  
  
fizz-poc是一个被动流量漏洞扫描器，支持XRAY(XPOC)的POC文件，能自动识别.pcap文件的流量漏洞，并生成报告。  
  
使用方法  
```
Usage: fizz-poc [-hV] [--https] [--cert=<certFile>] [-d=<pocDir>]
                [--key=<keyFile>] [-o=<reportFile>] -p=<pcapFile>
                [--report-format=<reportFormat>] [--threads=<threads>]
                [--timeout=<timeout>]
POC扫描工具
      --cert=<certFile>     SSL证书文件路径
  -d, --poc-dir=<pocDir>    POC目录路径 (可选，默认使用内置POC)
  -h, --help                Show this help message and exit.
      --https               启用HTTPS解密
      --key=<keyFile>       SSL私钥文件路径
  -o, --output=<reportFile> 报告输出文件路径 (默认: poc_report.json)
  -p, --pcap=<pcapFile>     PCAP文件路径
      --report-format=<reportFormat>
                            报告格式 (json/html) (默认: json)
      --threads=<threads>   线程数 (默认: CPU核心数)
      --timeout=<timeout>   超时时间(分钟) (默认: 60)
  -V, --version             Print version information and exit.
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Xu1xJEZRrFgWiaWicmsNhLTxeSjSvOuP2XIyC7x7TYzh8z8HtQ1pbibeTA98xicb8NeEUY4ibEBgjxNf0x6d8VricBQQ/640?wx_fmt=png&from=appmsg "")  
  
注：  
工具仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布者不承担任何法律及连带责任。信息及工具收集于互联网，真实性及安全性自测！！  
  
  
  
  
  

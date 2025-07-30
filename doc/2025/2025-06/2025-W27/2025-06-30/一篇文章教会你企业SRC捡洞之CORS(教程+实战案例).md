> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMzQyMzUwMg==&mid=2247486716&idx=1&sn=e011383ff4d1af1b836c733b18e15244

#  一篇文章教会你企业SRC捡洞之CORS(教程+实战案例)  
原创 漏洞挖掘  LK安全   2025-06-30 02:15  
  
免责声明  
  
本课程旨在培养具备合法合规网络安全技能的白帽子安全研究人员，专注于网络安全漏洞挖掘与防护技术。任何参与本课程的学员，均需承诺遵守国家法律法规，严格遵守网络安全行业的道德规范。严禁黑灰产及违法行为：本课程严禁任何从事黑灰产、非法入侵、攻击他人系统或从事任何违法行为的人员参与。如果学员在学习过程中有任何违法行为，本课程及相关机构将不承担任何责任。学员行为与本课程无关：课程内容仅供学术研究与技术提升之用，任何学员的行为与本课程无关，学员需对其行为负责，并承诺仅将所学用于合法的网络安全防护和技术研究。参与本课程即表示您已充分理解并同意以上免责声明。如有任何疑问，欢迎与我们联系。  
  
  
0x01 前言  
  
提到CORS这个漏洞，刚开始可谓是让本安服仔恨的牙痒痒，因为笔者还是个脚本小子的时候，用扫描器总是能扫出一堆的CORS，但是因为当时菜的抠脚，只会拿着扫描器 biubiubiu，哪里懂漏洞的深度利用啊，但是随着笔者挖洞技术的深化，并且在后面的实战中多次遇到，发现这玩意在挖洞  
特别是在企业SRC中  
简直是躺着捡钱啊，所以今天写下这篇文章，有错误之处希望大家及时指出，提前谢谢各位🐮子哥  
  
0x02 漏洞介绍  
  
在我看来，学习一个新知识，肯定要先从它的名字看起  
  
CORS，中文名称跨域资源共享  
  
现在问题来了，首先第一个问题，神马是跨域  
  
第二个问题，神马是资源共享  
  
搞清楚这两个问题，我相信这个漏洞也不是啥难事了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR0BMDhEERmM0ibc8iaVEQ1Ur5PzibibIv9W8Y5xllgUjEOGgWs8libk4t4nBQ/640?wx_fmt=png&from=appmsg "")  
  
当然，在正式内容开始之前呢，还是要补充一些基础知识，说到这里我就要吐槽一下，要想挖Web漏洞的一个绝对前提就是，要对Web的基础绝对到位，最近宣传课程加了几位🐮子哥，一问http协议是什么都不清楚，就想着上手挖洞了，这一点很不好嗷  
  
上面提了两个问题，我们首先来看第一个，神马是跨域，当然在跨之前呢，还是先搞清楚什么是域，要不然情况都没搞清楚就想往过跨，容易把🥚扯了。  
  
当然，先问一下伟大的ai  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR0scRCxAIuDk8AGlI3yAQeSX8bo494mZTIdL3iaRTJVoITXw0ibCgWs1XQ/640?wx_fmt=png&from=appmsg "")  
  
哦  
  
原来Origin(域) = 协议 + 域名 + 端口  
  
当然，在这里也引出另外一个基础概念，叫做同源策略  
  
一句话来总结就是在浏览器中，只有当协议、域名、端口相同的情况下，才能读写对方的dom、cookie、session、ajax等操作的权限资源。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR0hrZXuEM6OwCrgwg9Z9aPM6JmVxBx4QpsgvYKzlrYph71N9fJARc4qA/640?wx_fmt=png&from=appmsg "")  
  
原来如此，搞清楚同源策略与域之后，那情况就非常明了了  
  
并且此时呢，第二个问题也解决了，共享的资源文件包括  
对方的dom、cookie、session、ajax请求等等  
  
总结一下，一般情况下，不同源的网页是没办法拥有对方的权限资源的，但是在二般情况下，不同源的网页想拥有对方的权限资源怎么办  
  
伟大的前端提供了两种方式  
  
第一种就是标准的跨域请求机制，也就是我们本文中重点介绍的CORS  
  
第二种是JSONP跨域请求，当然这里也存在漏洞，我们下期展开讲讲  
  
本来呢，前端是好心提供的跨域请求机制，但是为什么会出现漏洞呢，坏就坏在了配置上  
  
浏览器直接发出CORS请求，接下来浏览器会自动在请求的header中加上Origin字段，告诉服务器这个请求来自哪个源。  

```
Origin:
```

  
服务器端收到请求后，会对比这个字段，如果这个源在服务器端的许可范围内，服务器的响应头会加上以下字段  

```
Access-Control-Allow-Origin：(这里的值为Origin的值)
Access-Control-Allow-Credentials:true
```

  
如下图所示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR00GE4ibp3cHG2bc4zbL7sbMcwIXQT9FAKAia879VZRqEYjZCFMwo4KmOg/640?wx_fmt=png&from=appmsg "")  
  
如果说服务端配置了   
Access-Control-Allow-Origin  
 响应头，并且浏览器认可该值，跨域就被允许了，此时漏洞也产生了  
  
讲完了原理，我们再来总结一下  
  
本来呢，CORS是浏览器用来允许前端 JS 向不同域请求资源  
的一个安全机制。默认情况下，浏览器出于同源策略  
的限制，不允许 JavaScript 跨域读取接口数据。但是如果服务端错误地配置了跨域规则，那么就会导致一些很危险的事情产生  
  
0x03 实战案例  
  
好了，啰嗦了半天，直接上某SRC实战案例看一下  
  
该接口是用户登录之后，下载个人信息文件的一个接口，在请求包中发现了Origin字段，通过修改该字段查看服务器回显，发现服务端对   
Origin  
 头没有验证，直接反射原样回显：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR0HUib638lIhts69ich4Wey9BkRHrtwxJXRRGibAxAHc6Et84J5HiaQhy1ug/640?wx_fmt=png&from=appmsg "")  
  
然后构造好攻击的poc  

```
(async () => {
  try {
    const res = await fetch(&#34;http://xxxx/download&#34;, {
      method: &#34;POST&#34;,
      credentials: &#34;include&#34;,
      headers: { &#34;Content-Type&#34;: &#34;application/json&#34; },
      body: &#34;{}&#34;
    });
    if (!res.ok) {
      alert(&#34;请求失败，状态码：&#34;   res.status);
      return;
    }
    const data = await res.json();
    alert(&#34;窃取的数据:\n&#34;   JSON.stringify(data, null, 2));
  } catch (error) {
    alert(&#34;请求异常：&#34;   error.message);
  }
})();
```

  
找到一个外部页面通过 JavaScript 发送如下跨域请求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR00NCoyJJNWEpfyshEvM3TDtmtcXG251GLBtFOkkz2FbSpRfOS3mFOuw/640?wx_fmt=png&from=appmsg "")  
  
最终的攻击效果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR0n0ibZR4yXllaChqX8iaZSZoSic94qoZYyXOpyibMLy9rxtKVwTNhRJH24Q/640?wx_fmt=png&from=appmsg "")  
  
当然，这个案例中还有一些更敏感的接口也可以被攻击，在这里就不一一展示，总之这个洞现在出现的概率也挺大，在一些SRC中一般都是低危甚至中危，还是不错滴  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR0KeShqsI4qjfgufDFiblSbibibHqruLshR0M1fhpnxwthtzdQXagpjfbFg/640?wx_fmt=png&from=appmsg "")  
  
0x04 实战怎么挖  
  
  
接下来就来到最重要的一个环节，实战中怎么挖？  
  
  
其实关于CORS漏洞利用，就注意下面四个点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR0AdoCVetYwkkfMPHkKJHKQXg8Y38GD6T3rTDlqHWvX64fNdricibV5ZxA/640?wx_fmt=png&from=appmsg "")  
  
当然burp中提供的功能，能帮我们去探测  
  
首先，选中Origin方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR0YicRUmuTIWcWgutfEyrLKMCr0LzaUa8RLKqog4W0yNdJBxDxy1T4jyQ/640?wx_fmt=png&from=appmsg "")  
  
  
然后在burp http历史包的选项中  
  
点击筛选器把方法写到红框处，进行筛选Access-Control-Allow-Origin: foo.example.org，剩下的就是可能存在CORS漏洞。发送的origin和返回的origin一样，acao为true，就存在漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7jO6Ng1KzpYt68DMia0rXkR0MjiafdCbGv75rdyibgcM3ECznZqYXc7EiaianNYMPvBsNJYZtSvmHuS4ibg/640?wx_fmt=png&from=appmsg "")  
  
至于定位具体数据包之后，还要看响应中是否携带敏感信息，如果携带的话就可以提交了  
  
你学废了吗  
  
  
LK网安学院-Web漏洞实战挖掘课程第四期开课啦！！  
  
价格1000出头！课程内容覆盖企业赏金SRC、众测赏金、CNVD、Edusrc、网安岗入职技能培训等~~  
  
  
课程大纲  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqsibhpDDUpyqo4b6l9AdcXApCsUkAC0Uokz7h0JbGETicOUatEBtmsQAQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**第四期漏洞挖掘课程**  
  
  
  
      该课程集合了讲师多年的漏洞挖掘/渗透测试/工作经验，  
旨在让各位同学用最短的时间，最快的速度挖到人生第一洞；  
让只会打靶场，挖不到漏洞或者在实战中没有挖洞思路的同学挖到人生第一洞；  
让只会挖公益漏洞挖不到赏金漏洞的同学挖到人生第一桶金；  
让认真付出愿意报名的学员真正的学会技术；  
一次报名即可永久学习，并且赠送永久纷传圈子  
  
  
  
**往期学员成果汇报**  
  
  
  
        
众多学员入职  
小米/长t/安h/奇安x/绿m  
等互联网或网安大厂；众多学员成功挖到人生第一桶金/人生第一洞  
  
  
学员挖洞战绩  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrq24tqtyCcPVAH5ymOYmgfSphfBUd2vEicyrSNgAO4ZnFddbicEjYvQXkw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
五个sql注入 恐怖如斯  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqfiafQUkGRr6HI4jpZMajiav2G3ob9jlFI5LrS9eQOyLGzQTFHaia7bEDA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
某平台私密项目   
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqibXRlBudJwjZyhpGeYyyxek6C2Zniabm5PvA6vgOoWaSNZBmCIL9GKdw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
重复漏洞也有钱拿  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqWiae2QRKibNtQibqOyIqj3Np06mtv7rO9vjSh916ToHicc7hiaibRurgib7uw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
人生第一洞  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqQaa5icKicPkzKbJW3JxKo2ib5bl00QyTFJCa9s690Xpn5Iqv8G4NVPoibw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
内部项目 带各位师傅一起赚钱  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqbcCqND4tkzfuZqk8FE9aOicibibu0SCES0RSCHUibSNFJPQ5EIwP1dOu8w/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrq5J6EcvpvmY8BPTT9DPhqFqeLwRyvcqOaTI4db0dAKWfUcmpe86BYGA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrq547OicrmwrMLhyjcevH3dpCYzzQsyCnuaRefTiaicOiaMP3L7OfOmfuXfQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
学员反馈  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqqnG0CQaVlxbibEzRqETGeM0rxbkW0eicAicezsKWicrCJic0iaSaItGoy5vg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
出货的快乐  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqHaFBJN4t4D0y9VhVqjdOZTcvJ8NzXN8fFCXgO3OL0HzCrkL7K3uvWQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
学员反馈  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqRF9XccA4f7oDMzaAWybzo3dpda1Sj62Zo5mj36FFySN4WMXC9bmcMg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
学员战绩  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqzZEcDhZxiaw9wc1gehrgWtv05ysCakYUC0hpiadQZiaVENVmic9OB15jPQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
斩获edu证书  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrq2jPWNhF6gubNd5IfAxhFP6MfO6mk5l3RIp38byeL9nz704yx1mpjNw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
跟着我学了三个月 干到edu正式白帽子  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqxCNPf6xDBHScRn4nGnUIVMfeRFjmm3AT7Sg1h3zJD9UP6YIuvgDjsA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
学员就业案例  
  
某学员斩获3个offer 手握ct/360/安h实习offer  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqXTwCIic0UsEZbwq1XLyyCVXyy6HMK1yTRlhxuor3VzL0eYiaUU0eINSg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
大弟子 手把手带 从只能挖点垃圾洞的网安小白到单洞2k，在上海找到10k+工资的正式网安人员  
  
刚认识的时候，很菜  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrq7ZY8L4g4xGYseBiaUo3dEl59SzmJZWc7tA0t8GrXtXnAAYv3yq0pMvQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
经过一段时间的学习，已经可以单洞2k  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqpiaCYNEyljyiaZ5bbGiafHibAvdQOcJrQnsnHgasn87LolUXwkVCH9HJrA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
也拿了不错的offer，恭喜上岸  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqf408dicTmibFnRLUBHGornxI1Eb2Piaiced4510swMWAkm9arqADextbhg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
另外一个大学生，刚认识的时候也是什么都不会，经过学习拿下小米offer  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqEwrTYCEacddL6omz9OdZzAmVh0B4SGHKtdW0SWVfDKJ4sH6uVAsBYg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
学员就业案例 太多了 就不一一展示了  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqJbdriadnUHtPCX4uIHYkdXVQibN2eFpPB9NCmckyxH2kyAKAMYUQl85Q/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
手把手带着学员们做项目  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrq9icNvRDTibtnPeh5hsMHLyeOEiadI5gBHb6mSTzzYXF1oyh58X2vG9FmA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqvhibghDpypRuJUaLYwAQlrVpa5K7icVeNc6Dh5ybibZttCB2M5RrVCgsQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
各种短期项目   
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqTI2zNhzrro4qsrreRqibWJHqZlia7Zhiah78BllUZw30BECFMXhrlxKrg/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
带学员做各种项目  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7hrcFmzKW9GLfqmcDMnydrqPlibdOMriaRed6gJPXBU64505sFjt9vvSzPtoepOmZWmuPrLLdFLbc3g/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
太多了 好多我也没整理  
  
课程加量不加价、上述课表中的内容，不代表第四期的全部内容，实际上课会比课表多更多。  
  
  
  
  
技术交流/加群聊/课程咨询  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7j4Fwia89786A7ho8vsJLciaBKa1fSdJD1tdLxu6A1juOZgbaQicoBHODKPiaJdtCEaZTxubeWR6pkicqw/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
技术群聊已满200人 群内各种福利 欢迎各位师傅进群交流  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aibjdZFMRy7j4Fwia89786A7ho8vsJLciaByL5K3CpyGYw7Knuic1ryaWRX5Tiaf4cjonWxjGibbBuaZpyU5NPmetcJA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  

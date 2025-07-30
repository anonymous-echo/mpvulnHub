> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyMDUzMzY1MA==&mid=2247500131&idx=1&sn=f1e9778b2f244ff660cb9f1384059a92

#  微信也有xss了吗？  
原创 零漏安全  零漏安全   2025-07-13 04:19  
  
今天本来也是无所事事的一天，突然老大跟博主说发现了一个好玩的，微信居然可以xss弹东西，吗喽马上上线尝试一下，具体效果如图所示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9GGhFCliayOQZGdzUfotGPeZOFLcjribWibINz0fCUCXIibLdnLkcuGPAUlmkXd28VibfuzKzlID5zSDOXlzGAuDQRg/640?wx_fmt=jpeg&from=appmsg "")  
  
你只要点击这个文字就会弹我喜欢你，但是经过测试发现，好像只能自己手机上触发，别的手机是能看到原文的，也就是这个  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/9GGhFCliayOQZGdzUfotGPeZOFLcjribWib2jB4NKH3ADhyK8ic8rD08mqAtJm2RUYMslgncEFVjeNcoicciabD08qvw/640?wx_fmt=jpeg&from=appmsg "")  
  
最后吗喽说这个东西只能说聊胜于无，下面我也是直接贴出原文，大家可以看看有啥更多的利用  

```
<a
href=&#34;weixin://bizmsgmenu
?msgmenucontent=我喜欢你
&msgmenuid=960&#34;>起拍0🕠‧石狮.pt 树身H烛光闪烁耀人目，喜上眉梢迎佳节。平安之夜多快乐，家人团聚举杯贺。准备礼物亲人送，情深意重祝福绵。祝你身体健康，万事如意</ a>
```

  
  

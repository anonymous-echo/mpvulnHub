#  爆出 CSS 注入漏洞之后，GitHub 被玩成 QQ 空间了   
营销号  非尝咸鱼贩   2024-06-08 23:48  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6N4b2yN3FOKrbGVLTaM8Uw2oCZLUpdscpXJ8kRk6MsfcthxaGb1HEibTyIH9mFxLbmC19Jou4dW1qDRA4LHichFg/640?wx_fmt=png&from=appmsg "")  
  
周五晚 @cloud11665 发现 GitHub 渲染   
MathJax 时可以插入自定义的 CSS 样式。虽然 GitHub README 也偶有 XSS 的报告，但由于 CSP，比较难利用。  
  
接着网友开始疯狂整活装扮 GitHub 首页，各种酷炫的动态背景，仿佛变成 QQ 空间。  
  
这个问题去年 11 月就有人报告给 MathJax，只是没搞出这么大动静。POC 如下  
```
\unicode[some-font; color:red; height: 100000px;]{x1234}
```  
  
  
https://github.com/mathjax/MathJax/issues/3129  
  
大概是自定义样式有钓鱼的风险，  
GitHub   
周五连夜加班修复了几个变体。  
  
然而 \unicode 并不是唯一一个可以注入 css 的向量。  
截止目前，  
网上还有一个野生的绕过：  
  
> new Date()  
  
2024-06-08T15:29:44.844Z  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6N4b2yN3FOKrbGVLTaM8Uw2oCZLUpdscXP5TuNlMccOTn7oey1XvzYBKRX6E2jMxG40bLe5dDAKsM9TB3vicNBQ/640?wx_fmt=png&from=appmsg "")  
  
https://github.com/PewsBurner/  
  

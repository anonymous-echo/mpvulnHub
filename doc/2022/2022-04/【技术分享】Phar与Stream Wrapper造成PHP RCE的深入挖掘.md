#  【技术分享】Phar与Stream Wrapper造成PHP RCE的深入挖掘   
原创 zsx  安全客   2022-04-20 10:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb7DhmUoMkZyHeLxIj7KDMSZFd0jjYm7AhvsDhRx1ibUJcmNKKJTenzIG87bBOcDyqq8tT65xythicdA/640?wx_fmt=png "")  
> 今年的HITCON打完了，沉迷写前端搞Nextjs骚操作的我成功爆0（雾），不想写前端了.jpg。  
> 先跑个题。  
> HITCON 2016上，orange 出了一道PHP反序列化。  
> HITCON 2017上，orange 出了一道Phar + PHP反序列化。  
> HITCON 2018上，orange 出了一道file_get_contents + Phar + PHP反序列化。  
> 让我们期待HITCON 2019的操作（雾。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb7DhmUoMkZyHeLxIj7KDMSZibTSatKKAoiaibF28ISicDBZULUVZsrwJovDKeAD6TMafia3ibPouNoTno5Q/640?wx_fmt=png "")  
  
**Phar RCE**  
  
今年HITCON上，baby cake这一题，涉及到了今年BlackHat大会上的Sam Thomas分享的File Operation Induced Unserialization via the “phar://” Stream Wrapper这个议题，见：  
https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf  
 。它的主要内容是，通过phar://协议对一个phar文件进行文件操作，如file_get_contents，就可以触发反序列化，从而达成RCE的效果。  
  
在文章开头部分，让我先对phar反序列化做一些小小的分析。我们直接阅读PHP源码。在   
phar.c#L618  
 处，其调用了php_var_unserialize。  
```
```  
  
因此可以构造一个特殊的phar包，使得攻击代码能够被反序列化，从而构造一个POP链。这一部分已经太常见了，CTF比赛中都出烂了，没什么值得继续讨论的。值得关注的是到底为什么file_get_contents能够实现RCE。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb7DhmUoMkZyHeLxIj7KDMSZibTSatKKAoiaibF28ISicDBZULUVZsrwJovDKeAD6TMafia3ibPouNoTno5Q/640?wx_fmt=png "")  
  
**Steam AP|**  
  
因此，为解决这个问题，我们需要首先阅读此函数的源码。大概在此处：  
https://github.com/php/php-src/blob/PHP-  
7.2.11/ext/standard/file.c#L548  
 ，重点关注此行：  
```
```  
  
可以注意，其使用的是php_stream系列API来打开一个文件。阅读PHP的这篇文档：  
Streams API for PHP Extension Authors  
，可知，Stream API是PHP中一种统一的处理文件的方法，并且其被设计为可扩展的，允许任意扩展作者使用。而本次事件的主角，也就是phar这个扩展，其就注册了phar://这个stream wrapper。可以使用stream_get_wrapper看到系统内注册了哪一些wrapper，但其余的没什么值得关注的。  
```
php > var_dump(stream_get_wrappers());
array(12) {
  [0]=>
  string(5) "https"
  [1]=>
  string(4) "ftps"
  [2]=>
  string(13) "compress.zlib"
  [3]=>
  string(14) "compress.bzip2"
  [4]=>
  string(3) "php"
  [5]=>
  string(4) "file"
  [6]=>
  string(4) "glob"
  [7]=>
  string(4) "data"
  [8]=>
  string(4) "http"
  [9]=>
  string(3) "ftp"
  [10]=>
  string(4) "phar"
  [11]=>
  string(3) "zip"
}
```  
  
那么，注册一个 stream wrapper，能实现什么功能呢？很容易就能找到其定义：  
https://github.com/php/php-src/blob/8d3f8ca12a0b00f2a74a27424790222536235502/main/php_streams.h#L132  
```
```  
  
因此，我们发现，一个 stream wrapper，它支持以下功能：打开文件（夹）、删除文件（夹）、重命名文件（夹），以及获取文件的meta。我们很容易就能断定，类似unlink等函数也是同样通过这个 streams api 进行操作。  
  
Sam Thomas 的 pdf 指出  
> This is true for both direct file operations (such as“file_exists”) and indirect operations such as those that occur during external entity processingwithin XML (i.e. when an XXE vulnerability is being exploited).  
  
  
我们通过试验也很容易发现，类似unlink等函数也均是可以使用的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb7DhmUoMkZyHeLxIj7KDMSZ93yAsujUgRleRDqFyF26y5sp3oYrLJ4197jiaKW8eBPNNGC0ibOztR9g/640?wx_fmt=png "")  
  
知道创宇404实验室的研究员 seaii 更为我们指出了所有文件函数均可使用（  
https://paper.seebug.org/680/  
）：  
- fileatime / filectime / filemtime  
  
- stat / fileinode / fileowner / filegroup / fileperms  
  
- file / file_get_contents / readfile / `fopen“  
  
- file_exists / is_dir / is_executable / is_file / is_link / is_readable / is_writeable / is_writable  
  
- parse_ini_file  
  
- unlink  
  
- copy  
  
- ![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb7DhmUoMkZyHeLxIj7KDMSZicUeXkKY8LI6iaQT7U6maUyqpWO5ogtu82lF6yv51THWjwibZ4F9Pplrg/640?wx_fmt=png "")  
  
仅仅是知道一些受影响的函数，就够了吗？为什么就可以使用了呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ok4fxxCpBb7DhmUoMkZyHeLxIj7KDMSZ5J5BnPKwsvzNjyBMaUug3mcNQicHUcVNnHQqrFabnoZXztTMz4xWhHg/640?wx_fmt=gif "")  
  
**寻找受害者**  
  
当然不够。我们需要先找到其原理，然后往下深入挖掘。先看file_get_contents的代码。其调用了  
```
```  
  
这么个函数。  
  
再看unlink的代码，其调用了  
```
```  
  
这么个函数。  
  
从php_stream_open_wrapper_ex的  
实现  
，可以看到，其也调用了php_stream_locate_url_wrapper 。这个函数的作用是通过url来找到对应的wrapper。我们可以看到，phar组件注册了phar://这个wrapper，   
https://github.com/php/php-src/blob/67b4c3379a1c7f8a34522972c9cb3adf3776bc4a/ext/phar/stream.c  
**其定义如下：**  
```
```  
  
接着，让我们翻这几个函数的实现，会发现它们都调用了phar_parse_url，这个函数再调用phar_open_or_create_filename -> phar_create_or_parse_filename -> phar_open_from_fp ->phar_parse_pharfile -> phar_parse_metadata -> phar_var_unserialize。因此，明面上来看，所有文件函数，均可以触发此phar漏洞，因为它们都直接或间接地调用了这个wrapper。  
  
只是这些文件函数，就够了吗？当然不够。这是一个所有的和IO有关的函数，都可能触发的问题。  
  
前面我已经指出，它们都有一个共同特征，就是调用了php_stream_locate_url_wrapper。但是这个不那么好用，换php_stream_open_wrapper更合适点。让我们搜索一下PHP源代码吧，  
  
我们很快就能发现，操作文件的touch，也是能触发它的。不看文件了，我们假设文件全部都能用。  
  
我们会惊讶（一点都不）地发现：  
### exif  
- exif_thumbnail  
  
- exif_imagetype  
  
### gd  
- imageloadfont  
  
- imagecreatefrom***  
  
### hash  
- hash_hmac_file  
  
- hash_file  
  
- hash_update_file  
  
- md5_file  
  
- sha1_file  
  
### file / url  
- get_meta_tags  
  
- get_headers  
  
### standard  
- getimagesize  
  
- getimagesizefromstring  
  
## zip  
```
```  
### Bzip / Gzip  
  
这，够了吗？non non哒哟！  
  
如果题目限制了，phar://不能出现在头几个字符怎么办？请欣赏你船未见过的船新操作。  
  
$z = 'compress.bzip2://phar:///home/sx/test.phar/test.txt';  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb7DhmUoMkZyHeLxIj7KDMSZ55rWePnBWMW9RumeP61GEw8Z4b1qsMauONgomfj8OCE6tOk0nic49wA/640?wx_fmt=png "")  
  
当然，它同样适用于compress.zlib://。  
### Postgres  
  
再来个数据库吧！  
```
```  
  
当然，pgsqlCopyToFile和pg_trace同样也是能使用的，只是它们需要开启phar的写功能。  
### MySQL  
  
还有什么骚操作呢？……MySQL？走你！  
  
我们注意到，LOAD DATA LOCAL INFILE也会触发这个php_stream_open_wrapper. 让我们测试一下。  
```
```  
  
再配置一下mysqld。  
```
```  
  
……然后，走你！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb7DhmUoMkZyHeLxIj7KDMSZJh7HFw5szYwUCFyrEUpTa6F8134F0CpsupWTduIRDVc7oib7Kib08jOg/640?wx_fmt=png "")  
  
这就是我想要看到的舞台！——长颈鹿很可惜，这不是默认配置；但是，嗯，很有意思。  
  
我相信，PHP代码内部还有相当多的php_stream_open_wrapper等待挖掘，这只是关于stream wrapper利用的一小步。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6OLwHohYU7UjX5anusw3ZzxxUKM0Ert9iaakSvib40glppuwsWytjDfiaFx1T25gsIWL5c8c7kicamxw/640?wx_fmt=png "虚线阴影分割线")  
```
```  

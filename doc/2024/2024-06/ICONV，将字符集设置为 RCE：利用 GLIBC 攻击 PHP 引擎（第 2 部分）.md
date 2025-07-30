#  ICONV，将字符集设置为 RCE：利用 GLIBC 攻击 PHP 引擎（第 2 部分）   
 Ots安全   2024-06-17 20:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiaicW6QDllG92WIVCBl2lGozPbSicuZ6Fyt2gevPsCnNcZic3ACQcf3fV0A/640?wx_fmt=png&from=appmsg "")  
  
介绍  
  
几个月前，我偶然发现了 glibc（Linux 程序的基础库）中存在一个已有 24 年历史的缓冲区溢出漏洞。尽管在多个知名库或可执行文件中都可以找到该漏洞，但事实证明它很少被利用 — 虽然它没有提供太多的回旋余地，但它需要难以实现的先决条件。寻找目标主要导致失望。然而，在 PHP 上，这个漏洞却大放异彩，并被证明可以通过两种不同的方式利用其引擎。  
  
在第一部分中，我介绍了该漏洞，讲述了它的发现过程及其局限性，并通过将文件读取漏洞转换为 RCE 演示了它在 PHP 上的使用。在这篇博文中，我将探索一种利用 PHP 漏洞的新方法，即直接调用，并通过针对流行的 PHP 网络邮件 Roundcube 来说明该漏洞。同样，我将通过揭示使用mbstring时iconv()意想不到的到达方式来展示对生态系统的影响。iconv()  
  
另一个触发器  
  
虽然使用这个漏洞触发方式  
php://filter很方便，但最明显的方法是使用同名的 API 来调用  
iconv()它。在 PHP 中，它具有以下原型：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJia4BewicY7iaoiahuySd3azLTlpe8R5yCGwSwEkt6k00ibhbbo4YoLSha7aA/640?wx_fmt=png&from=appmsg "")  
  
此函数与其 C 等效函数之间的区别在于，缓冲区管理（在 C 中必须由调用者完成）现在不可见，因为它由 PHP 在后台处理。在第 1 部分中，我们了解到我们非常依赖输出缓冲区的外观：在许多情况下，该错误很可能无法利用。  
  
那么，PHP 的实现是否存在漏洞？当我们使用 将大小为N  
iconv()的字符串转换为另一个字符集时，PHP 会分配一个大小为N+32的输出缓冲区，以期“在大多数情况下避免 realloc()” [1]。如果缓冲区不够大[2]，则会将其变大[3]。  
iconv()  
```
// ext/iconv/iconv.c

PHP_ICONV_API php_iconv_err_t php_iconv_string(const char *in_p, size_t in_len, zend_string **out, const char *out_charset, const char *in_charset)
{
    ...

    in_left= in_len;
    out_left = in_len + 32; /* Avoid realloc() most cases */ // [1]
    out_size = 0;
    bsz = out_left;
    out_buf = zend_string_alloc(bsz, 0);
    out_p = ZSTR_VAL(out_buf);

    while (in_left > 0) {
        result = iconv(cd, (ICONV_CONST char **) &in_p, &in_left, (char **) &out_p, &out_left);
        out_size = bsz - out_left;
        if (result == (size_t)(-1)) {
            if (ignore_ilseq && errno == EILSEQ) {
                if (in_left <= 1) {
                    result = 0;
                } else {
                    errno = 0;
                    in_p++;
                    in_left--;
                    continue;
                }
            }

            if (errno == E2BIG && in_left > 0) { // [2]
                /* converted string is longer than out buffer */
                bsz += in_len;

                out_buf = zend_string_extend(out_buf, bsz, 0); // [3]
                out_p = ZSTR_VAL(out_buf);
                out_p += out_size;
                out_left = bsz - out_size;
                continue;
            }
        }
        break;
    }

    ...
}
```  
  
因此，输出缓冲区比输入缓冲区大 32 个字节，因此很容易触发溢出。poc 可在此处找到。它归结为：  
```
$input = 
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .
    "AAA劄劄\n劄劄\n劄劄\n劄\n劄\n劄\n劄";
$output = iconv("UTF-8", "ISO-2022-CN-EXT", $input);
```  
  
现在我们知道可以使用 触发该漏洞  
iconv()，我们可以寻找目标。同样，先决条件如下：我们需要控制输出字符集，以及至少部分输入缓冲区。现在，什么类型的软件可以满足这些条件？我最初的想法是查看电子邮件客户端，因为电子邮件意味着编码。但在我们深入了解攻击细节之前，让我们先了解一些理论。  
  
PHP 远程二进制漏洞利用：理论  
  
虽然许多人认为 PHP 不安全，但针对 PHP 的远程二进制攻击至少没有得到充分记录。攻击者如何利用我们遇到的缓冲区溢出漏洞来破坏 PHP 引擎并执行远程代码？在我们动手之前，我将向您展示为什么这并不像看起来那么容易。  
  
从第 1 部分开始，您应该对 PHP 堆的工作原理有了大致的了解。它的设计很简单，而且没有受到任何保护（目前还没有？）。然而，对我来说，它的主要攻击缓解来自一个简单的（可能与安全无关的）设计选择：**一个堆只处理一个请求**。当您向 PHP 发送 HTTP 请求时，它将创建一个新的堆，解析和分配您的参数（GET、POST等），编译并运行请求的脚本，返回 HTTP 响应，然后，当一切都完成后，删除堆。  
  
想想你的标准远程利用。我们可以粗略地将其分为三个步骤：设置，触发和使用。以释放后使用为例：首先，你可能与服务器交互以塑造目标的堆，可能喷射一些结构，或安排一些空闲列表。这是设置。然后，你将发送第二个请求，触发错误，并让应用程序释放一些块，同时留下一个悬空的指针。紧接着，你会发出额外的稻草，用你更喜欢的东西替换丢失的块。第四个请求将是棺材上的钉子：利用你的类型混淆结构来发挥你的优势，并启动一些 ROP 链，从而使用你的错误。  
  
使用 PHP，我们需要在**一次请求-响应交换**过程中完成**所有这些步骤**。发送 HTTP 参数后，我们就束手无策了：没有其他方法可以与引擎交互，我们期望在获得 HTTP 响应之前，设置、触发和使用能够自行发生，然后堆才会被销毁。  
  
为了规避这个问题，人们经常针对那些让你在请求运行时与 PHP 交互的函数。这就是为什么几年前我针对 PHP 中与数据库相关的代码：当 PHP 发送 SQL 查询并接收结果时，它为我们提供了一种交换数据的方法，迫使 PHP 进行分配、释放等。更一般地说，诸如此类函数中的漏洞  
unserialize()构成了一个理想的目标，因为它可以让你触发错误，然后创建任意对象、字符串、数组……  
  
在第 1 部分中，当攻击 时  
php://filter，我们遇到了类似的情况，我们可以使用精心挑选的过滤器和存储桶在堆上执行操作，并通过转换为ISO-2022-CN-EXT在任意时刻引发内存损坏。但在这个新案例中，直接调用  
iconv()，我们处于一个非常令人不安的境地：该函数只会让我们触发错误。要执行设置，然后使用它，我们需要另一种方法。  
  
鼓励建筑  
  
然而，我们已做好了准备。环境易于攻击：为了处理 HTTP 请求，PHP-FPM 和 mod PHP 具有主/工作器架构，其中根进程控制一些权限较低的工作器。每当工作器死亡时，主进程都会通过分叉重新启动它。这有双重优势。首先，如果我们以某种方式使工作器崩溃，它会被重新生成。不存在对服务器进行 DOS 攻击的风险。其次，内存布局（ASLR、PIE）在各个工作器上是相同的：如果我们泄露其中一个工作器的地址，我们可以保证它们的 MSB 与其他工作器的地址相同。  
  
理论开发目标  
  
因此，进行远程 PHP 攻击的标准方法是两次利用该漏洞：一次获取泄漏，然后执行代码。为了实现这一点，我们可以依次破坏两个结构：  
zend_string s和  
zend_array s。  
  
该  
zend_string结构表示一个 PHP 字符串。它由几个字段和一个缓冲区组成。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiaHnQ2oz1yU3MwmiaFEyia5kSLxA6NxFJNE97nW5N4SJ9xHBh366toHIfQ/640?wx_fmt=png&from=appmsg "")  
  
结构zend_string  
  
在 PHP 中，字符串不是以 NULL 结尾的字节集合；它们的  
len字段定义其大小。因此，为了显示字符串  
s，PHP 会显示  
len从 开始的字节  
s+18h。如果我们设法人为地增加此字段的值，则可能会泄漏内存。  
  
有了泄漏的内存，事情就变得简单了。我们可以轻松地在堆中找到自己，并获取指向主二进制文件的指针。下一步，执行代码，可以通过覆盖结构的最后一个字段来完成  
zend_array，该字段代表一个 PHP 数组：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiau7td0fxjmYwSLc91gXib9Wf2f3Hvnic0wCibocgtNpRy73UiaXZuzq28fg/640?wx_fmt=png&from=appmsg "")  
  
结构zend_array  
  
pDestructor是指向负责从数组中删除元素的函数的指针。它通常指向zval_ptr_dtor PHP的变量销毁函数。更改其值允许我们获得 RIP：当数组被删除时，其元素也会被删除，因此  
pDestructor会被调用。  
  
但现在理论已经足够了。  
  
攻击 Roundcube  
  
Roundcube可能是最流行的 PHP 网络邮件。它经常被邮件提供商、网络托管商或私人公司用作一种无需桌面客户端即可快速轻松地访问邮件的方式。您可能已经在网上见过一个：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiaHqdZZQe19zOqvVYpicLK0yute7icibMHGqdZS3OrYsXGtpNpXXVNicNDvg/640?wx_fmt=png&from=appmsg "")  
  
Roundcube 接口  
  
遗憾的是，它符合我们的每一个先决条件，并让我们以标准用户的身份实现**远程代码执行**。  
  
找到漏洞  
  
_to使用 Roundcube 发送电子邮件时，可以使用、  
_cc和字段指定收件人、抄送人和密件抄送人  
_bcc。由于你们可能都已经发送过电子邮件，所以我就不描述它们是什么了；你们知道它们代表一组电子邮件地址。  
  
现在，除了这些字段之外，用户还可以发送  
_charset HTTP 参数[1]。在这种情况下，Roundcube 将  
iconv()在处理之前将上述参数转换为字符集。代码如下所示（大大简化）：  
```
# /program/include/rcmail_sendmail.php
class rcmail_sendmail
{
    public function headers_input()
{
        ...

        // set default charset
        if (empty($this->options['charset'])) { // [1]
            $charset = rcube_utils::get_input_string('_charset', rcube_utils::INPUT_POST) ?: $this->rcmail->output->get_charset();
            $this->options['charset'] = $charset;
        }

        $charset = $this->options['charset'];

        ...

        $mailto  = $this->email_input_format(rcube_utils::get_input_string('_to', rcube_utils::INPUT_POST, true, $charset), true);
        $mailcc  = $this->email_input_format(rcube_utils::get_input_string('_cc', rcube_utils::INPUT_POST, true, $charset), true);
        $mailbcc = $this->email_input_format(rcube_utils::get_input_string('_bcc', rcube_utils::INPUT_POST, true, $charset), true);

        ...

        if (!empty($this->invalid_email)) { // [2]
            return display_error('emailformaterror', 'error', ['email' => $this->invalid_email]);
        }
    }
}
```  
  
虽然  
rcube_utils::get_input_string()是获取 HTTP 参数并将其转换为 的简单包装器，但  
$charset它  
email_input_format()是一个复杂的函数，用于验证电子邮件列表是否有效。实际上，如果提供的电子邮件之一无效，它将被复制到 中  
$this->invalid_email，并显示在错误消息中，例如：  
Invalid email address: <email>。  
  
_to我们可以使用、  
_cc或 来触发漏洞  
_bcc。  
  
**出现泄漏**  
  
为了获取泄漏，我们需要在显示之前覆盖  
len的字段。我们将此字符串称为目标字符串。在我们的例子中，我们有一个非常简单的候选：如果我们发送的一封电子邮件无效，Roundcube 将显示包含该电子邮件的错误消息。我们可以在 中发送这样的电子邮件，并将其用作目标字符串！zend_string_to  
  
现在，我们的原语远非“写入任意位置”或任意溢出。它最多写入 3 个越界字节。如果我们直接溢出到  
zend_string，我们唯一可以覆盖的就是它的  
refcount。显然，我们不能直接利用这个漏洞来做我们想做的事情。相反，我们可以利用 1 字节溢出到一个空闲的块指针，类似于第 1 部分中使用的技术，以便将其替换，并使一个块与目标字符串 重叠，从而允许我们覆盖其标头。  
  
虽然从理论上讲，这一切都是可行的，但我们面临的是每个请求只处理一个堆的缓解措施。我们如何在错误触发之前调整堆？一旦我们改变了空闲列表指针的 LSB，我们如何让 PHP 分配更多块，以覆盖目标字符串的标头？  
  
**堆整形 101**  
  
使用 GET、POST 和 cookies，可以强制 PHP 分配任意长度的字符串。每次发送一个键值对（例如）时  
key=value，PHP 都会分配一个  
zend_string来存储键，分配两个来存储值。此外，您可以通过发送键的新值来让 PHP 释放块：这  
key=value&key=other-value会导致 PHP 分配key，然后value分配两次，然后other-value分配两次，最后释放这两个字符串。例如，要用大小为0x400   
value的块填充页面，并释放第三个，您可以使用以下组合（大小为N 的a存储在N+0x19字节上）：  
zend_string  
```
# Imagining that we have a page of four unallocated 0x400 chunks: C1 C2 C3 C4
# With a "standard" free list of C1→C2→C3→C4
 a=AA...AAAAA (0x3e7 times)  # Allocates two 0x400 chunks in C1 and C2
&b=BB...BBBBB (0x3e7 times)  # Allocates two more in C3 and C4
&b=                          # Frees C3, then C4
&CC...CCCCC (0x3e7 times)=   # Allocates C4
```  
  
因此，使用 HTTP 参数，我们可以在创建堆后立即将其调整为我们所喜欢的形状。虽然这很好，但并不完美：现代 PHP 应用程序在编译和运行时将执行数千个堆操作，从而完全扰乱我们的工作。想象一下整个过程：解析代码、注释、字符串、对象、将代码编译为 PHP VM 指令，然后运行它们、操作数据、进入和退出函数等。最好的计划（如果可以的话）是尝试攻击应用程序较少使用的块大小，以便程序不会过多地弄乱您的设置。  
  
代码小工具  
  
现在我们可以影响堆的外观，我们可以构建一个五步流程来获取泄漏：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiaFYRJibibn55sgF2pyHhicMMKeq0sdAeew0ibFGEVcZ4AgYX8Yxmdj92mag/640?wx_fmt=png&from=appmsg "")  
  
针对大小为 0x100 的块进行利用  
  
我们首先对堆进行整形，使得 4 个0x100块  
A、  
B、  
C、  
D连续且空闲，空闲列表为：  
D→   
A→   
B→   
C（图 1）。  
  
在让 PHP 写入  
zend_string将无效电子邮件地址存储在（虚构）地址  
0x7fff11a33300(   
D) 处的块（图 2）后，我们从地址  
0x7fff11a33000(   
A) 处的块溢出，覆盖指向  
0x7fff11a33200(   
C) 的指针的 LSB，变为  
0x7fff11a33248(图 3)。触发错误后，我们得到  
A→   
B→ (图 4)。然后，通过另外 3 次分配，我们分配一个与目标字符串  
C+48h重叠的块（图 5），使我们能够覆盖其标题，更准确地说，覆盖其字段。zend_string  
len  
  
我们知道如何执行设置（步骤 1、2）并触发错误（步骤 3、4）。但是缺少一个步骤：破坏空闲列表后，我们如何分配块？在执行的这个阶段，脚本是独立的。唯一能让 PHP 分配任何东西的就是脚本本身。因此，要执行我们所需的分配，我们需要研究让 PHP 应用程序为我们执行此操作的方法。  
  
我们再来检查一下目标函数：  
```
# /program/include/rcmail_sendmail.php
class rcmail_sendmail
{
    public function headers_input()
{
        ...

        $mailto  = $this->email_input_format(rcube_utils::get_input_string('_to', rcube_utils::INPUT_POST, true, $charset), true);
        $mailcc  = $this->email_input_format(rcube_utils::get_input_string('_cc', rcube_utils::INPUT_POST, true, $charset), true); // [1]
        $mailbcc = $this->email_input_format(rcube_utils::get_input_string('_bcc', rcube_utils::INPUT_POST, true, $charset), true);

        ...

        if (!empty($this->invalid_email)) {
            return display_error('emailformaterror', 'error', ['email' => $this->invalid_email]); // [2]
        }
    }
}
```  
  
假设我们  
_to设置了一个无效的电子邮件，然后  
_cc触发了错误，我们可以使用 [1] 和 [2] 之间发生的任何事情来分配我们的块。  
让我们看一下  
email_input_format()（再次大大简化）：  
```
# /program/include/rcmail_sendmail.php
class rcmail_sendmail
{
    /**
     * Parse and cleanup email address input (and count addresses)
     *
     * @param string $mailto Address input
     * @param bool   $count  Do count recipients (count saved in $this->parse_data['RECIPIENT_COUNT'])
     * @param bool   $check  Validate addresses (errors saved in $this->parse_data['INVALID_EMAIL'])
     *
     * @return string Canonical recipients string (comma separated)
     */
    public function email_input_format($mailto, $count = false, $check = true)
{
        ...

        $emails  = rcube_utils::explode_quoted_string("[,;]", $mailto); // [1]

        foreach($emails as $email) {
            if(!is_valid_email($email)) {
                $this->invalid_email = $email;
                return "";
            }
        }

        return implode(", ", $emails);
    }
```  
  
该方法将  
$mailto电子邮件列表拆分为数组[1]。这是强制 PHP 分配块的完美方法！  
  
我们现在有一个完整的策略：  
- 使用 HTTP 参数塑造堆（步骤 1）  
  
- 用于  
_to发送无效的电子邮件，设置  
$this->invalid_email（步骤2）  
  
- 用于  
_cc触发漏洞，修改空闲列表（步骤3、4）  
  
- 用于  
_bcc强制 PHP 分配字符串，覆盖长度  
invalid_email（步骤 5）  
  
当显示错误消息时，内存就会泄漏。  
  
构建漏洞之后，我设法让 Roundcube 使用我修改后的电子邮件（  
Adresse courriel invalide法语为  
Invalid email address）显示错误，但是它……毫无亮点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiagPRicG7T5fVK7NiaG8MayWo8VGPsP2gN0MYVsCY8B7yPVWHnSu12VQOg/640?wx_fmt=png&from=appmsg "")  
  
JSON 编码的错误消息  
  
错误消息仅包含空格、unicode 转义的空字节和 ASCII 字符。发生了什么？实际上，Roundcube 将错误消息显示为 JSON。为了对它们进行编码，它使用  
json_encode()带有标志的 API 。JSON_INVALID_UTF8_IGNORE因此，无效 UTF-8 的字符会被丢弃。由于内存中的大多数数据都不是有效的，因此我们的泄漏不包含任何有趣的内容。  
  
**修订泄漏策略**  
  
我们的目标字符串不是最有成效的，但这个想法仍然是正确的。相反，我们需要找到一个“按原样”显示的变量（或者，修改较少）。  
  
与大多数 Web 应用程序一样，Roundcube 在执行的最后阶段（**在我们触发漏洞之后**）才格式化其输出。显然，这是大多数候选目标字符串分配的位置。因此，我们需要更改我们的漏洞利用算法。我们仍将使用 4 个块，并且仍将置换C以使其与 重叠D，这将包含目标字符串。但这次，我们在目标字符串分配**之前**触发溢出。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiaNwAzyibcWdS98SdqtoS0EPwDibYa6639N8JngctlpK05sSsGhibkAz2Ww/640?wx_fmt=png&from=appmsg "")  
  
更好的利用步骤（针对大小为 0x800 的块）  
  
之前的空闲列表是D→ A→ B→ C。现在，我们需要A→ D→ B→ C（图 1）。然后我们可以从 溢出A到B（图 2），并得到A→ D→ B→ C'（图 3），其中C'与 重叠D。  
  
我们不能像上一节那样轻易地分配块，因为  
explode_quoted_string()现在的天意发生在目标字符串的分配之前。此外，我们不能盲目地分配 3 个块：由于空闲列表现在是→ → → ，我们需要让 PHP 分配一个块，然后分配目标字符串（图 4），然后再分配另外两个（图 5）。A  
D  
B  
C''  
  
让我们一步一步地执行我们的策略。首先，我们将使用  
_to执行溢出，从而进入步骤 2。为了强制分配A，我们将使用_bcc，以便  
email_input_format()返回一个适合0x800块的字符串。空闲列表变为D→ B→ C'。  
  
现在我们需要解决最困难的部分：找到目标字符串。我查看了负责显示错误消息的整个堆栈跟踪，最终找到  
rcmail_output_html::get_js_commands()  
```
# program/include/rcmail_output_html.php    
class rcmail_output_html extends rcmail_output
{
    protected function get_js_commands(&$framed = null)
{
        $out             = '';
        $parent_commands = 0;
        $parent_prefix   = '';
        $top_commands    = [];

        // these should be always on top,
        // e.g. hide_message() below depends on env.framed
        if (!$this->framed && !empty($this->js_env)) {
            $top_commands[] = ['set_env', $this->js_env];
        }
        if (!empty($this->js_labels)) {
            $top_commands[] = ['add_label', $this->js_labels];
        }

        // unlock interface after iframe load
        $unlock = isset($_REQUEST['_unlock']) ? preg_replace('/[^a-z0-9]/i', '', $_REQUEST['_unlock']) : 0;
        if ($this->framed) {
            $top_commands[] = ['iframe_loaded', $unlock];
        }
        else if ($unlock) {
            $top_commands[] = ['hide_message', $unlock];
        }

        $commands = array_merge($top_commands, $this->js_commands);

        foreach ($commands as $i => $args) {
            $method = array_shift($args);
            $parent = $this->framed || preg_match('/^parent\./', $method);

            foreach ($args as $i => $arg) {
                $args[$i] = self::json_serialize($arg, $this->devel_mode);
            }

            if ($parent) {
                $parent_commands++;
                $method        = preg_replace('/^parent\./', '', $method);
                $parent_prefix = 'if (window.parent && parent.' . self::JS_OBJECT_NAME . ') parent.';
                $method        = $parent_prefix . self::JS_OBJECT_NAME . '.' . $method;
            }
            else {
                $method = self::JS_OBJECT_NAME . '.' . $method;
            }

            $out .= sprintf("%s(%s);\n", $method, implode(',', $args));
        }

        $framed = $parent_prefix && $parent_commands == count($commands);

        // make the output more compact if all commands go to parent window
        if ($framed) {
            $out = "if (window.parent && parent." . self::JS_OBJECT_NAME . ") {\n"
                . str_replace($parent_prefix, "\tparent.", $out)
                . "}\n";
        }

        return $out;
    }
}
```  
  
此方法生成在 HTTP 响应中显示的**原始JavaScript 代码**。  
  
它相当复杂，但从某种意义上来说，这是一件好事：由于返回值  
$out必然会在某个时刻显示出来，因此与其连接的每个变量都是一个潜在的目标字符串。此外，这里的每一行代码都会执行一个或多个分配、释放或重新分配...一种处理步骤 5 的方法。因此，每行代码都是一个小工具，可能会也可能不会帮助我们覆盖字符串头。  
  
可悲的是，这里没有像这样简单的小工具  
explode_quoted_string()：我们需要变得更聪明。  
  
找到目标  
  
让我们通过删除未输入的条件来简化代码：  
```
01: protected function get_js_commands()
02: {
03:     $out             = '';
04:     $top_commands    = [];
05: 
06:     // unlock interface after iframe load
07:     $unlock = isset($_REQUEST['_unlock']) ? preg_replace('/[^a-z0-9]/i', '', $_REQUEST['_unlock']) : 0;
08:     $top_commands[] = ['iframe_loaded', $unlock];
09: 
10:     $commands = array_merge($top_commands, $this->js_commands);
11: 
12:     foreach ($commands as $i => $args) {
13:         $method = array_shift($args);
14: 
15:         foreach ($args as $i => $arg) {
16:             $args[$i] = self::json_serialize($arg, $this->devel_mode); // [1]
17:         }
18: 
19:         $method = 'if (window.parent && parent.rcmail) parent.rcmail.' . $method;
20:         $out .= sprintf("%s(%s);\n", $method, implode(',', $args)); // [2]
21:     }
22: 
23:     $out = "if (window.parent && parent.rcmail) {\n"
24:          . str_replace('if (window.parent && parent.rcmail) parent.rcmail.', "\tparent.", $out)
25:          . "}\n";
26: 
27:     return $out;
28: }
```  
  
在我们的例子中，当代码到达时get_js_commands()  
，$this->js_commands是一个包含单个元素的数组，即一个包含 2 项的数组：  
["display_message", "Addresse courriel invalide: <email-we-sent>"]。因此，该  
$commands数组由 2 个元素组成：  
```
[
    ["hide_message", "<unlock-value>"],
    ["display_message", "Addresse courriel invalide: <invalid-email>"],
]
```  
  
然后，每行都用于在 中迭代构建部分 javascript 代码  
$out，然后返回变量。在 12 行到 21 行的循环迭代中，我们控制  
$args[0]，它会被 JSON 序列化，然后使用 进行格式化  
sprintf()。让我们逐一进行两次迭代。在进入 之前  
foreach()，空闲列表是D→ B→ C'：下一个分配必须是我们的目标字符串。  
  
如果我们为 HTTP 参数指定大小0x6a1  
_unlock，则循环的第一次迭代将以  
$out大小超过  
0x700字节而结束。因此，它将被分配到块中  
D。然后，  
$out在其大小发生变化之前，我们需要再进行 2 次分配来覆盖 的长度。我们需要在循环的最后一次迭代中完成它们。  
  
为了实现这一点，我们将其设置  
invalid_email为0x63c ASCII 字节，后跟0x37空字节。当错误消息被 JSON 序列化[2]时，  
$args[0]由于它包含空字节，其大小会大大增加：每个空字节都成为其 unicode 转义表示，  
\u0000。因此，JSON 编码的  
$args[0]大小约为0x786字节。因此它被分配在 中  
B。该  
sprintf()调用向其中添加了几个字节，并导致在 中分配一个大小为0x800  
C'的新块。此时，我们已成功覆盖 的  
D标头：的大小大大增加，就在它再次被修改之前，它与[2]  
$out的结果连接起来！  
sprintf()  
  
最后，我们得到了我们期望的泄漏：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiaRGTVxEwaz2JHibI3lQhZc6tMh8aulFj4BEDcicTEfjLExPPLhOuMqWpA/640?wx_fmt=png&from=appmsg "")  
  
成功泄漏内存  
  
注意：sprintf()分配一个大小为 0x800 的块来存储结果字符串，这迫使我们攻击这个块大小。  
  
**两条路**  
  
通过仔细设置堆，我们可以同时泄漏指向 PHP 二进制文件的指针和靠近目标字符串位置的指针。因此，ASLR 和 PIE 变得无关紧要。此外，我们已经知道如何破坏空闲列表，因此我们可以在堆中的任何位置分配一个块。但游戏还没有结束。此时，有两种方法可以采用。  
  
第一个是我们工作的逻辑延续：使用我们的二进制损坏来执行代码。它通常涉及转储二进制文件的部分以找到有趣的偏移量，然后启动 ROP 链。第二个涉及执行仅数据攻击。每种方法都有其优点和缺点。虽然我在 OffensiveCon 上演示了二进制漏洞利用，但我发现仅数据攻击更优雅，因此我将展示它。它是更深入地研究 PHP 引擎的好方法。  
  
仅数据攻击  
  
与二进制攻击相比，纯数据攻击的优势在于我们不依赖机器代码。相反，我们使用低级漏洞来破坏 PHP 变量并改变脚本的执行（一个非常简单的例子是设置一个假设的  
$is_admin标志来  
true提升我们的权限）。  
  
虽然我们可以构建相当复杂的结构，但我们只能引用堆地址。因此，并非每个变量都可以被覆盖：我们可以针对简单类型（bool  
、、int）  
string和  
arrays，但不能  
objects，因为代表它们的结构  
zend_object包括指向主二进制文件的指针（我们对此了解不多！）。  
  
理想目标是存储在  
$_SESSION数组中的会话变量，原因如下。首先，它们在漏洞利用后仍然存在（前提是漏洞没有崩溃）。其次，它们在脚本执行结束时被保存，让我们有“时间”来修改它们。第三，从攻击者的角度来看，它们通常很有趣：谁没有梦想过能够改变自己的角色呢  
superadmin？  
  
然而，在 Roundcube 中，没有角色的概念。但浏览代码，我们实际上可以找到更好的：  
```
# program/lib/Roundcube/rcube_user.php
class rcube_user
{
    function get_prefs()
{
        if ($_SESSION['preferences_time'] < time() - 5 * 60) {
            $saved_prefs = unserialize($_SESSION['preferences']); // <-----------
            $this->rc->session->remove('preferences');
            $this->rc->session->remove('preferences_time');
            $this->save_prefs($saved_prefs);
        }
        ...
    }
}
```  
  
调用PHP 反序列化函数unserialize()！能够执行反序列化通常意味着在大型框架上可以实现 RCE，Roundcube 也不例外。事实上，它使用Guzzle（一种流行的库）来执行 HTTP 请求。使用PHPGGC，我们可以生成  
guzzle/fw1有效载荷，并将反序列化转换为任意文件写入。  
  
显然，在正常使用情况下，  
$_SESSION['preferences']用户无法修改。然而，我们不是普通用户：我们可以在堆中写入！因此，我们可以让两个块重叠并覆盖  
zend_string此会话变量！  
  
但问题又来了：在默认配置下，  
$_SESSION['preferences']永远不会被设置。没有什么可以覆盖的！不过，一切还不算完：我们可以更深入地研究，使用我们的任意分配将元素添加到数组中  
$_SESSION。我们该怎么做呢？  
  
我们需要深入研究 PHP 数组的实现。  
  
PHP 数组  
  
PHP 数组由键/值对组成，其中值可以是任意类型，但键可以是整数或字符串。我们在此仅介绍字符串键。  
  
每一对都保存在一个称为的结构中  
Bucket：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiabp9g6gGZw3q3zge1bAXxzAC9ebvkuuPaYd4pAEa8HKASxvJZavfgew/640?wx_fmt=png&from=appmsg "")  
  
结构Bucket  
  
第一个元素  
val可以是简单值（long、float）或指向值的指针（、 等  
zend_string）  
zend_object。定义变量类型。指示列表中下一个的索引（稍后会详细介绍）。存储在 中，其DJBX33A 哈希存储在 中。type  
next  
Bucket  
key  
Bucket.key  
  
  
Bucket.h  
  
创建非空数组时，PHP 会分配一个  
zend_array结构和另一个由  
uint32_t值列表hashmap组成的块，后跟8   
Buckets的列表。  
  
zend_array.arData指向这个 Butterfly 结构：这个结构的底部是bucket列表，顶部是 hashmap。hashmap可以将哈希转换为bucket  
zend_string列表中的索引：当尝试访问某个键的值时，PHP 会将表掩码 ( ) 与键的哈希 ( )进行或运算，得到一个负数，并将其用作指针的索引。zend_array.nTableMask  
zend_string.h  
int32_t  
(uint32_t[]) arData  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiaeVIb93QKCB6MwiaficJYbKjC23ILEM70drDh7GfpgrLqc1vaceicX4Tfg/640?wx_fmt=png&from=appmsg "")  
  
访问哈希图  
  
在上面的例子中，我们在包含8 个preferences元素的数组中查找。索引等于。通过从哈希表的末尾开始选择第 元素，我们得到（蓝色）。因此，PHP 检查第五个存储桶。(int32_t) (0xfffffff0h | 0xc0c1e3149808db17) = 0xfffffff7 = -9  
9  
4  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tacP446WExM6COP1Ody0bwJiatbdAAMJ62QaMg95KSWoX1JWlLkbhsjkemofRdrWd33JhL84uOGGZSQ/640?wx_fmt=png&from=appmsg "")  
  
一个 bucket 及其键值对。键是preferences，值是序列化的字符串。  
  
为了确保这确实是正确的存储桶（两个不同的字符串可能具有相同的哈希值，或者映射到相同索引的哈希值），PHP 会根据所提供键的哈希值检查存储桶的哈希值。如果它们相等（在我们的示例中，它们是相等的），它会比较键的大小和值。如果它们相等（在我们的示例中，它们再次相等），则它就是正确的存储桶，PHP 将返回其值。如果预期的键与存储桶的键不同，PHP 将转到通过值指示索引的存储桶  
next（在我们的示例中  
5为蓝色），并继续查找，直到找到它。  
FF FF FF FF是一个特殊值，表示没有存储桶。  
  
覆盖会话数组  
  
因此，覆盖哈希图和一个存储桶就足以将键值对添加到数组中。  
  
现在，请记住，我们的原语让我们改变一个空闲列表指针，从而在堆中的任何位置分配一个  
zend_string（或任何东西，但s 是最有用的），即，我们可以让 PHP 分配任意块。  
zend_string  
  
会话数组由 32 个元素组成，因此其hashmap+bucket块的大小为0x500（ hashmap 为0x100， bucket 为0x400）。我们希望让伪造的堆指针指向正上方。  
  
这相当简单，但我们还需要采取一些预防措施。首先，我们不能随便指向任何地方：当 PHP 分配我们的任意块时，它会认为这真的是一个空闲块（愚蠢的 PHP）。因此，它会认为它的前 8 个字节是指向下一个块的指针。假设它不是一个有效的指针，如果 PHP 再分配一个相同大小的块，我们就会崩溃。此外，当我们的假块被释放时，它可能会再次被分配，并包含我们无法控制的数据。我们需要保护它不被重新分配；否则，它可能会完全破坏我们的工作。  
  
为了解决第一个问题，我们可以使用 HTTP 参数创建一个由0x500 个块组成的网络，这些块中填充了空字节，并以空洞分隔，希望hashmap+bucket块能够分配在其中两个块之间。如果我们指向这样一个块，PHP 会将空指针读作下一个空闲列表元素，并认为空闲列表已经耗尽，从而避免崩溃。  
  
为了解决第二个问题，一旦我们分配了任意块，我们也会分配大量大小为0x500的块。当它们全部被释放时，按顺序，最后的块将在空闲列表中位于我们的块之前，从而保护它免受分配。  
  
现在我们开始：使用我们的二进制漏洞，我们修改会话的内容，并将其设置  
preferences为任意字符串。然后，我们向索引发出 HTTP 请求，其中的内容  
$_SESSION['preferences']被反序列化。使用  
guzzle/fw1有效载荷，我们将文件写入  
public_html/shell.php。  
  
演示  
  
这是一个针对 PHP 8.3 下的 Roundcube 1.6.6 的演示。  
  
  
该漏洞可在此处获取。与往常一样，它带有评论，并揭示了我在博客文章中未包含的漏洞部分。  
  
对生态系统的影响  
  
因此，直接调用  
iconv()是可利用的，并且会产生影响。但它是唯一受 CVE-2024-2961 影响的 PHP 函数吗？根本不是。  
  
首先，  
iconv()有很多兄弟函数，例如iconv_strrpos()  
，iconv_substr()..这些函数可能存在漏洞（我还没有检查过）。但还有一个更可怕、更出乎意料的下沉。  
  
PHP 有一个非常流行的扩展，称为mbstring。该扩展用 C 语言构建，允许您操作各种字符集下的字符串，并执行字符集转换。它是许多框架和 CMS 的依赖项。  
  
但  
mbstring默认情况下不会安装。如果它没有安装（您需要超级用户权限才能安装），但您仍然想使用依赖它的库或框架，会发生什么？好吧，在这种情况下，您可以使用该库的 PHP 实现。名为 的项目symfony/polyfill-mbstring具有完全相同的 API：两者可以互换使用。而且它非常受欢迎，安装量超过8.23 亿次。  
  
但是polyfill-mbstring如何在不使用 的情况下，将一种字符集转换为另一种字符集  
mbstring？好吧，它使用...   
iconv()。  
  
因此，您可能认为您正在使用  
mbstring，因此不存在漏洞，但您却使用了 PHP 实现的 polyfill 版本，该版本使用了  
iconv()。  
  
随着 PHP 包管理器 的出现  
composer，这条线可能比想象中更容易跨越。如果您安装两个项目，一个依赖于  
ext-mbstring（原始 C 扩展），另一个依赖于  
polyfill-mbstring（PHP 等效项），则无论是否安装了扩展，安装都会成功  
mbstring。  
  
果然，当您运行我提供的 POC 时，但这次使用的  
mb_convert_encoding()是iconv()：  
```
- $output = iconv("UTF-8", "ISO-2022-CN-EXT", $input);
+ $output = mb_convert_encoding($input, "ISO-2022-CN-EXT", "UTF-8");
```  
  
您也会遇到崩溃。  
  
虽然我在这里停止了分析（寻找目标非常耗时），但我希望这不是我们最后一次看到 CVE-2024-2691 和 PHP。  
  
**结论**  
  
在利用PHP 过滤器之后，我们现在通过直接调用利用CVE-2024-2961iconv()来入侵著名的网络邮件 Roundcube。这让我们更深入地了解了 PHP 引擎的内部，并为潜在的新漏洞利用开辟了道路，利用明显的接收器和不太明显的接收器。  
  
现在我们已经通过 PHP 中的两种方式展示了影响，我们需要讨论最后一个问题：如果您拥有的文件读取原语是盲目的，会发生什么？  
  
敬请关注第 3 部分！  
  
```
https://www.ambionics.io/blog/iconv-cve-2024-2961-p2
```  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  

#  Iconv 实现PHP引擎RCE part2   
3bytes  3072   2024-06-17 20:29  
  
##  引言   
  
几个月前，我偶然发现了一个存在于glibc中长达24年的缓冲区溢出问题，glibc是Linux程序的基础库。尽管这个问题在许多众所周知的库或可执行文件中都可达，但很少被利用——因为它没有提供太多的灵活性，而且需要难以实现的先决条件。寻找目标主要带来的是失望。然而，在PHP中，这个漏洞却显得格外突出，并证明了它在两种不同方式上利用PHP引擎的用途。  
  
在第一部分中，我通过回顾其发现、局限性，并展示了如何将PHP中的文件读取漏洞转换为远程代码执行（RCE）。在这篇博文中，我将探索一种新的在PHP上利用该漏洞的方法，即使用对iconv()的直接调用，并以Roundcube为例，演示这种漏洞的影响。Roundcube是一个流行的PHP webmail客户端。同样，我将通过揭示在使用mbstring时达到iconv()的意外方式，展示对生态系统的影响。  
  
如果您不熟悉网络利用、PHP或PHP引擎，请不要担心：我将沿路解释相关的概念。  
- [引言]  
  
- [另一个触发器]  
  
- [PHP上的远程二进制利用：理论]  
  
- [非自愿的缓解措施]  
  
- [鼓励的架构]  
  
- [理论上的利用目标]  
  
- [攻击Roundcube]  
  
- [仅限数据的攻击]  
  
- [PHP数组]  
  
- [覆盖会话数组]  
  
- [堆塑形101]  
  
- [代码小工具]  
  
- [修订后的泄露策略]  
  
- [寻找目标]  
  
- [达到漏洞]  
  
- [获取泄露]  
  
- [两条路径]  
  
- [演示]  
  
- [对生态系统的影响]  
  
- [结论]  
  
- [我们正在招聘！]  
  
##  另一个触发器   
  
虽然使用php://filter触发这个漏洞非常方便，但达到iconv()调用的最明显方式是使用其同名API。在PHP中，它的原型如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763Tj5WQYE5ACON60tHQ69PpMym20uh1H62YdHCJQmsOvH4oWb8lt2gib1Q/640?wx_fmt=png&from=appmsg "")  
  
这个函数与C语言等价物的区别在于，缓冲区管理，在C语言中必须由调用者完成，现在不可见了，因为PHP在幕后处理了。在第一部分中，我们了解到我们非常依赖输出缓冲区的外观：在许多情况下，这个漏洞可能根本无法利用。  
  
那么，PHP的iconv()实现是否易受攻击？当我们使用iconv()将大小为N的字符串转换为另一种字符集时，PHP会分配一个大小为N+32的输出缓冲区，希望“在大多数情况下避免realloc()”[1]。如果缓冲区不够大[2]，它会变大[3]。  
```
// ext/iconv/iconv.c

PHP_ICONV_API php_iconv_err_t php_iconv_string(const char *in_p, size_t in_len, zend_string **out, const char *out_charset, const char *in_charset)
{
    ...

    in_left= in_len;
    out_left = in_len + 32; /* 在大多数情况下避免realloc() */ // [1]
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
                /* 转换后的字符串比输出缓冲区长 */
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
  
因此，输出缓冲区比输入缓冲区大32个字节，使溢出容易触发。在这里有一个可用的poc。简单来说：  
```
$input = 
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .
    "AAA劄劄\n劄劄\n劄劄\n劄\n劄\n劄\n劄";
$output = iconv("UTF-8", "ISO-2022-CN-EXT", $input);
```  
  
现在我们知道这个漏洞可以使用iconv()来触发，我们可以寻找目标。再次强调，先决条件如下：我们需要控制输出字符集，至少控制输入缓冲区的一部分。那么，哪种类型的软件可能满足这些条件呢？我最初的想法是看看电子邮件客户端，因为电子邮件意味着编码。但在我们深入攻击的细节之前，让我们再进行一些理论探讨。  
##  远程二进制利用在PHP上：理论   
##  非自愿的缓解   
  
尽管PHP被许多人认为是不安全的，但针对PHP的远程二进制利用——至少可以说——并没有得到很好的记录。一个攻击者，拥有像我们这样的缓冲区溢出，如何破坏PHP引擎并获得远程代码执行？在我们开始之前，我将展示为什么这并不像看起来那么容易。  
  
你应该对PHP堆的工作原理有一个合理的了解，从第一部分。它的设计是直接的，并且没有任何保护（还没有？）。然而，对我来说，它的主要攻击缓解来自于一个简单的（可能与安全无关的）设计选择：**堆只处理一个请求**。当您向PHP发送HTTP请求时，它会创建一个新的堆，解析并分配您的参数（GET，POST等），编译并运行所请求的脚本，返回HTTP响应，然后，当一切都说完了，删除堆。  
  
想想你标准的远程利用。我们可以大致将其分为三个步骤：设置，触发和使用。以使用后释放为例：您可能首先与服务器交互，以形成目标的堆，可能喷一些结构，或安排一些自由列表。那是设置。然后，您会发送第二个请求，触发漏洞，并使应用程序释放一些块，同时留下一个指针。紧接着，您会发出一个额外的稻草，用您更喜欢的东西替换缺失的块。第四个请求将是棺材上的钉子：利用您的类型混淆结构，并启动一些ROP链，从而使用您的漏洞。  
  
使用PHP，我们需要**所有这些步骤**在**一次请求-响应交换**的过程中发生。并且在我们发送HTTP参数后，我们的手就被束缚了：没有更多的方法与引擎交互，我们期望设置，触发和使用在它们自己发生，在我们得到HTTP响应和堆被销毁之前。  
  
为了绕过这个问题，人们经常针对允许您通过设计，在请求运行时与PHP交互的函数。这就是为什么我几年前针对PHP中与数据库相关的代码：当PHP发送SQL查询并接收结果时，它为我们提供了一种交换数据的方式，强制PHP进行分配，释放等。更一般地说，像unserialize()这样的函数中的漏洞是一个理想的目标，因为它让您触发一个错误，然后创建任意对象，字符串，数组...  
  
在第一部分，当攻击php://filter时，我们有一个类似的情况，我们可以通过使用仔细挑选的过滤器和桶对堆执行操作，并在任意时刻通过转换为ISO-2022-CN-EXT来引发内存损坏。但在这种新情况下，直接调用iconv()，我们处于一个非常不安的位置：该函数只允许我们触发漏洞。要执行设置，然后使用它，我们需要另一种方式。  
##  鼓励的架构   
  
然而，我们有一些有利于攻击的事情。环境是攻击友好的：为了处理HTTP请求，PHP-FPM和mod PHP有一个主/工作程序架构，其中根进程控制一些较少特权的工作程序。每当一个工作程序死亡时，主进程通过分叉重新启动它。两个方面的优势。首先，如果我们以某种方式崩溃了一个工作程序，它会重新生成。没有DOS服务器的风险。第二，内存布局（ASLR，PIE）在工作程序中是相同的：如果我们从一个中泄露地址，我们保证它们的MSB将与其他人相同。  
##  理论上的利用目标   
  
进行远程PHP利用的标准方法是两次使用漏洞：一次获取泄露，然后执行代码。要使这成为可能，我们可以依次破坏两个结构：zend_string和zend_array。  
  
zend_string结构表示PHP字符串。它由几个字段组成，后面是一个缓冲区。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763TPOJMXBnDrvjSAc2LhU4t2seAzrlRlCBXoxTGpM29gQtNuLnrVsjzsA/640?wx_fmt=png&from=appmsg "")  
  
zend_string结构  
  
在PHP中，字符串不是以NULL终止的字节集合；它们的len字段定义了它们的大小。因此，要显示字符串s，PHP会显示从s+18h开始的len个字节。如果我们设法人为地增加这个字段的值，我们就可以泄露内存。  
  
有了泄露的内存，事情变得更容易。我们可以轻松地在堆中定位自己，并获取指向主二进制的指针。下一步，执行代码，可以通过覆盖zend_array结构的最后一个字段来完成，它表示PHP数组：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763T7rNAU4oJ0k4IpuiapGzl9bsw7KFeB8F8StsDKs3hUKMAicGwdeg7sVow/640?wx_fmt=png&from=appmsg "")  
  
zend_array结构  
  
pDestructor是一个指向负责从数组中删除元素的函数的指针。它通常指向zval_ptr_dtor，PHP的变量销毁函数。改变它的值允许我们获得RIP：当数组被删除时，它的元素也被删除，因此pDestructor被调用。  
  
但现在理论已经足够了。  
##  攻击Roundcube   
  
Roundcube  可能是最受欢迎的PHP webmail。它通常被邮件提供商，网络托管商或私人公司用作快速简便的方式，无需桌面客户端即可访问您的邮件。你可能已经在线上看到过一个：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763TpAlo8X1UiaYexm9HaFPlAfbxKIpeWLSZrjwlljMpzZibE8m0qmw5CoIA/640?wx_fmt=png&from=appmsg "")  
  
Roundcube界面  
  
可悲的是，它符合我们的所有先决条件，并让我们作为标准用户实现**远程代码执行**。  
##  达到漏洞   
  
当使用Roundcube发送电子邮件时，用户可以指定收件人，抄送和密送使用_to，_cc和_bcc字段。由于你们可能都已经发送过电子邮件，我不会描述它们是什么；你知道它们代表一系列电子邮件地址。  
  
现在，除了这些字段外，用户还可以发送一个_charset HTTP参数[1]。在这种情况下，Roundcube将使用iconv()将前述参数转换为字符集后再进行处理。代码看起来像这样（大大简化）：  
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
  
虽然 rcube_utils::get_input_string() 只是一个简单的包装器，用于获取HTTP参数并将其转换为 $charset，email_input_format() 却是一个复杂的函数，用于验证电子邮件列表是否有效。实际上，如果提供的电子邮件地址之一无效，它将被复制到 $this->invalid_email 中，并在错误消息中显示，例如：Invalid email address: <email> [2]。  
  
我们可以使用 _to、_cc 或 _bcc 触发漏洞。  
##  获取泄露信息   
  
为了获取泄露信息，我们需要在 zend_string 的 len 字段被显示之前覆盖它。我们将这个字符串称为 目标字符串。在我们的情况下，我们有一个非常简单的候选：如果我们发送的电子邮件之一无效，Roundcube 将显示一个包含该电子邮件的错误消息。我们可以在 _to 中发送这样的电子邮件，并将其用作 目标字符串！  
  
现在，我们的原始数据远不是 写什么-在哪里，甚至不是任意溢出。它最多在界限之外写入3个字节。如果我们直接溢出到 zend_string，我们唯一能覆盖的就是它的 refcount。显然，我们不能直接使用这个漏洞来做我们想做的事情。相反，我们可以利用1字节溢出到一个空闲块指针，类似于第一部分中使用的技术，以移位它，并使一个块与 目标字符串 重叠，允许我们覆盖它的头部。  
  
虽然这一切都在理论上有效，但我们面临着 每个请求一个堆 的缓解措施。我们如何在漏洞触发之前塑造堆？一旦我们更改了空闲列表指针的LSB，我们如何让PHP分配更多的块，以覆盖 目标字符串 的头部？  
### 堆塑形101  
  
使用GET、POST和cookies，可以强制PHP分配任意长度的字符串。每次您发送一个键值对如 key=value，PHP都会分配一个 zend_string 来存储键，以及两个来存储值。此外，您可以通过发送新的值来使PHP释放块：key=value&key=other-value 会导致PHP分配 key，然后 value 两次，然后 other-value 两次，最后释放两个 value 字符串。例如，要填充一个包含大小为 0x400 的块的页面，并留下第三个未分配，您可以使用以下组合（大小为 N 的 zend_string 存储在 N+0x19 字节上）：  
```
# 假设我们有一个包含四个未分配的0x400块的页面：C1 C2 C3 C4
# 使用一个“标准”的空闲列表 C1→C2→C3→C4
 a=AA...AAAAA (0x3e7次)  # 在C1和C2分配两个0x400块
 &b=BB...BBBBB (0x3e7次)  # 在C3和C4分配两个
 &b=                          # 释放C3，然后C4
 &CC...CCCCC (0x3e7次)=   # 分配C4
```  
  
因此，我们可以使用HTTP参数在创建后立即按照我们的喜好塑造堆。虽然这是非常好的，但并不完美：现代PHP应用程序在编译和运行时会执行数千次堆操作，从而完全破坏我们的工作。想象整个过程：解析代码、注释、字符串、对象、将代码编译为PHP VM指令，然后运行它们，操作数据，进入和退出函数，等等。当你可以的时候，最好的计划是尝试在应用程序使用较少的块大小上进行攻击，以便程序不会太破坏你的设置。  
### 代码小工具  
  
现在我们可以影响堆的外观，我们可以建立一个五步过程来获取我们的泄露：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763TVwyqLgd7jx0mUPdX8gOocFWs9WFw3pyIMia4h1odU1icwSuOyzMUQFyw/640?wx_fmt=png&from=appmsg "")  
  
在大小为0x100的块上利用步骤  
  
我们首先塑造堆，使得4个 0x100 块 A、B、C、D 是连续且空闲的，并且空闲列表是：D→A→B→C（图1）。  
  
在使PHP在（虚构的）地址 0x7fff11a33300 (D)处写入存储无效电子邮件地址的 zend_string 之后（图2），我们从地址 0x7fff11a33000 (A)的块溢出，覆盖指向 0x7fff11a33200 (C)的指针的LSB，使其变为 0x7fff11a33248（图3）。漏洞触发后，我们有 A→B→C+48h（图4）。然后，通过3次更多的分配，我们分配一个与 目标字符串 重叠的块（图5），允许我们覆盖它的 zend_string 头部，更具体地说，是它的 len 字段。  
  
我们知道如何执行设置（步骤1，2）和触发漏洞（步骤3，4）。但还有一个步骤缺失：我们如何在破坏空闲列表后分配块？在执行的这一点上，脚本是独立的。唯一能让PHP分配任何东西的是脚本本身。因此，为了执行我们所需的分配，我们需要研究让PHP应用程序为我们执行的方法。  
  
让我们再次检查目标函数：  
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
  
假设我们使用 _to 设置一个无效的电子邮件，然后使用 _cc 触发漏洞，我们可以在 [1] 和 [2] 之间发生的任何事情来分配我们的块。让我们看看 email_input_format()（再次，大大简化）：  
```
# /program/include/rcmail_sendmail.php
class rcmail_sendmail
{
    /**
     * 解析并清理电子邮件地址输入（并计算地址数量）
     *
     * @param string $mailto 地址输入
     * @param bool   $count  是否计算收件人（计数保存在 $this->parse_data['RECIPIENT_COUNT']）
     * @param bool   $check  验证地址（错误保存在 $this->parse_data['INVALID_EMAIL']）
     *
     * @return string 规范的收件人字符串（逗号分隔）
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
  
该方法将 $mailto，一个电子邮件列表，分割成一个数组 [1]。这是强制PHP分配块的完美方式！  
  
现在我们有了一个完整的策略：  
- 使用HTTP参数塑造堆（步骤1）  
  
- 使用 _to 发送一个无效的电子邮件，设置 $this->invalid_email（步骤2）  
  
- 使用 _cc 触发漏洞，修改空闲列表（步骤3，4）  
  
- 使用 _bcc 强制PHP分配字符串，覆盖 invalid_email 的长度（步骤5）  
  
当错误消息被显示时，内存被泄露。  
  
在构建了一个利用之后，我设法让Roundcube显示了一个带有我修改后的电子邮件的错误（Adresse courriel invalide 是法语中的 Invalid email address），但这是... 令人不满意的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763T15rhYGTEcHFarGM7Q2PS3rEczXn6X2cXNOicCTe3pAzsOrZbEVpeNzQ/640?wx_fmt=png&from=appmsg "")  
  
JSON编码的错误消息  
  
错误消息只包含空格、Unicode转义的空字节和ASCII字符。发生了什么？实际上，Roundcube 将错误消息显示为JSON。为了编码它们，它使用 json_encode() API，并带有  JSON_INVALID_UTF8_IGNORE 标志。结果，无效的UTF-8字符被丢弃了。由于内存中的大部分数据都不是，我们的泄露不包含任何有趣的东西。  
### 修订后的泄露策略  
  
我们的 目标字符串 并没有带来最丰富的结果，但这个想法仍然是正确的。相反，我们需要找到一个以“原样”显示（或者，经过较少修改）的变量。  
  
像大多数网络应用程序一样，Roundcube 在执行的最后阶段格式化其输出，远远 **在我们触发漏洞之后**。很明显，这是大多数候选 目标字符串 分配的地方。因此，我们需要改变我们的利用算法。我们仍然会使用4个块，并且仍然会移动 C 以使其与包含 目标字符串 的 D 重叠。但这一次，我们在 目标字符串 分配 **之前** 触发溢出。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763TjwPuSsazBIr9713EqRWR8E00ncsGFRS7ibJBx8EkmhLDB1DpibXLj3ZA/640?wx_fmt=png&from=appmsg "")  
  
更好的利用步骤（在大小为0x800的块上）  
  
以前的空闲列表是 D→A→B→C。现在，我们需要 A→D→B→C（图1）。然后我们可以从 A 溢出到 B（图2），得到 A→D→B→C'（图3），其中 C' 与 D 重叠。  
  
我们不能像前一节那样轻易地分配块，因为现在天赐的 explode_quoted_string() 发生在 目标字符串 分配 **之前**。此外，我们不能只是盲目地分配3个块：由于空闲列表现在是 A→D→B→C'，我们需要让PHP分配一个块，然后是 目标字符串（图4），然后是另外两个（图5）。  
  
让我们一个一个地执行我们策略的步骤。首先，我们将使用 _to 执行溢出，最终达到步骤2。为了强制在 A 中分配，我们将使用 _bcc，以使 email_input_format() 返回一个适合 0x800 块的字符串。空闲列表变为 D→B→C'。  
  
现在我们需要解决棘手的部分：找到一个 目标字符串。我浏览了负责显示错误消息的整个堆栈跟踪，最终在 rcmail_output_html::get_js_commands() 中找到了：  
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
  
这个方法生成的 JavaScript 代码会在 HTTP 响应中以 **原始** 形式显示。  
  
它的复杂性在某种程度上是件好事：由于返回值 $out 迟早要被显示，每个连接到它的变量都是潜在的 目标字符串。此外，这里的每行代码执行一个或多个分配、释放或重新分配...这是处理步骤5的一种方式。因此，每一行代码都是一个 小工具，可能会帮助我们覆盖字符串头部。  
  
遗憾的是，这里没有像 explode_quoted_string() 那样简单的小工具：我们需要更聪明一些。  
### 寻找目标  
  
让我们通过移除我们不进入的条件来简化代码：  
```
protected function get_js_commands()
{
    $out = '';
    $top_commands = [];
 
    // 解锁iframe加载后的界面
    $unlock = isset($_REQUEST['_unlock']) ? preg_replace('/[^a-z0-9]/i', '', $_REQUEST['_unlock']) : 0;
    $top_commands[] = ['iframe_loaded', $unlock];
 
    $commands = array_merge($top_commands, $this->js_commands);
 
    foreach ($commands as $i => $args) {
        $method = array_shift($args);
 
        foreach ($args as $i => $arg) {
            $args[$i] = self::json_serialize($arg, $this->devel_mode); // [1]
        }
 
        $method = 'if (window.parent && parent.rcmail) parent.rcmail.' . $method;
        $out .= sprintf("%s(%s);\n", $method, implode(',', $args)); // [2]
    }
 
    $out = "if (window.parent && parent.rcmail) {\n"
          . str_replace('if (window.parent && parent.rcmail) parent.rcmail.', "\tparent.", $out)
          . "}\n";
 
    return $out;
}
```  
  
在我们的情况下，当代码到达 get_js_commands() 时，$this->js_commands 是一个数组，包含一个单一元素，一个2项数组：["display_message", "Addresse courriel invalide: <email-we-sent>"]。因此，$commands 数组由2个元素组成：  
```
[
    [
        "hide_message", "<unlock-value>",
    ],
    [
        "display_message", "Addresse courriel invalide: <invalid-email>",
    ],
]
```  
  
然后，每一行被用来逐步构建 $out 中的部分 JavaScript 代码，然后返回该变量。在第12至21行的循环中，我们控制 $args[0]，它被 JSON 序列化，然后使用 sprintf() 格式化。让我们逐一看看两次迭代。在我们进入 foreach() 之前，空闲列表是 D→B→C'：下一次分配必须是我们的 目标字符串。  
  
如果我们给 HTTP 参数 _unlock 一个大小为 0x6a1，则循环的第一次迭代将以 $out 的大小超过 0x700 字节结束。因此它被分配在块 D 中。然后我们需要2次更多的分配来覆盖 $out 的长度，然后它的大小再次改变。我们需要在循环的最后一次迭代中让它们发生。  
  
为了实现这一点，我们将 invalid_email 设置为 0x63c ASCII 字节，后面跟着 0x37 个空字节。当错误消息被 JSON 序列化 [2] 时，由于它包含的空字节，$args[0] 的大小大大增加：每个空字节都变成了它的 unicode 转义表示，\u0000。因此，JSON 编码的 $args[0] 的大小约为 0x786 字节。因此它被分配在 B 中。sprintf() 调用增加了一些字节，导致在 C' 中分配了一个新的大小为 0x800 的块。在这一点上，我们已经成功地覆盖了 D 的头部：$out 的大小在被 sprintf() 的结果连接之前大大增加了 [2]！  
  
最后，我们得到了非常想要的泄露：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763TtXzLC5ZyuwoYEianqgfy401YHibVW2cr1tOhicvFJCRIZyXL9rZ5cxKnw/640?wx_fmt=png&from=appmsg "")  
  
成功泄露内存  
  
注意：sprintf() 分配一个大小为 0x800 的块来存储结果字符串，这迫使我们必须在这种块大小上进行攻击。  
##  两条路径   
  
通过仔细设置堆，我们可以同时泄露指向 PHP 二进制文件的指针和接近我们目标字符串位置的指针。因此，ASLR 和 PIE 变得无关紧要。此外，我们知道如何腐蚀一个空闲列表，因此我们可以在堆的任何地方 **分配一个块**。但这还不是 游戏结束。在这一点上，有两个方向可以选择。  
  
第一个是我们工作的逻辑延续：使用我们的二进制腐蚀来执行代码。它通常涉及转储二进制文件的部分内容以找到有趣的偏移量，然后启动 ROP 链。第二个涉及执行 仅限数据 攻击。每种方法都有其优点和不便之处。虽然在 OffensiveCon 上我展示了一个二进制利用，但我认为 仅限数据 攻击更优雅，因此我将展示它。它是深入了解 PHP 引擎的好方法。  
### 仅限数据攻击  
  
与基于二进制的攻击相比，仅限数据攻击的优势在于我们不依赖机器代码。相反，我们使用我们的低级错误来腐蚀 PHP 变量并改变脚本的执行（一个非常简单的例子可能是将假定的 $is_admin 标志设置为 true 以提升我们的权限）。  
  
虽然我们可以构建相当复杂的结构，但我们只能引用堆地址。因此，并非每个变量都可以被覆盖：我们可以针对简单类型（bool、int、string）和 arrays，但不能针对 objects，因为表示它们的结构 zend_object 包括指向主二进制的指针（我们对此不太了解！）。  
  
理想目标是会话变量，存储在 $_SESSION 数组中，有几个原因。首先，它们在利用后仍然存在（前提是没有崩溃）。第二，它们在脚本执行结束时保存，给我们“时间”修改它们。第三，它们通常从攻击者的角度来看是有趣的：谁没有梦想过能够改变他们的角色为 superadmin？  
  
在 Roundcube 中，没有角色的概念。但是浏览代码时，我们可以找到更好的：  
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
  
调用了 PHP 反序列化函数 unserialize()！能够执行反序列化通常意味着在大型框架上的 RCE，Roundcube 也不例外。实际上，它使用了 Guzzle，一个流行的用于 HTTP 请求的库。使用 PHPGGC，我们可以生成一个 guzzle/fw1 有效载荷，并转换反序列化为任意文件写入。  
  
显然，在正常使用情况下，$_SESSION['preferences'] 无法被用户修改。然而，我们不仅仅是普通用户：我们可以在堆中写入！因此，我们只需要使两个块重叠并覆盖这个会话变量的 zend_string 就可以了！  
  
但是，还有一个问题：在默认配置下，$_SESSION['preferences'] 从未被设置。没有什么可以覆盖的！不过，我们可以更深入地使用我们的任意分配将元素添加到 $_SESSION 数组中。我们如何做到这一点呢？  
  
我们需要深入了解 PHP 数组的实现。  
### PHP 数组  
  
PHP 数组由键/值对组成，其中值可以是任何类型，但键可以是整数或字符串。我们这里只涉及字符串键。  
  
每对数据都保存在一个叫做 Bucket 的结构中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763TsibRYc6RiaSjXCIgbqokghWEaTLOTJllTTFT9B3T3xia039Z9yx0vwiacQ/640?wx_fmt=png&from=appmsg "")  
  
Bucket 结构  
  
第一个元素 val 是一个简单值（long、float）或指向值的指针（zend_string、zend_object 等）。type 定义变量类型。next 表示列表中下一个 Bucket 的索引（稍后详细介绍）。key 存储在 Bucket.key 中，其 DJBX33A 哈希 存储在 Bucket.h 中。  
  
当创建一个非空数组时，PHP 分配一个 zend_array 结构和另一个块，该块由一系列 uint32_t 值组成，即 hashmap，后面是一系列 8 个 Buckets。  
  
zend_array.arData 指向这个蝴蝶结构：该结构底部是 buckets 列表，顶部是 hashmap。hashmap 允许你将 zend_string 哈希转换为 buckets 列表中的索引：当尝试访问某个键的值时，PHP 将表格掩码（zend_array.nTableMask）与键的哈希（zend_string.h）OR 起来，得到一个负的 int32_t，它将作为从 (uint32_t[]) arData 指针的索引。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763TxhQH56CQ6JSia6ADokqR7coLzMmibCicibn45BkaREMjNiaBUTQmQZz5mtA/640?wx_fmt=png&from=appmsg "")  
  
访问 hashmap  
  
在上面的例子中，我们正在一个 8 元素数组中查找 preferences。索引等于 (int32_t) (0xfffffff0h | 0xc0c1e3149808db17) = 0xfffffff7 = -9。通过从 hashmap 的末尾开始选择第 9 个元素，我们得到 4（在 蓝色 中）。结果，PHP 检查第五个 bucket。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZEkT0Rn34yGhCb36Dtu20ibiaiaqK4W763Ts8iaQiaEXPt2Qm2qlhEMgic9AUQHWUImbCWUWSQyS9GMicPA9vsDqqG72Q/640?wx_fmt=png&from=appmsg "")  
  
一个 bucket 及其键值对。键是 preferences，值是一个序列化的字符串。  
  
为了确保这确实是正确的 bucket（两个不同的字符串可能具有相同的哈希，或者映射到相同索引的哈希），PHP 会将 bucket 的哈希与提供的键的哈希进行比较。如果它们相等（在我们的例子中，它们是），它会比较键的大小和值。如果它们相等（在我们的例子中，它们再次相等），那就是正确的 bucket，PHP 返回值。如果预期的键与 bucket 的键不同，PHP 将前往 next 值指示的 bucket 索引（在我们的例子中，蓝色 的 5），并继续寻找。FF FF FF FF 是一个特殊值，表示没有 bucket。  
### 覆盖会话数组  
  
因此，覆盖 hashmap 和一个 bucket 足以向数组添加键值对。  
  
现在，记住，我们的原始数据让我们可以改变一个空闲列表指针，因此可以在堆的任何地方分配一个 zend_string（或任何东西，但 zend_strings 最有用），即我们可以强制 PHP 分配任意块。  
  
会话数组由 32 个元素组成，因此其 hashmap+bucket 块的大小为 0x500（0x100 用于 hashmap，0x400 用于 buckets）。我们希望让我们的假堆指针指向其正上方。  
  
这相当简单，但我们需要采取一些额外的预防措施。首先，我们不能只是指向任何地方：当 PHP 分配我们的任意块时，它会认为这真的是一个空闲块（愚蠢的 PHP）。因此，它将期望其前 8 个字节是指向下一个块的指针。假设它不是一个有效的指针，如果 PHP 再分配一个相同大小的块，我们就会崩溃。此外，当我们的假块被释放时，它可能会再次被分配，并包含我们不控制的数据。我们需要保护它不被重新分配；否则，它可能完全破坏我们的工作。  
  
为解决第一个问题，我们可以使用 HTTP 参数创建一个 0x500 块的网络，用空字节填充，并在中间留一个洞，希望 hashmap+bucket 块被分配在它们之间。如果我们指向这样的块，PHP 将读取一个空指针作为下一个空闲列表元素，并认为空闲列表已经耗尽，从而避免崩溃。  
  
为解决第二个问题，一旦我们分配了我们的任意块，我们还分配了大量 0x500 大小的块。当它们按顺序全部释放时，最后的块将在我们的块之前进入空闲列表，保护它不被分配。  
  
我们到了：使用我们的二进制错误，我们改变了会话的内容，并将 preferences 设置为任意字符串。然后我们向索引发出一个 HTTP 请求，在那里 $_SESSION['preferences'] 被反序列化。使用 guzzle/fw1 有效载荷，我们将文件写入 public_html/shell.php。  
##  演示   
  
这里有一个针对 PHP 8.3 下 Roundcube 1.6.6 的演示。  
  
  
  
利用代码可在 这里 获取。像往常一样，代码有详细的注释，并揭示了博客文章中未包含的部分利用细节。  
##  对生态系统的影响   
  
因此，直接调用 iconv() 是可利用的，并且影响深远。但这是否是 CVE-2024-2961 影响的唯一 PHP 函数？当然不是。  
  
首先，iconv() 有很多类似的函数，如 iconv_strrpos()、iconv_substr()... 这些函数可能也是易受攻击的（我尚未检查）。但还有一个更可怕、更出乎意料的漏洞源头。  
  
PHP 有一个非常受欢迎的扩展名为 mbstring。这个用 C 语言编写的扩展允许你在不同的字符集下操作字符串，并执行字符集转换。它是许多框架和 CMS 的 依赖项。  
  
但 mbstring 不是默认安装的。当它没有安装（你需要超级用户权限才能这样做），但你仍想使用依赖于它的库或框架时会发生什么？在这种情况下，你可以使用该库的 PHP 实现。名为 symfony/polyfill-mbstring 的项目 拥有完全相同的 API：两者可以互换使用。并且它非常受欢迎，安装次数超过 **8.23亿**。  
  
但 polyfill-mbstring 是如何完成其工作，即在不使用 mbstring 的情况下从一种字符集转换为另一种字符集的呢？好吧，它使用的是... iconv()。  
  
因此，你可能认为你正在使用 mbstring，因此不受漏洞影响，但实际上你使用的是 PHP 实现的 polyfill 版本，它使用的是 iconv()。  
  
随着 PHP 包管理器 composer 的出现，使用起来可能比预期的更容易混淆。如果你安装了两个项目，一个依赖于 ext-mbstring（原始的 C 扩展），另一个依赖于 polyfill-mbstring（PHP 等效项），无论是否安装了 mbstring 扩展，安装都会成功。  
  
当你运行我提供的 POC 时，这次使用 mb_convert_encoding() 代替 iconv()：  
```
- $output = iconv("UTF-8", "ISO-2022-CN-EXT", $input);
+ $output = mb_convert_encoding($input, "ISO-2022-CN-EXT", "UTF-8");
```  
  
你同样会得到一个崩溃。  
  
虽然我在这里停止了我的分析（寻找目标非常耗时），但我希望这并不是我们最后一次看到 CVE-2024-2691 和 PHP。  
##  结论   
  
在利用 PHP 过滤器 之后，我们现在通过直接调用 iconv() 利用 **CVE-2024-2961** 来破坏著名的 webmail，Roundcube。这让我们更深入地了解了 PHP 引擎的内部，并为使用明显的漏洞源头和不那么明显的漏洞源头的潜在新利用铺平了道路。  
  
现在我们已经通过 PHP 中的两种方式展示了影响，我们需要回答最后的问题：如果你拥有的文件读取原语是 blind（盲的），会发生什么？  
  
敬请期待第三部分！  
  
- END -  
  
  

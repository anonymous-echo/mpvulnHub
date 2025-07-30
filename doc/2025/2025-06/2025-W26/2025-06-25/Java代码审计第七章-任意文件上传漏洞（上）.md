> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4Njk1NDg5NQ==&mid=2247483910&idx=1&sn=213863db5a9b86c813db99bade0660e1

#  Java代码审计第七章-任意文件上传漏洞（上）  
原创 今木安全  今木安全   2025-06-25 11:52  
  
定义  
  
        任意文件上传漏洞是Web应用中的高危漏洞，攻击者通过绕过文件类型检测机制，将恶意脚本（如WebShell）上传至服务器。该漏洞的本质是  
**文件上传操作未规范校验文件类型**  
，导致检测功能被绕过。随着开发人员安全意识提升，此类漏洞有所减少但仍未绝迹。  
## 黑盒测试过程  
### 文件上传流程  
1. **前端提交**  
  
1. 用户选择文件并提交表单  
  
1. 浏览器生成POST Multipart报文发送至服务器  
  
1. **报文解析**  
  
1. 请求头部分  
  
HTTP协议版本、浏览器信息、请求方式、编码类型、请求地址  
  
1. 请求数据部分  
  
普通参数：参数名/参数值（含隐藏字段）  
  
文件数据：文件名、响应函数名、文件类型  
  
1. **服务器处理**  
  
1. 中间件接收并解析报文  
  
1. 后端代码处理请求（PHP特有：将内容写入临时文件）  
  
1. 最终文件写入目标存储路径  
  
### 上传漏洞的必要条件  
1. 存在上传功能点  
  
1. 可上传动态脚本文件（如.php/.jsp）  
  
1. 上传目录有执行权限  
  
1. 上传文件可执行  
  
1. 可访问上传的动态文件  
  
### 上传检测流程  
#### 前端提交检测  
- **JavaScript检测**  
  
- 触发事件：  

```
onchange
```

  
（内容改变时）、  

```
onsubmit
```

  
（表单提交时）  
  
- 绕过：删除检测函数或使用BurpSuite拦截修改请求  
  
- **Flash AS检测**  
  
- 提交前触发ActionScript检测  
  
- 绕过：直接修改POST报文内容  
  
- **App上传检测**  
  
  
**安卓绕过步骤**  
：  

```
adb connect 127.0.0.1:7555  # MuMu模拟器
am start -a android.settings.WIFI_SETTINGS
```

  
- 设置代理：Burp IP:8080  
  
- 安装Burp证书（.crt格式）  
  
- 信任证书（IOS需额外设置）  
  
- 对抗证书校验：Xposed框架+JustTrustMe  
  
#### 数据传输检测  
- WAF拦截：双后缀/00截断绕过  
  
- IPS拦截：慢速攻击/分块传输  
  
#### 后端处理检测  
- **扩展名检测绕过**  
  
- 大小写混合：  

```
.PhP
```

  
  
- 特殊后缀：  

```
.phtml
```

  
  
- **MIME Type检测绕过**  
  
- 伪造Content-Type：  

```
image/jpeg
```

  
  
- **文件格式检测**  
  
<table><thead><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border-top: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><th style="box-sizing: border-box;padding: 6px 13px;border-width: 1px 1px 0px;border-bottom-style: initial;border-bottom-color: initial;font-weight: bold;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;margin: 0px;"><span cid="n98" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 138.8px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">检测类型</span></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;border-width: 1px 1px 0px;border-bottom-style: initial;border-bottom-color: initial;font-weight: bold;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;margin: 0px;"><span cid="n99" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 576.4px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">绕过方法</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border-top: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n101" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 138.8px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">文件头检测</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n102" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 576.4px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">添加合法文件头（如</span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">GIF89a</span></code></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">）</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border-top: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n104" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 138.8px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">完整内容检测</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n105" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 576.4px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">图片与脚本合并：</span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;font-family: var(--monospace);text-align: left;vertical-align: initial;border: 1px solid rgb(231, 234, 237);background-color: rgb(243, 244, 244);border-radius: 3px;padding: 0px 2px;font-size: 0.9em;"><span leaf="">copy /b 1.jpg+shell.php final.jpg</span></code></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border-top: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n107" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 138.8px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">恶意内容检测</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n108" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 576.4px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">高度混淆WebShell（Weevely工具）</span></span></span></td></tr></tbody></table>  
#### 写入文件系统  
- 文件重命名绕过：利用解析漏洞  
  
- 杀毒软件对抗：内存马/无文件攻击  
  
#### 访问文件执行  
- **解析漏洞利用**  

```
# Nginx畸形解析
shell.jpg%20%00.php

# Apache配置错误
shell.php.jpg

# IIS分号解析
shell.asp;.jpg
```

  
- **服务器识别**  
  
- F12 → 网络 → Server头  
  
- 访问不存在页面查看错误信息  
  
## 绕过的高级技巧  
### 重绘图绕过  
1. 用目标图形库转换正常图片  
  
1. 识别转换前后未变化区域  
  
1. 将WebShell注入未变化区  
  
1. 二次转换验证完整性  
  
工具：Bypass-PHP-GD-Process-To-RCE  
  
### PHPinfo+本地包含组合利用  
  
**攻击流程**  
：  
1. 上传含大文件（拖延处理）  
  
1. 快速访问PHPinfo获取  

```
$_FILES
```

  
信息  
  
1. 利用本地包含执行临时文件   

```
GET /lfi.php?file=/tmp/phpXXXXX
```

  
### 在线压缩包利用  
- **目录穿越攻击**  

```
zip -r evil.zip ../../etc/crontab
```

  
- **符号链接攻击**  

```
ln -s /etc/passwd ./link
zip --symlinks -r evil.zip ./link
```

  
- **路径混淆攻击**  
  
  
-      构造含  

```
../
```

  
路径的压缩包结构  
  
> 下半部分将涵盖白盒审计、修复方案等深度内容。  
  
  
  

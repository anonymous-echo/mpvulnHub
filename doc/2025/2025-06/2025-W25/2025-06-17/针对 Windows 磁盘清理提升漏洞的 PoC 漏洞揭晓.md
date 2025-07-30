> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096336&idx=2&sn=c3e591e98ec6f4b4800be540858e1ccc

#  针对 Windows 磁盘清理提升漏洞的 PoC 漏洞揭晓  
 网安百色   2025-06-17 11:31  
  
Microsoft 在 2025 年 2 月的“星期二补丁日”期间，在其 Windows 磁盘清理实用程序 （cleanmgr.exe） 中解决了一个高严重性权限提升漏洞 （CVE-2025-21420）。  
  
该漏洞在 CVSS 量表上得分为 7.8，使攻击者能够通过 DLL 旁加载和目录遍历技术以 SYSTEM 权限执行恶意代码。  
## CVE-2025-21420 的技术分析  
  
该漏洞源于 cleanmgr.exe 未能验证 DLL 加载路径和缓解符号链接攻击。  
  
关键组件包括：  
  
**1. 开发机制**  
- DLL 旁加载：攻击者在可写系统目录中植入恶意库（例如 ）。bash此命令链利用路径拦截漏洞加载未签名的 DLL。
```
dokannp1.dll
```


```
cp .\dokan1.dll C:\Users\<username>\System32\System32\System32\dokannp1.dll cleanmgr /sageset:2
```

  
- SilentCleanup 任务劫持：Windows 任务计划程序的任务（以 SYSTEM 运行）在没有适当符号链接检查的情况下删除文件夹内容。攻击者通过以下方式滥用此内容：python 通过将文件夹删除重定向到 ，攻击者触发任意文件作。
```
SilentCleanup
```


```
# Exploit script structure os.makedirs(r'C:\$Windows.~WS') os.makedirs(r'C:\ESD\Windows') open(r'C:\ESD\Windows\dummy.txt', 'w').close()
```


```
C:\Config.Msi
```

  
**2. 漏洞链**  
  
<table><thead><tr style="box-sizing: border-box;"><th style="box-sizing: border-box;padding: 2px 8px;text-align: left;border: 1px solid;word-break: break-word;"><strong msttexthash="15358161" msthash="43" style="box-sizing: border-box;font-weight: bold;"><span leaf="">修补前行为</span></strong></th><th style="box-sizing: border-box;padding: 2px 8px;text-align: left;border: 1px solid;word-break: break-word;"><strong msttexthash="17048616" msthash="44" style="box-sizing: border-box;font-weight: bold;"><span leaf="">补丁后缓解</span></strong></th></tr></thead><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">符号链接没有重定向保护</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><code style="box-sizing: border-box;font-family: monospace, monospace;font-size: 1em;top: -1px;border: none;background-color: rgb(241, 241, 241);padding: 2px 6px;"><span leaf="">SetProcessMitigationPolicy</span></code><font mstmutation="1" msttexthash="5080309" msthash="46" style="box-sizing: border-box;"><span leaf="">启用</span></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">从用户路径加载不受信任的 DLL</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">DLL 的严格签名验证</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">通过联结删除特权文件</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">CWE-59 通过路径规范化解决</span></section></td></tr></tbody></table>## 概念验证 （PoC） 工作流程  
  
安全研究人员使用多阶段流程演示了漏洞利用：  
1. 文件夹设置：使用虚拟文件创建嵌套目录 （） 以触发 SilentCleanup 的删除例程。
```
C:\ESD\Windows
```

  
1. 交汇点重定向：用于转换为指向 的交汇点。
```
FolderContentsDeleteToFolderDelete
```


```
C:\ESD\Windows
```


```
C:\Config.Msi
```

  
1. 权限提升：执行后清理，通过受损的 Config.Msi 目录生成 SYSTEM shell。
```
osk.exe
```

  

```
# Sample exploit script (abridged)
import os, time
os.makedirs(r'C:\$Windows.~WS', exist_ok=True)
os.makedirs(r'C:\ESD\Windows', exist_ok=True)
with open(r'C:\ESD\Windows\dummy.txt', 'w') as f: f.write('trigger')
input(&#34;Press Enter after setting up junctions...&#34;)
os.startfile(r'C:\Windows\System32\cleanmgr.exe')

```

## 缓解和补丁部署  
  
Microsoft 的 2025 年 2 月更新通过以下方式解决了该漏洞：  
- 重定向防护：阻止通过 的符号链接攻击。
```
PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY
```

  
- **DLL 签名强制**  
：cleanmgr.exe 现在在加载库之前验证数字签名。  
  
**建议的作**  
：  
- 立即通过 Windows Update/WSUS 应用 KB5025321。  
  
- 审核系统目录中是否存在未经授权的 DLL（例如 ）。
```
dokannp1.dll
```

  
- 监控非标准上下文中的执行情况。
```
cleanmgr.exe
```

  
此补丁是修复 67 个漏洞的更广泛更新的一部分，包括 Windows 辅助功能驱动程序 （CVE-2025-21418） 和 NTLM （CVE-2025-21377） 中被积极利用的零日漏洞。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  

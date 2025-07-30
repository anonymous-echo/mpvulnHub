#  Rsync Rsync 未授权 缓冲区溢出漏洞   
 上汽集团网络安全应急响应中心   2025-02-15 15:56  
  
**漏洞情报**  
  
  
  
  
  
**Rsync Rsync 未授权 缓冲区溢出漏洞**  
  
  
**【 漏洞编号 】**  
  
CVE-2024-12084  
  
  
**【 情报等级 】**  
  
**高危**  
  
  
**【 漏洞描述 】**  
  
360漏洞云监测到 Rsync 文件同步工具被披露存在多达六个安全漏洞，其中包含一个由于校验和长度处理不当导致堆缓冲区溢出，漏洞可能导致攻击者在客户端执行任意代码，读取敏感数据等。Rsync 官方已发布新版本修复这些漏洞，建议受影响用户及时采取防护措施。  
  
  
**【 影响产品 】**  
  
<table><tbody><tr><td colspan="1" rowspan="1" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="99.0000%"><section style="text-align: center;font-size: 14px;"><p>rsync,rsync 文件同步工具,rsync file synchronization tool,Rsync 文件同步工具,Rsync,rsync同步工具,Rsync File Synchronization Tool,Rsync同步工具&gt;=3.2.7&amp;&amp;&lt;3.4.0</p></section></td></tr></tbody></table>  
  
**【 解决方案与修复建议 】**  
  
针对此漏洞，官方已经发布了漏洞修复版本，请立即更新到**安全版本：**  
  
Rsync Rsync >= 3.4.0  
  
**下载链接：**  
  
 https://github.com/RsyncProject/rsync/releases   
  
安装前，请确保备份所有关键数据，并按照官方指南进行操作。安装后，进行全面测试以验证漏洞已被彻底修复，并确保系统其他功能正常运行。  
  

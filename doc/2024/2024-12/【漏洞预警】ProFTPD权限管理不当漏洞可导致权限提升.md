#  【漏洞预警】ProFTPD权限管理不当漏洞可导致权限提升   
cexlife  飓风网络安全   2024-12-04 08:48  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00Yr33CKOhxFGTYFRy8u7F8w7WBRnyNcKSUfBWxGCB3ZCwEYb2I2rozJ56KqAKCEVU9DicJH8bEKpw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
  
ProFTPD存在一个权限管理不当漏洞,该漏洞是由于没有补充组的用户将错误地从父进程继承补充组,父进程在启动时的补充组成员身份（特别是补充GID 0）将被保留,并且即使存在User和Group指令,子进程也会继承这些成员身份,没有自己的补充组的用户将保留此继承的补充GID,并授予他们访问根组拥有的文件/目录的权限。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00Yr33CKOhxFGTYFRy8u7F8WlaSKpmrrIjwEYszE6N3OaD7NDcuRx57VScIicXoW8acP362alAWpaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00Yr33CKOhxFGTYFRy8u7F8zATrSpOqCywCziaLTzZUVgUDgEo9kYa44grvOd1XxO69eEzuE2JA8FQ/640?wx_fmt=png&from=appmsg "")  
  
**修复建议:**  
  
**正式防护方案:**截止目前厂商已对漏洞进行了修复,但还未推出正式修复版本。  
  
请做好资产自查以及预防工作,并在厂商发布更新版本后及时更新,以免遭受黑客攻击。  
  

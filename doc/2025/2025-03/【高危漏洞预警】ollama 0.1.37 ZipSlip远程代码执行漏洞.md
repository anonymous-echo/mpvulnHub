#  【高危漏洞预警】ollama 0.1.37 ZipSlip远程代码执行漏洞   
cexlife  飓风网络安全   2025-03-20 22:50  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01GaIaxz1dhickfN6Rl9oZHPmbkKP42O1LvDgOjr5NGHribZWuDJ2XUg3z1bdCY6sacCgxZsjbsAzAw/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
оllаmа/оllаmа版本0.137中存在一个漏洞,允许远程代码执行（RCE）,这是由于在处理ziр文件时输入验证不当造成的,这个漏洞被称为ZiрSliр,发生在ѕеrvеr/mоdеl.ɡо中的раrѕеFrоmZiрFilе函数代码没有检查ziр归档内文件名中的目录遍历序列（../）,允许攻击者将任意文件写入文件系统,这可以被利用来创建文件,例如/еtс/ld.ѕо.рrеlоаd 和一个恶意共享库,从而导致RCE。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01GaIaxz1dhickfN6Rl9oZHPQ388vvPc8JN6N9iay5cMXAaTibdrbuRLT43U4XcaU0oMet4B42tdkToA/640?wx_fmt=png&from=appmsg "")  
```
curl -X POST http://localhost:11434/api/create -H "Content-Type: application/json" -d'{"name":"maria","modelfile":"FROM /tmp/poc.zip\nSYSTEM DUMMY"}
```  
  
```
curl -X POST http://localhost:11434/api/chat -H "Content-Type: application/json" -d'{"model":"moondream","messages":[]}'
```  
  
攻击场景:  
  
攻击者可能通过上传恶意ziр文件,利用目录遍历序列（../）写入任意文件到文件系统,导致RCE。  
  
影响产品:  
  
ollama/ollama<0.4.0   
  
修复建议:  
  
安装补丁:请关注Ollаmа的官方更新,及时安装相关补丁以修复该漏洞  
  
其他修复方法:在处理ziр文件时,确保使用安全的路径限制,避免提取到父目录。  
  
建议用户在未修复漏洞前,避免使用ziр文件提取功能,或对ｚiр文件进行严格的路径检查。  
  
  
  

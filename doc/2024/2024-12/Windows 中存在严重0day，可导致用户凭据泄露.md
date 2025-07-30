#  Windows 中存在严重0day，可导致用户凭据泄露   
 独眼情报   2024-12-07 06:15  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnTIwIxanMuJtGh68KNqzON1q15xhtdz6kmtQuSMDYWA3MXTd9ZtlCG1vp64MGWnWBupb4NbpPU5SQ/640?wx_fmt=png&from=appmsg "")  
  
我们的研究人员发现了一个影响从Windows 7和Server 2008 R2到最新的Windows 11 v24H2和Server 2022的所有Windows工作站和服务器版本的安全漏洞。攻击者只需让用户在Windows资源管理器中查看恶意文件，就可以获取用户的NTLM凭据 - 例如，通过打开包含此类文件的共享文件夹或U盘，或查看先前从攻击者网页自动下载到"下载"文件夹的文件。  
  
我们已将此问题报告给微软，并按照惯例发布了微补丁，在微软提供官方修复之前，这些补丁将免费提供。  
  
为了最大限度地减少恶意利用的风险，我们将对这一漏洞的具体细节进行保密，直到微软的修复补丁可用。  
  
这是我们最近发现并向微软报告的第三个0day漏洞，继Windows主题文件问题（仍是一个没有官方补丁的0day）和Server 2012的网页标记问题（同样也是一个没有官方补丁的0day）之后。  
  
此外，"EventLogCrasher"漏洞（允许攻击者禁用所有域计算机上的Windows事件日志，由安全研究员Florian于今年1月报告给微软）仍在等待官方补丁，因此我们的补丁是目前唯一可用的补丁。  
  
目前还有三个微软已决定不修复的、与NTLM相关的公开已知漏洞，我们已提供了0patch补丁：PetitPotam、PrinterBug/SpoolSample和DFSCoerce。这些漏洞存在于所有最新的完全更新的Windows版本中，如果您的组织出于某些原因仍在使用NTLM，则可能会受到影响。  
  
  

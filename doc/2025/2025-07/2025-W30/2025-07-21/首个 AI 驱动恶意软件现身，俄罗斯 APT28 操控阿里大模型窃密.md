> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0MDYwMjE3OQ==&mid=2247486999&idx=1&sn=fbdc445daac2baccc94e94075ecb9672

#  首个 AI 驱动恶意软件现身，俄罗斯 APT28 操控阿里大模型窃密  
 安全威胁纵横   2025-07-21 08:49  
  
乌克兰计算机应急响应小组发现首款利用   
LLM 生成攻击指令的恶意软件  
 LameHug，推测其与俄罗斯 APT28组织存在关联。该恶意软件通过伪装政府文件的钓鱼邮件传播，窃取系统信息及文档，可动态调整攻击链。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok8FsaZqg4zxf4tXPIwEDFgvqxaoGr4yyLaQgWxBZ31ecYYYibxSd3AoruQA7TRyJV35hlxkWTUAp1avT3pe1XA/640?wx_fmt=jpeg "")  
  
  
  
乌克兰计算机应急响应小组（CERT-UA）近日发布警报，监测到一款名为   
LameHug  
 的新型恶意软件。  
该软件借助大语言模型（LLM），在受感染的 Windows 系统中生成并执行攻击指令。  
乌克兰专家推测该恶意软件与俄罗斯关联的黑客组织   
APT28  
 有关。  
  
CERT-UA 在警报中提到，LameHug 的突出特点是使用 LLM，依据文本描述生成可执行命令。该机构表示，“有中等把握判定这一活动与 UAC-0001（即 APT28）相关。”  
  
2025年7月10日，CERT-UA发现一起针对政府部门的钓鱼攻击活动，攻击者通过伪装成政府文件的ZIP压缩包进行传播。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok8FsaZqg4xZRdFODW99NlEFTLqH6sMDGnPXcniaslHbQCRbrwg0lkTiaPHIb2w2CedFkOW9auPvvvfFKD83jviaA/640?wx_fmt=webp&from=appmsg "")  
  
该压缩包内含伪装成.pif文件的LAMEHUG恶意软件，该软件使用Python编写并通过PyInstaller打包。研究人员发现存在**两种不同数据窃取方式**  
的变体。攻击者使用了被入侵的电子邮箱账户，并将基础设施托管在合法但已被攻陷的平台上。  
  
LAMEHUG通过huggingface[.]co服务API调用**Qwen 2.5-Coder-32B-Instruct**  
模型，基于静态输入的文本描述生成攻击指令。Qwen 2.5-Coder-32B-Instruct是由阿里巴巴Qwen团队开发的**开源大语言模型**  
，专门针对编程任务进行了优化。  
  
该恶意软件会收集系统信息，并在常见文件夹中搜索Office、PDF和TXT文档。收集的数据先存储在本地，然后通过SFTP或HTTP POST方式外传。  
警报中详细说明：“该软件会收集计算机基本信息（硬件配置、进程、服务、网络连接）并存储在‘%PROGRAMDATA%\info\info.txt’文件中，同时递归搜索‘文档’、‘下载’和‘桌面’目录中的Microsoft Office文档（包括TXT和PDF文件），将其复制到‘%PROGRAMDATA%\info’文件夹。不同版本的程序会使用SFTP或HTTP POST请求外传获取的信息和文件。”  
  
LameHug是**已知首款利用LLM生成攻击指令的恶意软件**  
，  
使威胁行为者能够根据实际需求动态调整攻击链。该报告还包含了相关网络威胁指标。  
  
  
转载请注明出处@安全威胁纵横，封面来源于网络；  
  
消息来源：https://securityaffairs.com/180092/apt/lamehug-first-ai-powered-malware-linked-to-russias-apt28.html  
  
  
  
      
更多网络安全视频，请关注视频号“知道创宇404实验室”  
  
  
  

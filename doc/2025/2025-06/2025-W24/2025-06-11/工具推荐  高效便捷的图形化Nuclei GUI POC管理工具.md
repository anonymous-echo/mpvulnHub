#  工具推荐 | 高效便捷的图形化Nuclei GUI POC管理工具  
perlh  星落安全团队   2025-06-10 16:01  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/spc4mP9cfo75FXwfFhKxbGU93Z4H0tgt4O9libYH9mKfZdHgvke0CeibvXDtNcdaqamRk3dEEcRQiaWbGiacZ2waVw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/WN0ZdfFXY80dA2Z4y8cq7zy2dicHmWOIib5sIn8xAxRIzJibo2fwVZ3aicVBM8RnAqRPH5Libr4f02Zs5YnMLBcREnA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
现在只对常读和星标的公众号才展示大图推送，建议大家能把  
**星落安全团队**  
“  
**设为星标**  
”，  
否则可能就看不到了啦  
！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkXnsUODwVWmlxAHuHu4dBuwIlu707ZfPdbNTYyibYzQHA0xn0p2hTbQAiba04SOnDiadxVExZ53nfog/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**背景介绍**  
  
Wavely 是一款专为 Nuclei POC 管理设计的图形化工具，提供安装包下载和常见问题解答，助您高效管理。  
  
主要功能  
```
实现对nuclei模板的添加、删除、查询以及修改操作。
兼容MacOS、Windows和Linux操作系统。
实现选择多个POC、多个扫描任务以及多目标的并行扫描功能。
支持自定义DNSLOG服务器，自定义扫描速率，同时支持http代理（http、https、socks5）。
支持查看 POC 匹配到的请求包与响应包。
支持 POC 编辑器的主题切换。
支持nuclei模板一键导入(选择POC文件夹即可导入，可实现nuclei模版去重导入，基于template id)。
支持国际化，已广泛覆盖大部分区域。
支持手动停止扫描任务，便于灵活控制扫描进程。
支持配置持久化，确保用户配置信息持久化保存。
支持 API 扫描，包括带目录扫描（如：http://target.com/api）。
支持图形化生成简单poc，降低 poc 生成门槛。
```  
  
安装指南  
```
1.1 MacOS 安装步骤
  1. 下载对应压缩包并解压，解压文件夹内包含Wavely.app和Applications文件夹。
  2. 将Wavely.app拖移至Applications文件夹中。
  3. 在终端执行：sudo xattr -d com.apple.quarantine /Applications/Wavely.app 。
1.2 Windows 安装步骤
  1. 下载对应压缩包并解压，执行Wavely-xxx-installer.exe安装程序
1.3 DNSLOG 设置说明
  1. 系统默认采用 Nuclei 默认 DNSLOG 服务。
  2. 如需搭建个人 Nuclei DNSLOG 服务器，可参考：搭建指南。
```  
  
使用教程  
  
2.1 注册  
  
依次点击设置 -> 注册，在注册页面按提示获取设备 ID，完成证书申请后上传证书，即可注册成功。  
  
2.2 导入方法  
  
在 App 中导入 POC（具备去重功能）  
- 点击从文件夹中导入POC  
按钮，选择存放nuclei poc  
文件的目录。  
  
- 系统将自动识别并导入所选目录内的所有 POC 文件，导入过程实时显示进度与文件数量，若存在基于 template id 的重复 POC，系统将自动去重，完成后弹窗告知导入结果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0fllln5icf8pDd2horQvfT3YzKlkMI0vv9P0YibncV9dYZfCXFnREnoKEehHewSVgTx0oXECYHOCIILdOKw/640?wx_fmt=png&from=appmsg "")  
  
2.3 创建扫描任务流程  
  
任务发起操作  
- 选择指定POC后，点击顶部扫描按钮即可启动扫描。  
  
- 若未选择 POC，系统将对搜索结果执行全扫描；  
  
- 若已选择 POC，则仅针对所选 POC 进行扫描。  
  
- 此外，点击扫描按钮前，可在任务设置区域自定义扫描速率等参数。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0fllln5icf8pDd2horQvfT3YzKlklAPVUzOsdAdT7t2driavxztdNlwrQLPcVz9sJqaL2hicMnbz5XQkmFcQ/640?wx_fmt=png&from=appmsg "")  
  
扫描结果查看  
- 扫描完成后，点击POC ID  
可直接跳转到` POC 编辑界面，方便进一步分析与调整。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0fllln5icf8pDd2horQvfT3YzKlkXjxny8ibnERzu1ORQZpcPSPC3saNPyteElib2ua0X9NNgdobsicOFnxEg/640?wx_fmt=png&from=appmsg "")  
  
2.4 Nuclei 模版编辑 / 添加操作  
  
编辑poc  
#####   
  
##### 查看请求 / 响应包（需检测匹配成功）  
#####   
  
##### 图形化生成 POC  
- **表单形式请求包**  
：通过直观的表单填写方式。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0fllln5icf8pDd2horQvfT3YzKlkwb6nUXZibBCPuWXxFiazYZ1C3eeat23iaXmhqBLNm35AaMW6QY0oBPxNA/640?wx_fmt=png&from=appmsg "")  
- **raw 格式请求包**  
：支持以 raw 格式编辑和生成请求包。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0fllln5icf8pDd2horQvfT3YzKlkf3icmMsRFa7dy5GbuoRRwIgQVPbtwKuaJsU6VYuU1g1icreAOVIP3pRA/640?wx_fmt=png&from=appmsg "")  
  
- **测试功能**  
：生成 POC 后，可点击测试按钮快速验证其有效性。  
  
![main](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0fllln5icf8pDd2horQvfT3YzKlkjBgdv7oUNhR2ng280VeR7LU8PKibs4yyyg6HtHgwguibjqE5icxib61qTQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**相关地址**  
  
**关注微信公众号后台回复“入群”，即可进入星落安全交流群！**  
  
**关注微信公众号后台回复“20250611”，即可获取项目下载地址！**  
  
****  
  
  
**圈子介绍**  
  
博主介绍  
：  
  
  
目前工作在某安全公司攻防实验室，一线攻击队选手。自2022-2024年总计参加过30+次省/市级攻防演练，擅长工具开发、免杀、代码审计、信息收集、内网渗透等安全技术。  
  
  
目前已经更新的免杀内容：  
- 部分免杀项目源代码  
  
- 一键击溃360+核晶  
  
- 一键击溃windows defender  
  
- 一键击溃火绒进程  
  
-    
CobaltStrike4.9.1二开   
  
-    
CobaltStrike免杀加载器  
  
- 数据库直连工具免杀版  
  
- aspx文件自动上线cobaltbrike  
  
- jsp文件  
自动上线cobaltbrike  
  
- 哥斯拉免杀工具   
XlByPassGodzilla  
  
- 冰蝎免杀工具 XlByPassBehinder  
  
- 冰蝎星落专版 xlbehinder  
  
- 正向代理工具 xleoreg  
  
- 反向代理工具xlfrc  
  
- 内网扫描工具 xlscan  
  
- CS免杀加载器 xlbpcs  
  
- Todesk/向日葵密码读取工具  
  
- 导出lsass内存工具 xlrls  
  
- 绕过WAF免杀工具 ByPassWAF  
  
- 等等...  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
目前星球已满500人，价格由208元  
调整为  
218元(  
交个朋友啦  
)，600名以后涨价至268元！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0flllkN0Z3pNGXR2znpzfM0z8rR6nUPo8lbItfge0zwVQpsQpBNMby3aslX4WWKgTgyvaPvYc3wf2AMBQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/MuoJjD4x9x3siaaGcOb598S56dSGAkNBwpF7IKjfj1vFmfagbF6iaiceKY4RGibdwBzJyeLS59NlowRF39EPwSCbeQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
     
往期推荐  
     
  
  
1.   
[学不会全额退款 | 星落免杀第一期，助你打造专属免杀武器库](https://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247494072&idx=1&sn=e46a6d176a8fad2aa4b4c055de3607da&scene=21#wechat_redirect)  
  
  
  
2.   
[【干货】你不得不学习的内网渗透手法](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489483&idx=1&sn=0cbeb449e56db1ae48abfb924ffd0b43&chksm=c0e2bc74f79535622f39166c8ed17d5fe5a2bbc3f622d20491033b6aa61d26d789e59bab5b79&scene=21#wechat_redirect)  
  
  
  
3.   
[【免杀】CobaltStrike4.9.1二开 | 自破解 免杀 修复BUG](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247488486&idx=1&sn=683083d38a58de4a95750673d9cb725d&chksm=c0e2b859f795314f3b7bc980a5d4114508ee2c286bc683cdfd25eefa4fb59f26adfe5483690b&scene=21#wechat_redirect)  
[！](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247486966&idx=1&sn=3f144d5936d5cdc11178004549384ace&chksm=c0e2a649f7952f5f7557dde6e9cca53ecee7b5e2f7ff23395250e8fe47acb102902d9727185d&scene=21#wechat_redirect)  
  
  
  
4.   
[【免杀】原来SQL注入也可以绕过杀软执行shellcode上CoblatStrike](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489950&idx=1&sn=a54e05e31a2970950ad47800606c80ff&chksm=c0e2b221f7953b37b5d7b1a8e259a440c1ee7127d535b2c24a5c6c2f2e773ac2a4df43a55696&scene=21#wechat_redirect)  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
【  
声明  
】本文所涉及的技术、思路和工具仅用于安全测试和防御研究，切勿将其用于非法入侵或攻击他人系统以及盈利等目的，一切后果由操作者自行承担！！！  
  

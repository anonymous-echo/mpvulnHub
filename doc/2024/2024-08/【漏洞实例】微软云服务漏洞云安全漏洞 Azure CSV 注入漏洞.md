#  【漏洞实例】微软云服务漏洞云安全漏洞 Azure CSV 注入漏洞   
 EnhancerSec   2024-08-07 16:58  
  
前言  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKVibeL72YzLH79T4AjdRH13DzX1avCNqbSeU0Xb1nicv59X6oLLh7kDFEvYM8xzc2FNaTyUeuPNejw/640?wx_fmt=png "")  
  
声明：本文仅供学习参考使用，如若造成其他不良影响，均与本公众号无关！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKKVhibmmQYk6h7BJniaX1Pkr9ic8Xw9Fu6W3ObsRKIxiaOQ698AxA5OUUiaHO2DZlBAlpjibzKAuNMEYmw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
本文已于7月30日上传至知识星球，加入星球可享受的福利请看文末  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtr30wnPhH67UE1iaJPWI1V7YJ0aLhUVXATnFiacR459s5qJ7X6hpFaQ3og/640?wx_fmt=png&from=appmsg "")  
### 漏洞摘要：  
  
    在测试时，发现Azure用户可以尝试(但失败)创建具有恶意名称的 Azure“资源组”。在将此名称设置为Microsoft Excel公式时，系统将拒绝语法 (由于某些黑名单字符)，但仍然在Azure“活动日志”中记录原始恶意字符串。 当受害者用户下载(现已感染)CSV日志并在Excel中打开它们时，攻击者的远程代码被执行，损害了用户(可能还有他们的Azure帐户)。能够保存至活动日志还意味着低特权用户可以使用此攻击来针对管理用户。  
  
**漏洞详情：**  
  
所需  
权  
限  
:创建资源组  
  
    利用此漏洞所需的权限是创建“资源组”，我导航到“资源组” 页面，然后单击左上角的“+添加”。  
  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtrm2XVmNwvBdaAEh9jhPFDjAfjpa6T8tX8TKcKtFCrxu4zCHnic1YZ9pg/640?wx_fmt=png&from=appmsg "")  
  
    将出现另一个“资源组”面板，创建新资源组的名称并填写其详细信息。由于客户端验证，如果输入框中有一个包含黑名单字符，则无法创建成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtrvCTmt6SmbB9QPdMubwkcnx2kJVNiaez9cQlCgMeO2EjpyQxQRyz6YIQ/640?wx_fmt=png&from=appmsg "")  
  
    我使用Burp Suite中包含的拦截代理来拦截正在提出的请求，我可以编辑名称参数中发送的值，从而绕过了已经到位的客户端验证。需要更改的请求 是“https://management.azure.com/api/invoke”的PUT请求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtrbJUyZpST3nZicTnrBtRauTHKwouRsWgCLqiaHHImrjHwY0GJ0mQKOlicg/640?wx_fmt=png&from=appmsg "")  
  
    有效载荷必须插入到上面截图中显示的两个高亮的位置。无需“x-ms-path-query”参数的值进行更改。对于正文中发送的JSON的“名称”属性中的位置，如果有效负载包含双引号，则必须将其转义以正确匹配JSON所需的格式，两个位置都必须包含相同的有效负载。  
  
    发送请求后显示400，HTTP 400响应将表明您向服务器提出了错误的请求——这是意料之中的。 不需要创建资源组，只需记录了失败的尝试日志。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtrCRRzrL616oANLknibwm8Ao0HKkqFmTUbbrN74CEXicwn8UnTYc0ZVuicw/640?wx_fmt=png&from=appmsg "")  
  
    现在，该csv公式已被注入到“活动日志”。  
  
查看  
Azure活动日志  
  
    如Azure文档中所述，“Azure活动日志是一个订阅日志，可以深入了解 Azure中发生的订阅级别事件”。这些日志(以前称为“审计日志”或“操作日志”)包括帐户订阅中资源的任何写入操作的所有详细信息，如PUT、POST 或DELETE。每个日志都包含有关该特定操作的“什么、谁和何时”信息。具 有读取权限的用户可以将这些日志的列表导出csv文件以供进一步检查。  
  
    当用户访问Azure活动日志时，可以看到订阅中最近发生的操作列表。 简而言之，没有办法在日志中的某个地方识别恶意事件。然而，仔细观察， 将识别攻击为“错误”类型，并将名称为“更新资源组”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtrDzF37zibxYvkmKd39DYiaITXliaiaYcGP64ZxXnd2ZsplvbSqWTNXmJEibA/640?wx_fmt=png&from=appmsg "")  
  
    当单击这个日志时，可以看到以下信息，以及一些JSON格式的更具    体的详细信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtrvAbdRWBchic8FsSic4F6KCMU8SK7mqhicPRhAdvLLvhJ2c7otH3BKyWog/640?wx_fmt=png&from=appmsg "")  
  
下载  
/  
打开CSV  
  
    在Azure中下载日志很简单—在任何查询结果上方都有一个在csv中下 载的按钮。  
  
    在Excel中打开受感染的日志后，用户将显示两个单独的弹出框。虽然这些 是警告，但它们特别指示用户，如果他们不信任文件的来源，就不要打开。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtribnIqSGIr6nNoEE7ArPaTbVXeNjHunCzM7ONYAwu4JQtDvAxsMLKvwQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtrOoiapiaBWn85dTbeWZPsxRqjte5Jbicqzf72eWpb3LuUXUWfbqlsUwbvQ/640?wx_fmt=png&from=appmsg "")  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIFrhmJI1sUQlpVotnburtraum7lHevXPfiaNQQ9vmx9lRp9ryDh4vowpRCoMYWT6ju7AJg6jbxIaA/640?wx_fmt=png&from=appmsg "")  
  
文末右下角点击“  
在看”不迷路  
  
备注：知识星球每周更新2-3篇漏洞实例和红队工具（或RCE的漏洞），公众号只会偶尔更新知识星球部分内容  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
  
  
关注不迷路  
‍  
‍  
‍  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnLC22Wa3B8Lb3AkPOhcfqzORXBdEyiajPX2GJd1patuUzlhgOZia7X11licPvQvJviakdHTDt0NWxjicOw/640?wx_fmt=png&from=appmsg "")  
  
关注本微信公众号，点击下方微信群，扫码加好友，备注“微信群”，拉你进交流群，后面会在群里抽奖！群里会不定期给大家分享国内外高危严重小技巧  
‍  
‍  
‍  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESIntAQKdnibCOF6NXl5ziaqupHVgRP1jh7Opk6N3XIbskCL0LykGQlj0g/640?wx_fmt=png&from=appmsg "")  
  
  
  
**【网安智汇】知识星球介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ES6UAWJficFjEVKMkcXkeK80uK2sI2PhFfrrEEm9OBX7HJlrltgHRzgGA/640?wx_fmt=png&from=appmsg "")  
  
创建知识星球的初衷就是为了分享学习资料，同时也是为了清理电脑和网盘的缓存，知识星球目前已经分享了安全运营、SRC漏洞实例、电子书籍、攻防红蓝紫方资料及其他方向的内容，均已设置了专栏方便大家阅读，可以自行扫码加入。目前星球福利如下：  
‍  
‍  
‍  
‍  
```
1、Fofa高级会员免费使用
2、Quake会员免费使用
3、每周更新2-3篇漏洞实例
4、每周更新2-3个红队工具、漏洞工具
5、在线书籍、议题、新颖学习资料
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DLnxHnM3icnK1Qzz53WFlGboRApmUJpFiaUMHQ84dwv1sO0aUGicOMkqnjicvZp6N5bHZTWCymKPfJABmqk4VicRwkg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnK1Qzz53WFlGboRApmUJpFiarYrFrqGZWhTcOqicR8kqQC0OIv5R4icjHic4qGfH3Uk64SuOtarTysDSQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnK1Qzz53WFlGboRApmUJpFia8hbfOZvK9aMtEK8U6IFoVGbDFwlQ9WhmoicNyw5x8G6N59XHZknCicDw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnIAea2vXMtA4mAcX7DgqL0ich04784P1BLG26LqgcO78icY9nxAnrbWMyyhicfTfJT8ZEHdEPOxsO60A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESL83GiaU5EqAELtNpV9jyNUZhFqSZa4D5FVIaicB5gqCvP8n64ouichf0A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESeLvxiaKoYfqtsQuA3Bn9aoG1sib0GDNEHFH9WV5KKcAgQyDq0mziaag0Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESFI0TmRaaadTWH2VicoVia0ElxFhXYf1cY0fqgulllkdN9nRMXTGfH3WA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESBKJpU6HJR4ibLticIOG5IJaHJfW9aaZ0eIeZyXUbdWeNzYWdhACmZoHQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ES3gVSxlibHpTShv4ZN3W5WwzKticdwCtSqHTTzn1eGbt2SDemEGXYuVibA/640?wx_fmt=png&from=appmsg "")  
  
或者在微信公众号后台点击微信群，添加微信，备注来意（微信群），加入交流群参与后续的抽奖活动免费进入知识星球。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnLC22Wa3B8Lb3AkPOhcfqzOgPVvZS2m3yFq0p9LSPmyFxlyEYVJQibItTiaWNiakooek4s6dV5tZCDEQ/640?wx_fmt=png&from=appmsg "")  
  
  
**END**  
  
  
  

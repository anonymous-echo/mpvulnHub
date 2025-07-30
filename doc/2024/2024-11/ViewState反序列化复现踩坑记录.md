#  ViewState反序列化复现踩坑记录   
 阿乐你好   2024-11-18 01:34  
  
<table><tbody><tr><td width="557" valign="top" height="62" style="word-break: break-all;"><section style="margin-bottom: 15px;"><span style="font-size: 14px;"><span style="color: rgb(217, 33, 66);"><strong>声明：</strong></span>该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。</span></section><section><span style="font-size: 14px;">请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。</span></section></td></tr></tbody></table>  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
潇湘信安  
“  
设为星标  
”，  
否则可能看不到了  
！  
  
  
某师傅遇到的一个ViewState反序列化提权遇到些问题，看到他在群里和其他几个师傅在交流就去问了下啥情况，然后我  
@尧  
哥就给我分享了他的这篇笔记，哈哈，感谢分享！！！  
  
图片是我后边本地测试后补的，也记录了遇到的一些坑，大家可作为了解学习之用，仅供参考！！！  
  
  
**0x00 背景**  
  
在ASP.NET应用程序中，ViewState  
是一种用于存储页面状态的机制，常被用于存储用户表单数据、控件状态等信息。然而，ViewState  
中的信息经过序列化后保存在页面上，如果开发者没有对其进行签名或加密，那么攻击者可以通过修改ViewState  
数据来执行恶意代码，甚至提权。  
  
  
**0x01 环境搭建**  
  
我们先搭建一个简单的ViewState  
反序列化漏洞测试环境，在测试机上安装好IIS并选择.NET  
相关选项使其支持.NET脚本，源码用的网上师傅公开的，copy到web目录下即可。  
  
  
**hello.aspx**  
```
<%@ Page Language="C#" AutoEventWireup="true" CodeFile="hello.aspx.cs" Inherits="hello" %>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
 <head runat="server">
  <title></title>
 </head>
 <body>
   <form id="form1" runat="server">
    <asp:TextBox id="TextArea1" TextMode="multiline" Columns="50" Rows="5" runat="server" />
    <asp:Button ID="Button1" runat="server" OnClick="Button1_Click"
    Text="GO" class="btn"/>
    <br />
    <asp:Label ID="Label1" runat="server"></asp:Label>
   </form>
 </body>
</html>
```  
  
  
**hello.aspx.cs**  
```
using System;
using System.Collections.Generic;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Text.RegularExpressions;
using System.Text;
using System.IO;

public partial class hello : System.Web.UI.Page
{
  protected void Page_Load(object sender, EventArgs e)
{
  }

 protected void Button1_Click(object sender, EventArgs e)
{
   Label1.Text = TextArea1.Text.ToString();
  }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEbtHiaicJvOMne1duibJnbWmYV62lIwR7J7n1cZ0WggfHtpsUZXH8pNs4g/640?wx_fmt=png&from=appmsg "")  
  
  
然后再禁用下ViewStateMac  
，可通过以下3种方式来禁用，不同.NET  
版本的禁用方式不太一样，这里我只是简单记录下，方便复现测试就行。  
```
web.config文件中的enableViewStateMac（.NET≤4.5）：
<pages enableViewStateMac="false" />

web.config文件添加一个appSettings配置项（NET≥.4.5.2）:
<appSettings><add key="aspnet:AllowInsecureDeserialization" value="true" /></appSettings>

注册表禁用ViewStateMac（0:禁用，1:启用）（.NET≥.4.5.2）:
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v AspNetEnforceViewStateMac /t REG_DWORD /d 0 /f

需在数据包中删除VIEWSTATEENCRYPTED场景：
enableViewStateMac=false，viewStateEncryptionMode=Always
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEOWKAEqMCkS5fIlRPuCPEecpsspBicXjw02GZUnDicSAH8KIKZUN62cvQ/640?wx_fmt=png&from=appmsg "")  
  
  
**0x02 攻击准备**  
  
**获取目标网站的ViewState信息：**  
  
访问目标网站的一个页面，打开浏览器的开发者工具，查找HTML源代码中的ViewState  
字段。通常该字段以<input type="hidden" name="__VIEWSTATE" value="...">  
的形式存在。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEVfhCGduFreXyzzx1jGBNm1zxarpibSNg8Phb8wyuSlsYTUG7qmKywPQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**ViewState插件安装：**  
  
viewstate-editor是一个可查看和编辑ViewState  
的BurpSuite插件，低版本1.7默认自带该插件，新版2021需在Extender  
->BApp Store  
安装（**注：**安装不了时需上墙安装）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEdIiaEb05Dv92OVejMNRI2I9d9j3wPCx8eEyF55QWKLEBw4Fk2cXJOlg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**ViewState插件使用：**  
  
BurpSuite设置好监听并开启抓包，访问测试地址   
http://192.168.1.110/hello.aspx   
提交数据包，然后点击这插件的ViewState  
，如果是MAC is not enabled  
说明ViewStateMac  
已禁用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEcU3rhE8icJAqmO3ib25W4ODlzcO4w7sDm6Krlq2XGU9QAaGqkCHjdLiaA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**解码ViewState内容：**  
  
ViewState默认是Base64  
编码的字符串，使用常见的工具（如：BurpSuite的Decoder或Python脚本）将其解码，得到序列化后的对象内容，如配置启用加密后则需要Key才能解。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKE2SDgqbqEHdjRYts9YiaDOBGxHE4HMibLmdlDx0icz6WJm4Al7Eer5EpBw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x03 攻击过程**  
  
**第一步：查找不安全的ViewState配置**  
  
检查ASP.NET应用的web.config  
配置文件，寻找与ViewState  
相关的设置，尤其是ViewStateEncryptionMode  
属性是否为Auto  
或Never  
。  
  
此外，如果应用程序未配置MAC签名EnableViewStateMac="false"  
，那么ViewState是不安全的，可以被攻击者篡改。  
> Always：所有的ViewState数据都会被加密  
  
Never：ViewState数据永远不会加密  
  
Auto：默认值，只有部署在IIS7或更高版本上且应用程序没有配置任何加密密钥时，ViewState才会加密  
  
  
  
**web.config**  
```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.web>
        <pages enableViewState="false" enableViewStateMac="false" viewStateEncryptionMode="Never" enableEventValidation="false" />
        <!--<machineKey decryption="AES" decryptionKey="DFE6143111640695FE6398BEFE11EE8C250948A3260E19BE" validation="SHA1" validationKey="55539B16C368A79B8DAC4994F6F5B627292EBF3AC940543215EE612EE4FCE1DDB07A2F25144016043D5BE349DA5074F5CA2BDF1DF2EE6BE0E475D2BED6DCE2E3" />-->
    </system.web>
    <!--<appSettings>
        <add key="aspnet:AllowInsecureDeserialization" value="true" />
    </appSettings>-->
</configuration>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEpdId3Bh9RBibgDbreFg7JbZunZib7LXsQ1uu5vmEA0ic4vNT43JurmiavA/640?wx_fmt=png&from=appmsg "")  
  
  
  
利用BurpSuite  
或Postman  
工具发出修改后的请求，观察是否可以通过篡改后的ViewState  
 提交数据，并成功反序列化执行。  
  
  
  
**第二步：构造恶意Payload进行反序列化**  
  
**构造恶意对象：**  
  
使用工具如ysoserial.net  
或ysoserial  
（适用于Java的ViewState反序列化攻击）来生成恶意的ViewState  
载荷，内置恶意命令或脚本。例如：  
  
- https://github.com/pwntester/ysoserial.net  
  
```
ysoserial.exe -o base64 -g TypeConfuseDelegate -f LosFormatter -c "echo 123 > C:\ProgramData\2\testing.txt"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEsfYOIquZsjOibONMqicMovrmt2SHbTSjvsnufENeVRqPu0weEiafn3dEQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**替换ViewState：**  
  
将生成的载荷替换原始页面的ViewState  
字段，然后将整个请求通过HTTP工具发送给服务器。此时如果服务器的ViewState  
签名和验证不安全，则会执行恶意对象内的代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEwfCdwvDicPBq22kHsZFIP1mIB4ywQ5cKaNOdicW68aggnPX8jjDWmD7Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
如果使用生成的恶意ViewState  
载荷成功进行反序列化攻击后会在C:\ProgramData\2\  
这个目录下创建一个testing.txt  
文本文件，其内容为123  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEKFj0QKcqADTwSZ7hibvLcLZHHgHko9IIDh8FVKXQP6JAXlU5F8S5Pkw/640?wx_fmt=png&from=appmsg "")  
  
  
**第三步：利用提权**  
  
**提升权限：**  
  
由于ASP.NET应用通常运行在NETWORK SERVICE  
账户下，攻击者可以使用反序列化的权限扩展漏洞（例如，将ViewState  
中的对象替换为高权限用户的token  
）来尝试执行系统命令，访问敏感文件，或直接获得应用程序的管理权限。  
  
  
这里推荐下  
@Rcoil师傅的SharpViewStateKing  
利用工具，已将ViewState  
反序列化的多种场景实现自动化，并且完成了命令执行、文件管理以及.NET内存执行等常用功能，我们可以使用Load Assembly  
加载.NET  
土豆提升权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOcgCmjt82D0Vsksic8TnUUKEUCWmp8ia0JbNcrLwkpanKIh5GEwQoycAR6wkTpeXh0jJnvDMxiaaYOkw/640?wx_fmt=png&from=appmsg "")  
  
  
**持久化攻击：**  
  
一旦获得更高权限的shell  
，我们就可以进一步在服务器上创建后门账户，设置持久的shell  
或利用工具进行内网横向移动等。  
  
  
**0x04 防御措施**  
  
**强制启用ViewState签名和加密：**  
  
在web.config  
文件中，确保ViewStateEncryptionMode  
 设置为Always  
，并将EnableViewStateMac  
设置为true  
，这些措施可以阻止未授权的篡改和反序列化攻击。  
  
  
**使用ASP.NET验证密钥：**  
  
设置一个强大的验证密钥（validationKey  
），并确保machineKey  
配置在Web服务器之间共享以防止篡改。  
  
  
**限制反序列化的对象：**  
  
尽量避免将敏感对象存储在ViewState  
中，并在应用程序中禁用反序列化不受信任的对象。  
  
  
**web.config示例代码：**  
  
以下代码展示了ViewState  
配置文件中的一些安全设置。  
```
<system.web>
    <pages enableViewState="true" viewStateEncryptionMode="Always" enableEventValidation="true" />
    <machineKey validationKey="AutoGenerate,IsolateApps" decryptionKey="AutoGenerate,IsolateApps" validation="SHA1" />
</system.web>
```  
  
  
**0x05 踩坑记录**  
  
记录下我在本地测试遇到的坑，看了很多文章都是将文件写到C:\Windows\temp  
临时目录下，但我在测试时就死活写不进去，这里坑了我很久，原以为是环境有问题，测试了几台机器都这样，使用原应用池和新建应用池以及修改为SYSTEM  
权限还是写不进去......，SharpViewStateKing  
倒是可以正常连接，不知道大家有没有遇到过这个问题，还是遇到了没人记录这个问题......。  
  
  
最后我是使用ysoserial.net  
重新生成了一个不带==  
的载荷换了C:\ProgramData\2  
目录才写进去，这里测试只要带=  
也写不进去。这个问题实在没辙放弃挣扎了（不在一个点上浪费太多时间），大家如果遇到以下两种情况时可参考着解决吧，不行别喷我...0.0...！！！  
> 当前用户或目录权限问题导致C:\Windows\Temp写不进文件，可尝试更好其他可读写目录；ysoserial.net生成的base64反序列化载荷存在==时写不进去，可尝试修改写入字符或路径；  
  
  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
 还在等什么？赶紧点击下方名片开始学习吧 ![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
**知 识 星 球**  
  
  
  
仅前1-400名: 99¥，400-600名  
: 128¥，  
600-800名  
: 148¥，  
800-1000+名  
: 168¥  
，  
所剩不多了...！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOdma4QtfwXXJ4w35lMtvMcogAnI5u4bWIhxq1EzXI0remsQXFk5uhv0BX4eSyzpzJGYHAybgEYeVA/640?wx_fmt=png&from=appmsg "")  
  
**推 荐 阅 读**  
  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247499188&idx=1&sn=9ce15a0e66b2595285e544aaa0c49c24&chksm=cfa559a7f8d2d0b162f00e0c1b02c85219f2668c282b32967b2530f15051b47b21ee2855a783&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247496043&idx=1&sn=4daa27ade9915de6021fea1c2a21d7bc&chksm=cfa55578f8d2dc6ef887ce27215f942ec233320fa6878bc1666ce0fecb0e7f6c7f96a3ba4e2b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247486327&idx=1&sn=71fc57dc96c7e3b1806993ad0a12794a&chksm=cfa6af64f8d1267259efd56edab4ad3cd43331ec53d3e029311bae1da987b2319a3cb9c0970e&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOdAPjIVeN2ZahG9ibP0Y3wlfg6BO1WO7MZfo1JeW7zDWcLSTQ5Ek8zXAia5w1nMnogpbpXP6OxXXOicA/640?wx_fmt=png "")  
  

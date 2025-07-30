#  nuclei+burp 快速构建护网漏洞武器库！！   
原创 fkalis  fkalis   2024-09-05 20:24  
  
## 背景  
> 之前发了一篇关于nuclei+ai浏览器插件的文章，交流群内有师傅想知道的一般用的什么nuclei的burp的插件，于是就写一篇文章给大家介绍一下我的插件的用法~~  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVz2EJKdjZZVRgsicpYHa3iafaLzQTDqGeHcON5NLNjia29znsJW8icjL8pgg/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzsENNnG0XBM5mqhicr1NXPGTlo2USS7vECC83cuArRqvG0ibSxoJnQGUA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzfNaHuHnDiahDwjqJmYTXMyUfJ8TFLtH2JOpvxZ2SHqB47kzRiaHhg9Cg/640?wx_fmt=png&from=appmsg "null")  
## 项目地址  
> **插件1：**https://github.com/projectdiscovery/nuclei-burp-plugin  
  
**插件2：**https://github.com/bit4woo/Fiora  
  
  
  
nuclei-burp-plugin  
### 安装  
  
直接在burp里面进行安装即可  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzqSyTTmgss9JOFYLbABnhicrl1MicaREGWAUHcy0Hvo19BlCDcWwsOTaw/640?wx_fmt=png&from=appmsg "null")  
### 配置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzcf1EVcsr2gcp04WlEHjb5a0nic9l03QKTicQPG8DffnvxqkDtb9ajPHw/640?wx_fmt=png&from=appmsg "null")  
### 单请求匹配  
> 找到能成功复现的案例，可以直接生成poc   
  
举个例子：例如我下面是一个可以正常复现的请求和响应  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzEq39hJHnVgqPLusYbXR7313UMibWsZEdWd3eQuZYdmlb3aTm5WYqicPQ/640?wx_fmt=png&from=appmsg "null")  
### 选中特征关键词，然后进行生成  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzdIezqlbDOOwHXoYBl6K92HaOAxvzIhjpM0nCuLTiccPCwVKVYoZUGJg/640?wx_fmt=png&from=appmsg "null")  
  
他就会弹出一个弹窗，同时已经将yaml的匹配添加为你添加的关键词了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzx6o67bm7NnmkPPiaLDFUWslVvZrYe3Qt2ibkhUqaeMffB3YkgthafJLQ/640?wx_fmt=png&from=appmsg "null")  
### 多请求匹配  
> 在有时候写poc的时候，这个poc可能需要两步才可以判断是否成功，例如文件上传等，这时候就可以将第二个请求选中，选择加入即可  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzD7bZHTx6RR8N3TWicC7HBCiblbIq7V42ToqemnhJBu98nO9KUmPZjvBg/640?wx_fmt=png&from=appmsg "null")  
  
就可以看见这个请求添加到了yaml中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzdIs8EItNvsZow9Hn20F4GCicSawq4HntlZY1cU0UbAEoUjiahNT33xhQ/640?wx_fmt=png&from=appmsg "null")  
### 漏洞快捷检测  
  
在漏洞生成页面可以直接点击执行，快捷检验poc  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzwgltBITYU77HeGZGeUJ8PnUoOqx8yLgR18jMMW6x9icv1MHclhia9EOw/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzAst9rCvliccdY6bGsm8UrPDCsxGtyUH9v6lLfy456KCDMJol5Wr5icWA/640?wx_fmt=png&from=appmsg "null")  
### 模板保存  
> 测试完成直接保存到模板库即可，可以快速的构建自己的poc漏洞库！！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzYey6NpQBJoHah7A1uTYNTUaLYKk7Z2ibibz8k7NqNwicBzjibh0oMDl0Dw/640?wx_fmt=png&from=appmsg "null")  
## Fiora  
> 如果说Nuclei的那个插件是为了快捷的生成yaml，那么这两个插件结合起来就可以实现一个漏洞库的集成了，  
> 这里我在其基础上进行了改装，添加了一些我的功能，和修复了一些bug，原版可以直接从我的链接下载  
  
### 漏洞查询  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzE1m1hSyrmdkj6XzpuMIg9g8LD0ic2ejKsdib9aXjHpib4YiazkkAibsOxeA/640?wx_fmt=png&from=appmsg "null")  
  
可以根据名称，tag等进行漏洞的查询，方便快速打day  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzHXtbwejCgQU6LkUNPutdq9FHCS1CNzZBzOJoTichU6DIsBzBiasXUMyw/640?wx_fmt=png&from=appmsg "null")  
### 快捷发送目标  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzW9oTtyzFEZnjpUs9ZAIhHOicpgqx6bpmJuFRHLVC5ZtVuCYW2ibRogVQ/640?wx_fmt=png&from=appmsg "null")  
### 快捷对目标进行漏扫  
  
可以根据tags，单poc，全部poc等对目标进行漏扫  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzHGc5aMwFnDfefW8V61IoAXEZQtNQQVPjCRxTicGgic8lwrlTbVIXng6g/640?wx_fmt=png&from=appmsg "null")  
### 快捷查看yaml信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiccXQwYeXDbOZpE0eJRicKtVzs0NR9lHtHTDNOnvjpjkmSmnwjIZkVsBVp2vtbF2tFeDmtB0l1h6N9w/640?wx_fmt=png&from=appmsg "null")  
## 总结  
> **将这两个插件结合使用，同时当nday/1day公开的时候自己去积累yaml，就可以很快很好的构建起自己的漏洞库，等到攻防的时候就可以比别人更快一步的进行打点！！**  
  
  
  

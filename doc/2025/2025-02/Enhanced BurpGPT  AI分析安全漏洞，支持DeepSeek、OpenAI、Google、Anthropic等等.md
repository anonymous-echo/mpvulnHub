#  Enhanced BurpGPT | AI分析安全漏洞，支持DeepSeek、OpenAI、Google、Anthropic等等   
原创 尘佑不尘  泷羽Sec-尘宇安全   2025-02-11 06:16  
  
#  前言   
  
Enhanced BurpGPT 是一个 Burp Suite 插件，它能帮助你使用 AI（人工智能）来分析 Web 应用的安全问题。简单来说，当你测试网站时，你可以在指定的请求响应对，点击send to gpt，交由AI分析，找出潜在的安全漏洞。  
  
**功能介绍**  
- 自动化分析，节省时间  
  
- AI 辅助发现安全问题  
  
- 适合新手学习安全测试  
  
- 提供详细的分析报告  
  
- 支持中文输出  
  
- 支持自定义prompt  
  
**下载地址在文末**  
### 往期推荐  
  
[oscp+：简介、考试形式、对比其他证书、政策变动](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247488607&idx=1&sn=5f5e5962a727e42c5dbe2e6345f05683&scene=21#wechat_redirect)  
  
  
[灵兔宝盒二开 | 286渗透工具合集，新增OneCS-49_尊享版、vshell4.9.3破解版、Godzilla特战版等24款](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247489169&idx=1&sn=497d7862c41cd6248d71a7ac1f61ed42&scene=21#wechat_redirect)  
  
  
[PotatoTool一款功能强大的网络安全综合工具支持免杀、自定义内存马、提权、扫描、一键解密、AI分析、溯源等等](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247489044&idx=1&sn=d3c8af030840190ec31d263a36e8895f&scene=21#wechat_redirect)  
  
  
[14w+poc，nuclei全家桶：nuclei模版管理工具+Nuclei](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247485366&idx=1&sn=d000689bc42cb4931657c9a081deebb5&scene=21#wechat_redirect)  
  
  
[红队武器库VulToolsKit全家桶：图形化页面+自己额外添加的一些工具](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247487982&idx=1&sn=57e323c285f66c87e46e496148307db9&scene=21#wechat_redirect)  
  
  
[fscan全家桶：FscanPlus，fs，fscan适用低版本系统，FscanParser](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247484721&idx=1&sn=a0bde50df32ae2df7f6e8fdb4a0ddb3a&scene=21#wechat_redirect)  
  
  
[一款集成了fofa、鹰图平台、360quake的信息收集工具 | NoMoney，工具涉及的范围在以上平台中都是免费的，安装使用](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247490142&idx=1&sn=1ecdb04eebda46659e5300779a7da310&scene=21#wechat_redirect)  
  
  
[ctf综合利用工具，集成多款AI，94GB大小量大管饱：ctftools-all-in-one_proV2](https://mp.weixin.qq.com/s?__biz=Mzk1NzE0ODk3Nw==&mid=2247488292&idx=1&sn=0d2517525b74c39bf4cda5c565ca2638&scene=21#wechat_redirect)  
  
#  支持的模型厂家（仅列举部分厂家和模型）   
### DeepSeek  
- **DeepSeek-R1**  
  
- 开源模型支持  
  
- 本地部署选项  
  
- **DeepSeek-Chat**  
  
- 优化的对话体验  
  
- 更好的中文支持  
  
### OpenAI  
- **GPT-3.5-turbo**  
  
- 快速响应，性价比高  
  
- 适合日常测试使用  
  
- **GPT-4**  
  
- 更强的分析能力  
  
- 适合复杂场景分析  
  
- **o1-preview**  
  
- 最新的模型版本  
  
- 更大的上下文窗口  
  
### Google  
- **Gemini Pro**  
  
- 优秀的代码分析能力  
  
- **Gemini-2.0-flash-thinking-exp**  
  
- 更强大的推理能力  
  
- 更好的多模态支持  
  
### Anthropic  
- **claude-3.5-sonnet**  
  
- 优秀的理解能力  
  
- 优秀的代码能力  
  
- **Claude 3 Haiku**  
  
- 更快的体验  
  
**几乎所有模型**  
#  使用截图   
### 配置标签栏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nb9ibdF5mcI65TuibHlh6Fr2ZyOnqo48wdbJYIkOOAJnKqbAFSW4okOkA/640?wx_fmt=png&from=appmsg "")  
  
比如我配置deepseek，即为：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nm1ZibyzWvVExBk3wpMeuKs1p7zLfjBSmSxU6YYiacEv34dS4X5992Aicw/640?wx_fmt=png&from=appmsg "")  
### 分析中截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nlicmPZicianBfQGY4qCmicRgXKSI0QeSsgpO6BIRDCCTibrCooQTkDuj3dA/640?wx_fmt=png&from=appmsg "")  
### 分析结果展示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nMjbH1UN6Bz89bTttS3d1C0k7VBQGdqO3lbq75fwOhF9ibsNzA8kvv6A/640?wx_fmt=png&from=appmsg "")  
  
Deepseek分析结果展示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nXKn4WDwykfFEpHsjc5gKWvcxUMcbyUfibcXr7lYDH5yuHwwbnYnmgTA/640?wx_fmt=png&from=appmsg "")  
#  安装步骤 📥   
### 前提条件  
- 已安装 Burp Suite  
  
- 已安装 Jython（Python 环境）  
  
- 有稳定的网络连接  
  
- 有 GPT API 的密钥（API Key）  
  
### 详细安装步骤  
1. **安装 Jython**  
  
1. 下载   
Jython Installer  
  
1. 运行安装程序，记住安装路径  
  
1. **配置 Burp Suite**  
  
1. 打开 Burp Suite  
  
1. 点击 Extender  
 标签  
  
1. 点击 Options  
 子标签  
  
1. 在 Python Environment  
 部分，选择你的 Jython jar 文件路径  
  
1. **安装插件**  
  
1. 在 Burp Suite 中，点击 Extender  
 标签  
  
1. 点击 Extensions  
 子标签  
  
1. 点击 Add  
 按钮  
  
1. 选择 Extension Type  
 为 Python  
  
1. 选择下载的 burpGTPv1.py  
 文件  
  
1. 点击 Next  
，等待加载完成  
  
#  配置教程 ⚙️   
### 第一步：基础配置  
1. 点击 GPT Analysis  
 标签  
  
1. 在 Configuration  
 标签页中：  
  
1. 填写 API URL  
（例如：https://api.openai.com/v1/chat/completions  
）  
  
1. 填写你的 API Key  
  
1. 选择或输入要使用的 Model  
（例如：gpt-3.5-turbo  
）  
  
1. 注意，获取模型默认访问的是/v1/models，对话访问的是/v1/chat/completions  
  
### 第二步：高级配置  
1. **设置超时和长度限制**  
  
1. Timeout  
：建议设置 60 秒  
  
1. Max Request Length  
：建议设置 1000  
  
1. Max Response Length  
：建议设置 2000  
  
1. **自定义提示模板**  
  
1. {URL}  
：目标网址  
  
1. {METHOD}  
：请求方法  
  
1. {REQUEST}  
：请求内容  
  
1. {RESPONSE}  
：响应内容  
  
1. 可以使用默认模板  
  
1. 也可以根据需要修改模板  
  
1. 支持的变量：  
  
#  使用方法 🎯   
### 基础使用  
1. 在 Burp 的任意位置（如 Proxy、Repeater）右键点击请求  
  
1. 选择 Send to GPT  
  
1. 等待分析完成  
  
1. 在 Analysis Results  
 标签页查看结果  
  
### 查看结果  
- 左侧显示分析历史列表  
  
- 右侧显示详细分析内容  
  
- 可以使用搜索功能查找历史记录  
  
- 可以导出分析报告  
  
### 查看日志  
- 切换到 Logs  
 标签页  
  
- 可以看到详细的操作记录  
  
- 出现问题时可以查看错误信息  
  
#  常见问题解答   
### 1. 插件加载失败？  
- 检查 Jython 是否正确安装  
  
- 查看 Extender  
 的 Errors  
 标签页错误信息  
  
### 2. 无法连接 API？  
- 检查网络连接  
  
- 验证 API URL 是否正确  
  
- 确认 API Key 是否有效  
  
- 检查代理设置  
  
### 3. 分析结果为空？  
- 检查请求/响应是否过大  
  
- 确认模型选择是否正确  
  
- 查看日志中的详细错误信息  
  
### 4. 分析太慢？  
- 调整超时时间设置  
  
- 减小最大请求/响应长度  
  
- 检查网络状况  
  
#  使用技巧 💪   
1. **提高分析效率**  
  
1. 合理设置请求/响应长度限制  
  
1. 使用自定义模板针对特定场景  
  
1. 定期导出重要分析结果  
  
1. **优化分析结果**  
  
1. 调整提示模板以获得更精确的分析  
  
1. 针对不同类型的请求使用不同的模板  
  
1. 结合 Burp Suite 其他功能使用  
  
1. **管理分析历史**  
  
1. 及时清理不需要的分析记录  
  
1. 使用搜索功能快速定位历史记录  
  
1. 定期导出重要发现  
  
#  注意事项 ⚠️   
1. **安全性**  
  
1. 不要分享你的 API Key  
  
1. 注意请求/响应中的敏感信息  
  
1. 定期更新插件版本  
  
1. **资源使用**  
  
1. 大量分析可能消耗 API 配额  
  
1. 过多历史记录可能占用内存  
  
1. 建议定期清理历史记录  
  
1. **使用限制**  
  
1. 部分功能需要网络连接  
  
1. 分析结果仅供参考  
  
1. 关闭 Burp Suite 后历史记录会清空  
  
#  获取帮助 💬   
  
如果遇到问题：  
1. 查看日志信息  
  
1. 检查配置是否正确  
  
1. 尝试重启插件或 Burp Suite  
  
后台回复：**20250211**  
 获取下载地址  
#  oscp+培训   
  
**在boss直聘搜索oscp，cisp进行对比**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7n8LEgFHIc5JfnN8JNaJBsysZOahWl6MBibHALTPVkkNND6aNia277FGIA/640?wx_fmt=png&from=appmsg "")  
### oscp+培训福利  
  
1、报名一次oscp培训即可**无限学习下一期**  
，下下一期，学到你会再去考试oscp  
  
2、学生党想找工作的或者上班的想换工作的学完oscp可以找泷羽sec推荐（自己有技术实力就行）  
  
3、4000培训费用证明学生，**可以分期，无利息**  
，还优惠500  
  
4、**拥有CISSP、OSCP、OSEP等多项专家认证的在职高级红队泷老师**  
的就业方向指导  
  
5、官方的oscp+有团购优惠，10人组团可以打8折优惠，如果在我们这里报了培训，到时候报名的时候就可以联系大陆官方负责人给你们凑团购，8折团购可以便宜几千  
  
6、感兴趣的师傅们可以**找我咨询**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nT5SiaBhIVdlvPlaLR6VplD7ZGWbFV2eWmfxZTuxEmVd4YB5DIE5EQVg/640?wx_fmt=png&from=appmsg "")  
## 泷羽Sec资料库  
  
可以加入一下我们的帮会，是真正的红队大佬创建的，里面会定时丢些网上没有的工具（比如安卓远控7.4，不过现在已经删除了，有时限，加入的记得看好时间），除了这个：还有大量的poc、渗透工具、渗透课程、实战案例等等。现在只要99就可以终身，后面人多了就会涨价了  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nlQyGvdFWSAJd3kYjueeqaYLIOVsgzQafQYl1F2p7mickz6Y0VaJoglw/640?wx_fmt=jpeg&from=appmsg "")  
- 各种的学习资料，各种的付费课程，各种的付费工具。包括且不限于渗透测试，python/c++编程，免杀，AI人工智障，逆向，安全开发等互联网资源  
  
![image-20250103035215880](https://mmbiz.qpic.cn/mmbiz_png/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nwYu4c3kMpalHDAt7mwoNKGZAYnlupBibx3ZMnlPfEBaL13xJCkLIdiaA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nHDv89eIaEKSeD08m40nUe05ksibM11HV5NcWCWsrG6yMQEkdp6vs5xQ/640?wx_fmt=png&from=appmsg "")  
## 学习交流群  
  
可以加入学习交流群，里面有学习一些资源。泷老师也在里面，有什么学习方面不会的大家可以一起交流，共同进步。如果问题比较困难可以问泷老师，他会帮忙解答的。如果二维码过期，后台发送 安全屋 获取新的二维码。  
  
由于直接放群二维码有很多广告加进来，如果想加入学习交流群的师傅请扫码添加我为好友，再拉你进群，避免广告进入。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/HG5jOHGyP3hoKUuUNoIw8E7x6hwDVU7nkPIdsDicRB1U6ZWjxR4xDmkMaw0f3Ribicd7GicExBUVM68AibXW0Q45Pfw/640?wx_fmt=jpeg&from=appmsg "")  
  
我们红队全栈公益课链接：https://space.bilibili.com/350329294  
  

#  警惕！Ollama 未授权访问漏洞来袭   
原创 骇客安全  骇客安全   2025-03-08 16:29  
  
亲爱的读者朋友们，在当下人工智能飞速发展的时代，Ollama 作为一款颇受欢迎的开源大语言模型服务工具，为众多开发者和使用者提供了便捷的服务。然而，近期它却被曝出存在严重的**未授权访问漏洞**  
，这一消息犹如一颗重磅炸弹，在相关领域引起了轩然大波。  
## 漏洞的危害  
  
- 📅 昨天与 AI 讨论的职场机密  
  
- 🏥 医疗模型训练的患者数据  
  
- 💼 公司核心项目的技术文档  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IePibcXn991NQyDPI622QX6Wdnib44H19bfVibxS9KWeGBiaGK9hwwgaCaRWJCkwdwtXhmFukRiav8hdGic6dU4YkXUA/640?wx_fmt=jpeg&from=appmsg "")  
  
攻击者可通过以下方式实施破坏：  
  
1.🔥 **窃取敏感数据**  
：聊天记录 / 模型文件 / API 密钥  
  
2.⚡ **滥用计算资源**  
：调用推理接口挖矿 / 暴力破解  
  
3.🛠️ **控制服务器**  
：植入木马程序发起勒索攻击  
## 漏洞的成因  
  
Ollama  
 默认部署时监听于 127.0.0.1，仅允许本地访问，从而在初始配置下保证了较高的安全性。然而部分用户为了方便从公网访问，会将监听地址修改为 0.0.0.0。  
  
在这种修改之后，如果未额外配置身份认证或访问控制机制，Ollama 的管理接口就会暴露于公网，导致攻击者只需访问服务端口（默认 11434）即可调用敏感功能接口，进而读取、下载或删除私有模型文件，或滥用模型推理资源等。  
  
此外，老版本 Ollama 的部分实现在处理用户提供的数据时缺乏严格校验，进一步加剧了漏洞影响。例如 Ollama   
0.1.34 版本之前  
的 /api/pull 接口存在路径遍历漏洞  
（  
CVE-2024-37032）  
，攻击者可利用特制请求覆盖服务器文件并进而执行任意代码。在缺乏认证的前提下，这类漏洞更加容易被远程利用。  
  
```
# 漏洞代码片段（示例）
def pull_model(request):
    path = request.GET.get('path')
    # 未做安全校验直接拼接路径
    with open('/models/' + path, 'r') as f:
        return f.read()
```  
## 受影响的范围  
- 🌍 **全球分布**  
：32 个国家检测到暴露实例  
  
- 🚦 **版本风险**  
：0.1.18-0.1.34 版本受 CVE 影响  
  
- 💻 **资产规模**  
：超过 12 万台服务器暴露公网  
  
##   
## 防护建议  
<table><thead><tr><th><section><span leaf="">步骤</span></section></th><th><section><span leaf="">操作指南</span></section></th><th><section><span leaf="">图示</span></section></th></tr></thead><tbody><tr><td><section><span leaf="">1. 检查配置</span></section></td><td><section><span leaf="">查看</span><code><span leaf="">ollama server</span></code><span leaf="">命令输出</span></section></td><td><p><span><span style=" box-sizing: border-box;display: inline-block;overflow: hidden;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px; max-width: 100%; "><span style="box-sizing: border-box;display: block;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px;max-width: 100%;"><span leaf=""></span></span><span leaf=""></span></span></span><span style="display: inline-block;width: 0px;height: 0px;"><span style=" box-sizing: border-box;display: inline-block;overflow: hidden;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px; max-width: 100%; "><span style="box-sizing: border-box;display: block;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px;max-width: 100%;"><span leaf=""></span></span><span leaf=""></span></span></span></p></td></tr><tr><td><section><span leaf="">2. 版本升级</span></section></td><td><section><span leaf="">执行</span><code><span leaf="">ollama version</span></code><span leaf="">后到官网下载补丁</span></section></td><td><p><span><span style=" box-sizing: border-box;display: inline-block;overflow: hidden;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px; max-width: 100%; "><span style="box-sizing: border-box;display: block;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px;max-width: 100%;"><span leaf=""></span></span><span leaf=""></span></span></span><span style="display: inline-block;width: 0px;height: 0px;"><span style=" box-sizing: border-box;display: inline-block;overflow: hidden;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px; max-width: 100%; "><span style="box-sizing: border-box;display: block;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px;max-width: 100%;"><span leaf=""></span></span><span leaf=""></span></span></span></p></td></tr><tr><td><section><span leaf="">3. 加固设置</span></section></td><td><section><span leaf="">启用 JWT 认证 + IP 白名单</span></section></td><td><p><span><span style=" box-sizing: border-box;display: inline-block;overflow: hidden;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px; max-width: 100%; "><span style="box-sizing: border-box;display: block;width: initial;height: initial;background: none;opacity: 1;border: 0px;margin: 0px;padding: 0px;max-width: 100%;"><span leaf=""></span></span><span leaf=""></span></span></span></p></td></tr></tbody></table>### 2️⃣ 高级防护方案  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991NQyDPI622QX6Wdnib44H19bLlvY30zMJaAeQGibGoYzackUDu0C3d42dhGe1rmCVkHhQicpk2qEvWKw/640?wx_fmt=png&from=appmsg "")  
```
graph TD
A[暴露面管理] --> B[关闭不必要的API]
A --> C[设置请求频率限制]
D[访问控制] --> E[启用RBAC权限]
D --> F[配置HMAC签名]
```  
## 特别提醒  
## ⚠️ 攻击正在进行时：安全团队监测到每分钟有 300 + 次漏洞扫描尝试⚠️ 妇女节特别关注：3 月 8 日当天攻击量激增 470%，或与节日期间系统维护人员减少有关  
##   
  
##   
##   
##   
  
**立即行动**  
：关注本公众号，后台回复【Ollama】获取：  
  
漏洞检测工具包（含自动扫描脚本）  
  
最新版安装包及升级指南  
  
  
  

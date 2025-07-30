> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNDIzNDUxOQ==&mid=2247500142&idx=2&sn=cf476f2a200acb32881e43ae5476faef

#  Realtek RTL8762E SDK v1.4.0 中的配对随机数过早注入漏洞  
 独眼情报   2025-06-26 09:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnQMMibMicE0rVN9WoAVnAbBNSPiaQIic8ib4aZH95rteg2icgadib605cP90pBqeVz2tVhn9u6xlL0S4ibZwQ/640?wx_fmt=png&from=appmsg "")  
## 1. 概述  
  
在使用 **RTL8762E SDK v1.4.0**  
 的 **Realtek RTL8762EKF-EVB**  
 开发平台中发现了一个拒绝服务（DoS）漏洞。在蓝牙安全连接配对过程中，设备在接收到必需的**配对公钥**  
之前就接受了精心构造的**配对随机数**  
数据包，导致状态机违规。这会引起协议不一致，使配对过程失败并拒绝后续连接尝试。重复利用此漏洞可能导致设备无法建立安全的BLE连接。  
## 2. 受影响组件  
- **厂商**  
：Realtek  
  
- **设备**  
：RTL8762EKF-EVB  
  
- **SDK版本**  
：RTL8762E SDK v1.4.0  
  
- **组件**  
：
```
BLE
```

  
 安全连接配对逻辑  
  
## 3. 漏洞详情  
### 3.1 描述  
  
蓝牙低功耗（BLE）安全连接配对需要严格的消息顺序：**配对随机数**  
消息必须在**配对公钥**  
成功交换之后发送。然而，受影响的SDK未能强制执行这一顺序。攻击者可以过早地注入**配对随机数**  
数据包，设备会错误地接受该数据包，从而违反安全连接状态机中的预期状态转换。  
  
这导致内部状态转换未定义或无效，阻止成功配对，并可能导致连接断开或保持卡住状态。  
### 3.2 根本原因  
  
BLE协议栈在处理
```
配对随机数
```

  
之前没有验证协议状态。具体来说，它没有强制执行蓝牙核心规范所要求的条件：**必须在接受随机值之前完成公钥交换**  
。  
## 4. 概念验证（PoC）  
  
攻击者作为BLE中心设备或外围设备连接到RTL8762EKF-EVB设备，并在预期的**配对公钥**  
之前立即发送精心构造的**配对随机数**  
数据包。这会导致设备进入无效状态并中止配对过程。详细信息和脚本可在pairing_random_before_pairing_public_key.py中找到。
```
https://github.com/yangting111/BLE_TEST/blob/main/result/PoC/Realtek/pairing_random_before_pairing_public_key.py
```

  

```
1. 攻击者发起BLE配对
2. 在配对公钥交换之前，发送恶意配对随机数
3. 目标设备接受数据包 → 状态不匹配 → 配对中止

```

## 5. 复现步骤  
1. 设置运行启用安全连接配对的BLE外围设备的RTL8762EKF-EVB。  
  
1. 使用自定义BLE中心设备（例如，修改的Android协议栈或具有注入功能的NRF BLE嗅探器）。  
  
1. 在配对过程中，在
```
配对公钥
```

  
交换之前注入
```
配对随机数
```

  
数据包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnQMMibMicE0rVN9WoAVnAbBNSyHu8DHYa9aJaFJDEqzuIhwLUVwkPfuWNzlmiby6jr2VQBRAEtzNsj1g/640?wx_fmt=png&from=appmsg "")  
1. 在协议流程的预期位置之前收到随机数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnQMMibMicE0rVN9WoAVnAbBNS8sbTAqiaaV7yiaeS6u46g2IKwsIZfVGh7wDmI5qJLGmz126yc2gWCT1w/640?wx_fmt=png&from=appmsg "")  
## 6. 安全影响  
- **漏洞类型**  
：拒绝服务（DoS）  
  
- **影响**  
：阻止合法的BLE安全连接  
  
- **所需权限**  
：无（空中攻击）  
  
## 7. 攻击向量  
  
处于BLE范围内的攻击者可以在公钥交换之前注入格式错误或过早的
```
配对随机数
```

  
数据包。受害设备接受这个无效序列，触发状态机错误并导致配对过程失败。重复此行为可能导致持续的连接拒绝。  
## 8. 参考资料  
- **蓝牙核心规范 v5.3**  
，第3卷，Part H，第2.4.5节（SMP状态机）  
  
- Realtek RTL8762E SDK v1.4.0  
  
- BLE安全连接协议流程图  
  
## 9. 修复建议  
- 在BLE SMP层实现严格的状态验证：确保
```
配对随机数
```

**仅在**  
双方交换
```
配对公钥
```

  
之后才被接受。  
  
- 根据SMP状态机丢弃任何**乱序接收**  
的消息。  
  
- 考虑添加日志记录或调试输出，以帮助在测试期间识别乱序消息。  
  
  
  
  

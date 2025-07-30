#  基于ESP8266水质检测 （MQTT上报小程序和HA）   
原创 大表哥吆  kali笔记   2025-04-15 00:00  
  
> 在前面的文章中，我们讲到了基于Arduino读取水质传感器的数据。详情可以阅读历史文章。  
  
  
但由于Arduino的限制，无法将数据上传至网络。因此，本文为大家带来基于Esp8266配置水质传感器进行数据上报。  
# 准备  
- Esp8266  
  
- 水质传感器  
  
- MQTT服务器  
  
# 线路连接  
  
VCC  
--3.3v  
  
GND  
--GND  
  
信号线  
--A0  
(模拟脚针)  
# 代码  
```
#include<ESP8266WiFi.h>#include<PubSubClient.h>#include<ArduinoJson.h>// WiFi配置constchar* ssid = "你的WiFi名称";constchar* password = "WiFi密码";// MQTT配置constchar* mqtt_server = "MQTT服务器地址";constint mqtt_port = 1883;constchar* mqtt_user = "admin";constchar* mqtt_password = "admin";constchar* topic = "shuizhi"; #订阅主题// 传感器配置constint TDS_PIN = A0;  // ESP8266只能使用A0进行模拟输入constfloat VREF = 3.3;  // 传感器工作电压constfloat K = 0.4;     // 校准系数WiFiClient espClient;PubSubClient client(espClient);voidsetup_wifi(){  delay(10);  Serial.println();  Serial.print("Connecting to ");  Serial.println(ssid);  WiFi.begin(ssid, password);while (WiFi.status() != WL_CONNECTED) {    delay(500);    Serial.print(".");  }  Serial.println("");  Serial.println("WiFi connected");  Serial.println("IP address: ");  Serial.println(WiFi.localIP());}voidreconnect(){while (!client.connected()) {    Serial.print("Attempting MQTT connection...");    if (client.connect("esp8266-SZ", mqtt_user, mqtt_password)) {      Serial.println("connected");    } else {      Serial.print("failed, rc=");      Serial.print(client.state());      Serial.println(" try again in 5 seconds");      delay(5000);    }  }}String getWaterQuality(float tds){if (tds <= 9) return"优";       // 0-9 mg/L 纯净水elseif (tds <= 60) return"优";  // 10-60 mg/L 山泉水、矿化水elseif (tds <= 100) return"中"; // 60-100 mg/L 净化水elseif (tds <= 300) return"中"; // 100-300 mg/L 普通自来水elsereturn"差";                // >300 mg/L 可能存在污染}voidsetup(){  Serial.begin(115200);  setup_wifi();  client.setServer(mqtt_server, mqtt_port);}voidloop(){if (!client.connected()) {    reconnect();  }  client.loop();// 读取并计算TDS值int analogValue = analogRead(TDS_PIN);float voltage = analogValue * VREF / 1024.0;float tdsValue = (133.42 * pow(voltage, 3) - 255.86 * pow(voltage, 2) + 857.39 * voltage) * K;// 获取水质等级  String quality = getWaterQuality(tdsValue);// 构建JSON数据  StaticJsonDocument<200> doc;  doc["TDS"] = round(tdsValue);  // 四舍五入取整  doc["DJ"] = quality;char jsonBuffer[512];  serializeJson(doc, jsonBuffer);// 发布MQTT消息  client.publish(topic, jsonBuffer);  Serial.print("Published: ");  Serial.println(jsonBuffer);  delay(5000);  // 5秒间隔}
```  
  
**代码功能说明：**  
- 每5s上传数据到shuizhi  
主题。  
  
- 对数据进行处理，分为优、中、差  
  
**数据格式说明:**  
  
发送数据为json数据，格式如下：  
```
{"TDS":21,"DJ":"优"}
```  
  
前者为上报的TDS数据，后者是当前的数据等级。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatgrCG1lBqkj7pC1RDmAxY4H06SiceaQQYBySNIGOW9bHibH4v2qcCGfTusNA4LdVmQ93Bmwowu3L8qw/640?wx_fmt=png&from=appmsg "")  
  
另外，当前仅为一个数据，如果您有多个设备，如用DHT11  
接入温湿度数据，可以将拼接为完整的jons数据，如：  
```
{"humi":58,"temp":36,"TDS":500,"DJ":"差"}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatgrCG1lBqkj7pC1RDmAxY4HoZ6UBHD9F8K7BeAGoRYNo6QpP6etqxGKCnrfqWw3St6pfd760gMneA/640?wx_fmt=png&from=appmsg "")  
# 接入HA或小程序  
  
因为是基于MQTT上报数据，我们可以将数据接入HA或者微信小程序。  
  
![矿泉水效果](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatgrCG1lBqkj7pC1RDmAxY4HnCz6p2EpNibSIxMrfzZgIdMFm0uoU1memAS2u9YohZvFOe7sGVu7Whw/640?wx_fmt=png&from=appmsg "")  
  
矿泉水效果  
  
![自来水数据](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatgrCG1lBqkj7pC1RDmAxY4Hicydm1GYqlf3rBBxTN4V1d9QPa7zEQ5FibExpIP2auWHH5lFJ1RwncJQ/640?wx_fmt=png&from=appmsg "")  
  
自来水数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatgrCG1lBqkj7pC1RDmAxY4HXlBt9m3mmJoFLtCeK9T8zRIAsuolRbbJavAs1BYfYSGSQYvEU4wVJA/640?wx_fmt=png&from=appmsg "")  
# 总结  
  
在后期，我们会更新其他类型的传感器。方便硬件爱好者学习和研究。当然，如果您有更好的方法，请在评论区留下你精彩的评论。  
  
**BREAK AWAY**  
  
**往期推荐**  
  
**0****1**  
  
[基于Arduino 水质检测](https://mp.weixin.qq.com/s?__biz=MzkxMzIwNTY1OA==&mid=2247511604&idx=1&sn=2573a47365c6833ade7593e3f0e62c47&scene=21#wechat_redirect)  
  
  
**0****2**  
  
[基于MQTT 小程序 完全开源！](https://mp.weixin.qq.com/s?__biz=MzkxMzIwNTY1OA==&mid=2247511532&idx=1&sn=72f823fb5bdaf5a30cc0438c764eb691&scene=21#wechat_redirect)  
  
  
**0****3**  
  
[一文玩转MQTT(基于esp8266 DHT11 MQTT Mysql实现)](https://mp.weixin.qq.com/s?__biz=MzkxMzIwNTY1OA==&mid=2247496521&idx=1&sn=38bde203405d397ca72d49f2e2a2d95c&scene=21#wechat_redirect)  
  
  
更多精彩文章 欢迎关注我们  
  
  

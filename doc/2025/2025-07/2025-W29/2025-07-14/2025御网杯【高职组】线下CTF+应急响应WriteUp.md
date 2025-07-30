> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU3MzEwMTQ3NQ==&mid=2247507954&idx=1&sn=6b10c6716afd896afaf8fd2199207606

#  2025御网杯【高职组】线下CTF+应急响应WriteUp  
原创 青少年CTF  中学生CTF   2025-07-14 10:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/98w89icYGQfc96SwZKF6hEasKqibSh0NvVAJX5u4U8MvicKA0LLbCSFNKAibpXql5IHkbPFZoS4UldrGV5GibvnUsPw/640?wx_fmt=jpeg&from=appmsg "")  
  
本次半决赛序号为B107、决赛序号为D22，作为高职组是没什么压力在身上的，队友全在睡觉和打游戏，一个人打这次比赛足矣。也很容易看出来这次比赛其实按照线上的赛制，完全没有什么压力存在。  
# CTF（半决赛）  
## Misc  
#### Misc1 - YWB_Misc_文件隐写02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVWYv76yARiaIbZ5wD0BNoPIdHp4U9D4luxmISGE1af21nlcI2L9Md2KA/640?wx_fmt=png&from=appmsg "")  
  
一个”题目附件.jpg“，但是说是JPG，我们用010看一下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVehldT7wUQk4hwiaQVxhoAkDyMONslV0uboSDy02uc8eRuoGy5j6vmeg/640?wx_fmt=png&from=appmsg "")  
  
其实不难发现，后面还有个flag.txt存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV6yyOvFjxlQibXPhPsjV3lpM66Mt9qBEoDHyXVnhfia63AhibrAUkcVDOg/640?wx_fmt=png&from=appmsg "")  
  
这是一个7z文件，直接右键使用压缩包打开，或者直接将上面那串字符进行解密：“666c61677b7761736a5f303130315f7a6968616f7d”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVkiaJtBS6OfE3PWQBxXEcarSJcs2CL7Vg9zcR5mMcDZUvKYlNGXjLvkA/640?wx_fmt=png&from=appmsg "")  
  
得到FLAG：flag{wasj_0101_zihao}  
#### Misc2 - YWB_Misc_图片隐写02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVU9oQVb69Jqtiau5yADRj4ic1X3HDQYclncJq29dkjTP2Qic0ibp5W6ZaBQ/640?wx_fmt=png&from=appmsg "")  
  
附件中，一个图片，二维码很明显是残缺不全的，底部被隐藏，那么大概率是宽高修改了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVKnMEFdQJfoxsdRBVpMK2oib69UBLYMmVpIegelMic66WTwhtaQP8ZBvA/640?wx_fmt=png&from=appmsg "")  
  
使用Brute_Crack_PNG工具，进行宽高爆破  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVfz5NIHeibXf4XibRicsicb2uBfStyansTS9QL5F2L63Oiaiay05njbDHI1jg/640?wx_fmt=png&from=appmsg "")  
  
使用爆破高度模式，进行爆破。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV3JDlrtPLBITNIU6RzxlwkYjBsCVqXttpib9ZjBmhcujMyhoicribwATeQ/640?wx_fmt=png&from=appmsg "")  
  
很明显，二维码一般是正方形图片，600px的高度，先保存文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVIiceQYtMc7bn3wbogQ77qnxqpLYQiciaCosovibC98VyeX3E9TWN7W5LPw/640?wx_fmt=png&from=appmsg "")  

```
import cv2
from pyzbar.pyzbar import decode

def scan_qr_code(image_path):
    # 读取图片
    img = cv2.imread(image_path)
    if img is None:
        print(f&#34;无法加载图片: {image_path}&#34;)
        return

    # 解码二维码
    decoded_objects = decode(img)
    if not decoded_objects:
        print(&#34;未检测到二维码。&#34;)
        return

    # 输出二维码内容
    for obj in decoded_objects:
        print(f&#34;类型: {obj.type}&#34;)
        print(f&#34;数据: {obj.data.decode('utf-8')}&#34;)
        print(&#34;-&#34; * 30)

if __name__ == &#34;__main__&#34;:
    scan_qr_code(&#34;modified.png&#34;)


```

  
进行二维码解码后，得到一串Base64：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV0nh78HhZuXDoaJYsTw1UzhREYhXGerQRzoU7jYWxNfFNhvSjQELCqg/640?wx_fmt=png&from=appmsg "")  

```
from qsnctf import base64_decode

print(base64_decode(&#34;RmxhZ3tuaXNwX3R1cGlhbjEyMTMxfQ==&#34;))

```

  
得到结果：Flag{nisp_tupian12131}  
#### YWB_Misc_次数还原  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV0ibWZ1iazbXsYibLqYIe2rPxFZ3NZtjH8gtEbfSmzfWpueJshVibEIgenA/640?wx_fmt=png&from=appmsg "")  
  
其实按照这个频率，FLAG大部分是大写，很难不让人想到应该分析每个字符频率的出现次数，进行排序后应该就是FLAG了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVJDcdclSeaF5Gb69YnAWM5bN0T1TN7nQwOBRfpUiapedht5Bep1xf2rg/640?wx_fmt=png&from=appmsg "")  

```
from collections import Counter

def char_frequency(text):
    counter = Counter(text)
    total = sum(counter.values())
    
    print(&#34;字符\t数量\t占比(%)&#34;)
    print(&#34;-&#34; * 20)
    for char, count in counter.most_common():
        percent = (count / total) * 100
        display_char = char if char != &#34;\n&#34; else &#34;\\n&#34;
        print(f&#34;{display_char}\t{count}\t{percent:.2f}&#34;)

if __name__ == &#34;__main__&#34;:
    content = &#34;&#34;&#34;这里粘贴文档内容&#34;&#34;&#34;
    char_frequency(content)


```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVsIDXVOGYWxEpT17l0ibXibIDdgRuQYVIf3YRKleNLcEk365GFteiak73g/640?wx_fmt=png&from=appmsg "")  
  
反转过来就是：FLAG{B8o6han}  
#### YWB_Misc_鼠标流量分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVXNa0zP4OVKiaKs1gFPHibib1g6rZxY3FxruXI6XjevY0AfM7VpFqtQibNQ/640?wx_fmt=png&from=appmsg "")  
  
看到鼠标流量分析，像这种设备的题目，键盘流量分析要知道按下了什么键，鼠标流量则要知道鼠标的移动轨迹等已经不用额外的说了。  
  
参考：https://blog.csdn.net/ON_Zero/article/details/130528679  
  
尝试使用
```
tshark -r usb2.pcap -T fields -e usb.capdata | sed '/^\s*$/d' > usbdata.txt
```

  
这种命令去读取，但是并没有读取成功，原因是：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVIGjfXyROHBIMP4iccb8Gzdcg1joDEJVibFInkcewz9faP0ecKCWJ22IQ/640?wx_fmt=png&from=appmsg "")  
  
实际上这个流量包是USB URB的数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV0hkicfvzsgzRzTZic0picWEHZfBHI8F3icZ4rBQrJic3T4z13LSICfT6tpA/640?wx_fmt=png&from=appmsg "")  
  
用开源工具打开，然后分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVRaTibHy29VKbPKicicd0iaa0hJwHKICA72lMD6vBlZYWMIR4M96W3POyLg/640?wx_fmt=png&from=appmsg "")  
  
得到：flag{A3H58FW7EX} W、X 注意一下大小写就行。  
#### 本科组题目 数据包分析1  
  
看到这个题属实笑
```
（对）
```

  
了我一大跳，因为是高职组，没有这道题。  
> ❝  
> 某天设备突然发生停机事件，发现设备存在多次异常行为，请协助调查人员找出设备的相关行为,flag为异常数据包的前面八位,格式为flag{}。  
  
  
流量包如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVJzdDgZhVNibGDHgAz068EAnyUjhVLiayvic1FUj8dPsUO59Uiaeeb7acbQ/640?wx_fmt=png&from=appmsg "")  
  

```
S7COMM
```

  
，其实是个
```
PLC
```

  
控制协议  
  
根据题目描述， 先过滤一下
```
s7comm.header
```

  
  
然后找到停止PLC的流量  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV58gtjwOCeBs4CofuDpiaRjFzdCwq3xgywh0X4BzY3wWaPnhjwUFz31Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVgDGSlTjhSsdQR7QcYabNfuBdXtobvI8CpSWr7iaeT9tm1v3ynR7lAAg/640?wx_fmt=png&from=appmsg "")  
  
确认为关机命令  
  
不过有比较多，Job和Ack_data都有，这个主要是尝试一下，由于不是本科组的我也没碰到这题，具体是4组Hex（8个字符）还是8组Hex（16个字符）我就不得而知了。
```
反正你只需要知道，御网杯就是很抽象的就对啦。
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVzzouUmS76Cf4NsYiaK8DdOw1fWvWgXcuy69h8EVJDTVR2zBb8bxgPDQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVSF1wiblIYReyErlxIT1RNls7oe2xFHKECeC4V2mlEia2MLYvKQXVShibQ/640?wx_fmt=png&from=appmsg "")  
  
类似的原题：https://blog.csdn.net/qq_25954259/article/details/137472040  
## Crypto  
#### ez_classical  
  
这道题的提示是 古典密码  

```
}GQM3iswdqiSSKXFSL{jfpi

```

  
我们得到的是一串逆序的字符，先反转得到正序：  

```
ipfj{LSFXKSSiqdwsi3MQG}

```

  
因为ipfj -> flag 的ASCII字符表顺序，可以考虑将 i - 3、p - 4 、 f - 5、j - 3，这样就能获得flag这四个字符，大概规律是这样，但是如果按照这个规律提交FLAG是错误的。  
  
最终经过10分钟的不断尝试，发现数字3的偏移是最麻烦的。比如i偏移了e，偏移量是4，到了3应该偏移5，但是3-5你会得到ASCII字符表"."  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVdKH29icwPfTD7EsewTyX8sc587IvuOrP8TtamvaSuIOyyVR8ZT7GhVQ/640?wx_fmt=png&from=appmsg "")  
  
这当然不对，也尝试过从ROT等字符表去偏移，但是一律都不对，也想过跳过。  
  
但是没想过，这个数字是应该保留，但是偏移是要计算的，也就是上一位偏移是4、数字3偏移应该是5、下一位是3，但是数字3还要保留不变。  

```
i - 3 = f
p - 4 = l
f - 5 = a
j - 3 = g
{、} 不变、不动后一位（不参与规律）
0-9 不变、动后一位（参与规律、 数字参与变化但保留原值）

```


```
def decrypt(s):
    result = []
    shifts = [3, 4, 5]  # 循环偏移量
    shift_idx = 0

    for c in s:
        if c in &#34;{}0123456789&#34;:
            result.append(c)
            continue

        shift = shifts[shift_idx % 3]

        if c.islower():
            new_c = chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
        elif c.isupper():
            new_c = chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
        else:
            new_c = c

        result.append(new_c)
        shift_idx += 1

    return ''.join(result)


cipher = &#34;ipfj{LSFXKSSiqdwsi3MQG}&#34;
plaintext = decrypt(cipher)
print(&#34;解密结果:&#34;, plaintext)


```

  
解密结果: flag{HNCTFPOdnzrpe3HNC}  
#### YWB_Crypto_01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV30mA4tPIXvriap8Wv4ZBhcLaa82HjX2GD40JBQur08RVtQwPtUYftDA/640?wx_fmt=png&from=appmsg "")  
  
全大写英文字符+数字+=，大概率是Base32吧？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVI19iacw0wWoADEto44jWicnV49C6zaON80FjbL0tsQFLOJD9QvOJwCSg/640?wx_fmt=png&from=appmsg "")  
  
得到的结果为：  

```
公正公正公正友善公正公正民主公正法治法治诚信民主公正和谐公正敬业法治和谐法治富强平等友善敬业公正友善爱国公正敬业法治和谐法治富强平等友善敬业和谐民主和谐文明和
谐和谐法治诚信和谐

```

  
那么还有一个社会主义核心价值观编码，正好我们的脚本也支持。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVTZiasjPQw5I7XWfibI4vrLDfxCWiaU6VPdWZDLAooJMIuDKqy0jfxuIZA/640?wx_fmt=png&from=appmsg "")  

```
from qsnctf import base32_decode, Chinese_socialism_decode

text = &#34;== 此处填写Base32的内容 ==&#34;
b32decode = base32_decode(text)
flag = Chinese_socialism_decode(b32decode)
print(flag)


```

#### YWB_Crypto_02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVRwyXiarNBRwQibjbiaIyibgA8KlvoVPXfgTP212wlkuW3tQ0wckNic1kCbA/640?wx_fmt=png&from=appmsg "")  
  
还蛮抽象的一题，难度不增反降。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVXXqaWPMdjgibBRwlQYZSibF73Eo2yz0NRrCVyMCjVB9jdGJZIibuLRR2Q/640?wx_fmt=png&from=appmsg "")  
  
Base64解码一层  
  
得到的结果：kqfl{829_on87_88up}  
  
大概率是凯撒密码了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVcAeicv7Qho0CqJ2ol8Ln8quzST9vSqvIEtxrem9c66iaCDYPiculZ5krA/640?wx_fmt=png&from=appmsg "")  
  
凯撒密码批量Fuzz，得到结果：flag{829_ji87_88pk}  
#### Find_flag1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVB7q7FmzM9mryuNKR2GlsVz35FswQyy7EQhrESJDhDU50QXrwuXv1Kg/640?wx_fmt=png&from=appmsg "")  
  
其实Js的大概内容不难看出来，是一个混淆的MD5加密、特殊检查的js。  

```
function hm(s) {
    return rh(rstr(str2rstr_utf8(s)));
}

```

  

```
hm(s)
```

  
 就是标准的 MD5(s)，小写输出  
  
先转 UTF-8  
  
然后 MD5  
  
然后 **base64编码**  

```
function ck(s) {
    var a = [119, 104, 102, 120, 117, 108, 48, 75, 81,70,87,73];
    if (s.length == a.length) {
        for (i = 0; i < s.length; i++) {
            if (a[i] - s.charCodeAt(i) != 3)
                return ic = false;
        }
        return ic = true;
    }
    return ic = false;
}


```

  
已知a数组为：[119, 104, 102, 120, 117, 108, 48, 75, 81, 70, 87, 73]  
  
目标：找到字符串s，满足
```
a[i] - s[i].charCodeAt() == 3
```

  
  
等价于  

```
s[i] = String.fromCharCode(a[i] - 3)

```

  
那其实就是凯撒偏移3位，得到：tecuri-HNCTF  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVnKh5pZsU7pmibeFMmZEaLiban5zIKQhPSG7XRfqm2CUjSxfYEcqicyZ5g/640?wx_fmt=png&from=appmsg "")  
## Reverse  
#### re_c5  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVkCNT2y5I6n9t7ExGEhNlSMmRT9om0q9dkoBDDWWekw6aU9h0cVwppQ/640?wx_fmt=png&from=appmsg "")  
  
78行，其实这里一眼ASCII，给ASCII转出即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVrKFBibicB1bLT9SNZeM1dicXkuqKvNbQnjVmmlWtmj38krXQjtlbcdW0w/640?wx_fmt=png&from=appmsg "")  

```
data = [102, 108, 97, 103, 123, 72, 78, 67, 84, 70, 109, 110, 103, 49, 50, 51, 52, 53, 125]

flag = ''.join([chr(i) for i in data])
print(flag)

```

  
flag：flag{HNCTFmng12345}  
#### re_python5  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVQDXWvsPAakEOXib50iaeamv5tUyT9uGv1LBYEUoInPdSictmbES0MoHBA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVQDXWvsPAakEOXib50iaeamv5tUyT9uGv1LBYEUoInPdSictmbES0MoHBA/640?wx_fmt=png&from=appmsg "")  
  
一个pyre.exe，先使用pyinstxtractor反编译为pyc文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVSaibENmToGm2iakO48e8tXZmJHjibDwOcNr26fD9Ik6D3iaWtbjlLkup4g/640?wx_fmt=png&from=appmsg "")  
  
得到1.pyc，使用uncompyle6或decompyle3将pyc转为py  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVgJPviaSoZoJIdLyANYkWP4ESRtq8UGbwKuPrhT3icOcZSxbQTw2iavH2g/640?wx_fmt=png&from=appmsg "")  
  
check函数要求输入一个长度为42的字符串，对于输入的每个字符a[i]，计算 ord(a[i]) * 33 mod b，然后与数组c中对应的值比较。  

```
c = [144, 163, 158, 177, 121, 39, 58, 58, 91, 111, 25, 158, 72, 53, 152, 78, 171, 12, 53, 105, 45, 12, 12, 53, 12, 171, 111, 91, 53, 152, 105, 45, 152, 144, 39, 171, 45, 91, 78, 45, 158, 8]
b = 179
inv = 38  # 33^{-1} mod 179

flag = ''.join(chr((num * inv) % b) for num in c)
print(&#34;解密结果:&#34;, flag)

```

##### 关于模数b的推导：  
  
在加密脚本中，验证逻辑为 
```
ord(a[i]) * 33 % b = c[i]
```

  
，其中 
```
c
```

  
 是已知的密文数组。
```
b
```

  
 的推导需满足以下条件：  
1. 数学约束：  
  
由于 
```
% b
```

  
 运算的结果 
```
c[i]
```

  
 必须小于 
```
b
```

  
，因此 
```
b > max(c)
```

  
。观察 
```
c
```

  
 数组的最大值为 
```
177
```

  
，故 
```
b > 177
```

  
。  
  
1. 首字母特征：  
  
Flag 通常以 
```
f
```

  
 开头（ASCII 值为 
```
102
```

  
），对应密文 
```
c[0] = 144
```

  
，因此有：  
  
102×33≡144(mod b  
)⟹3366≡144(mod b  
)  
  
移项得：  
  
b  
∣(3366−144)=3222  
  
1. 利用次字符特征  
  
第二字符 
```
l
```

  
（ASCII 值 
```
108
```

  
）对应密文 
```
c[1] = 163
```

  
：  
  
108×33≡163(mod b  
)⟹3564≡163(mod b  
)  
  
移项得：  
  
b  
∣(3564−163)=3401  
  
1. 求解公因数：  
  
计算 
```
3222
```

  
 和 
```
3401
```

  
 的最大公约数：  
  
gcd(3222,3401)=179  
  
	证 
```
179 > 177
```

  
 符合条件，因此 
```
b = 179
```

  
。  
##### 乘法逆元inv的推导：  
  
在解密时需解方程 33⋅x  
≡1(modb  
)，其中 
```
x
```

  
 即为逆元 
```
inv
```

  
。推导步骤如下：  
1. 方程转换  
  
	设 33⋅inv  
≡1(mod179)，等价于求解二元一次方程：  
  
	33⋅inv  
+179⋅k  
=1(k  
∈Z)  
1. 拓展欧几里得算法  
  
通过递归求解最大公约数，同时计算系数：  

```
def ext_euclid(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, gcd = ext_euclid(b, a % b)
        return y, x - (a // b) * y, gcd

```

  
代入 
```
a=33, b=179
```

  
：  
  
1. 第一步：
```
179 ÷ 33 = 5
```

  
 余 
```
14
```

  
 → 递归 
```
ext_euclid(33, 14)
```

  
  
1. 第二步：
```
33 ÷ 14 = 2
```

  
 余 
```
5
```

  
 → 递归 
```
ext_euclid(14, 5)
```

  
  
1. 第三步：
```
14 ÷ 5 = 2
```

  
 余 
```
4
```

  
 → 递归 
```
ext_euclid(5, 4)
```

  
  
1. 第四步：
```
5 ÷ 4 = 1
```

  
 余 
```
1
```

  
 → 递归 
```
ext_euclid(4, 1)
```

  
  
1. 第五步：
```
4 ÷ 1 = 4
```

  
 余 
```
0
```

  
 → 返回 
```
(1, 0, 1)
```

  
回溯计算系数：  
  
1=5−1×4=5−1×(14−2×5)=3×5−1×14=3×(33−2×14)−1×14=3×33−7×14=3×33−7×(179−5×33)=38×33−7×179  
  
因此 
```
inv = 38
```

  
.  
  
1. 唯一性验证  
  
	由于 
```
gcd(33, 179) = 1
```

  
，逆元存在且唯一，并通过模运算修正为非负数：  
  
inv  
=(38 mod 179)=38  
  
flag：flag{2889e7a3-0d6b-4cbb-b6e9-04c0f26c9dca}  
## Web  
#### Web - YWB_Web_命令执行  
  
由于Web是赛后复现环境，具体与原题不一致，但是思路是一致的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVcGagUibEuOItyzZmUeDYNhYvCIdRF4UL46Vr61ic9aU30vGpkWvOyaFQ/640?wx_fmt=png&from=appmsg "")  
  
虽然说这题名称是命令执行，但是我理解的更倾向于代码执行漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVmHwbZqoHiaCx8icKibndibBZ8p9ZDL29XHibwpghicsQ1u3rYHtibnIegXe5w/640?wx_fmt=png&from=appmsg "")  
  
环境如上图所示，近期的题目会在7日内上传到青少年CTF平台，感兴趣的师傅可以去青少年CTF平台看看。  
  
那么很明显，过滤了这么多，并且还需要我在解题的时候必须使用base这个关键词。  
  
其实就是指导我们需要使用
```
base64_encode
```

  
或者
```
base64_decode
```

  
嘛  
  
额外考虑一下，服务器是否允许使用 
```
file_get_contents
```

  
1. GET 参数 
```
cmd
```

  
 中必须包含子串 "base"（不区分大小写），但禁止包含黑名单关键词（如 
```
system
```

  
、
```
exec
```

  
、
```
flag
```

  
、
```
php
```

  
、
```
cat
```

  
 等）。  
  
1. 由于文件名 
```
flag.php
```

  
 包含禁止词 
```
flag
```

  
 和 
```
php
```

  
，需避免在 
```
cmd
```

  
 中直接出现这些词。  
  
1. 可通过 Base64 编码/解码绕过过滤。  
  
第一种想法：  

```
http://192.168.186.128/?cmd=$a=base64_decode(%27ZmxhZy5waHA=%27);echo%20base64_encode(file_get_contents($a));

```

  
第二种想法：  

```
http://192.168.20.225:47938/?cmd=print(base64_encode(file_get_contents(base64_decode(%22ZmxhZy5waHA=%22))));

```

  
但是其实不管是第一种想法还是第二种想法，思路都是一样的。先将
```
flag.php
```

  
编码为
```
ZmxhZy5waHA=
```

  
，然后用
```
base64_decode
```

  
去解码，解码后的内容就是flag.php了。  

```
file_get_contents(base64_decode(%22ZmxhZy5waHA=%22))；

```

  
其实上述代码，等效于
```
file_get_contents(&#34;flag.php&#34;)；
```

  
但是由于
```
flag.php
```

  
被过滤了，所以只能如此。  
  
如果要1:1还原，则将flag放置在
```
/tmp/flag.cisp
```

  
中即可。  
  
但是，你不觉得奇怪吗？？cisp??  
#### Web - YWB_Web_IP绕过登陆  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV0rXIm7vftVkHsnE7xOk6NLickUO45yn1lyhiahST6S2WFeDW75hQicHLg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVLZBBKXkHv0ZNK38AmoqjAcxRGibtPaRbndgxzmLbTEXx3ia6IdE3VXicw/640?wx_fmt=png&from=appmsg "")  
  
题目附件如上所示  

```
$cip = $_SERVER['HTTP_CLIENT_IP'];
if ($cip != &#34;1.2.3.4&#34;) {
    echo &#34;非法IP地址，只有1.2.3.4才能访问！&#34;;
    exit();
}

```

  
这里判断了HTTP_CLIENT_IP的传入是否是1.2.3.4  

```
$username = $_POST['username'];
$password = $_POST['password'];

if ($username === &#34;admin&#34; && $password === &#34;admin123&#34;) {
    echo &#34;登录成功！<br>&#34;;
    $flag = file_get_contents(&#34;../../../../flag.txt&#34;);
    echo $flag;
} else {
    echo &#34;用户名或密码错误！&#34;;
}
?> 

```

  
用户名为
```
admin
```

  
，密码为
```
admin123
```

  
  
那么我们使用浏览器插件即可。  
  
使用
```
X-Forwarded-For
```

  
插件，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVqY4BsWicTq7jfeIdD6nqBdIpKB6OxhQQUZ18dxy34DY0jibd0IzwDqRA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVKhmmzWE4ycUcgQeiaz2EpfmlZLwvibqRiaR4Cp5S8lKOFZzub1Z9RVicUw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVo2y57N699MaUyvEyQL9yicHbro8OZtqbvLoFu7Qy3NBJUTibnOrBY4zA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVbQGK5bsgpib8TSccrrIe4a1H511atzykjFIw2NneLScH5tSdmjbpybA/640?wx_fmt=png&from=appmsg "")  
  
成功拿到FLAG  
  
记得用完要关闭这个插件哦  
## 应急响应  
#### 1.应急响应靶场  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVqiavHz6jiaxkIfibY1ZmibneNTNNGkYbr5sjbVibI9wQejP7KAhf1icLibsmA/640?wx_fmt=png&from=appmsg "")  
  
（由于是比赛环境，没有准备太详细的wp）  
  
**1.请你获取攻击者的 webshell 文件（提交如下例：abc.asp ）：**  
  
服务器中有一个小皮面板，将www目录拖动到本机桌面，防护软件会提醒一个叫driver.php的文件，这个文件就是后门文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVzcmh9zGoD0Jarejb7B4KN7kDISVniawEjASibJepDxgicTUqiceWiaZicYFw/640?wx_fmt=png&from=appmsg "")  
  
**2.请你获取攻击者的 webshell 密码：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV2YbSVb4b5rjVJ7bCM8v9RyBE29968GzkzRCb6nINM34LdAYgH7S6ibQ/640?wx_fmt=png&from=appmsg "")  
  
打开后查看，密码为hack1234  
  
**3.请你获取攻击者的隐藏用户名：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV8fJFttyibLyZf4Dpw79O3Xo5icG4vQxeqk35V4JVFjSpSwbcgfxic2QmA/640?wx_fmt=png&from=appmsg "")  
  
**4.根据内网信息排查，发现攻击者投放了恶意信息收集程序是并且定期执行，排查清理恶意程序并且获取恶意信息收集软件名称（提交如下例：shell）：**  
  
其实这个点比较坑，因为开机启动后如果没及时注意Windows Defender就会错过。  
  
开机启动后，被Windows安全中心删除的，在日志里查看即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvV1AILkPQUfa9JiavqfFzLSEPQdB3TBquoH0iatQribDFzzLEBqvxjOMN9w/640?wx_fmt=png&from=appmsg "")  
  
**5.请你梳理攻击链路，分析攻击者是如何入侵攻击的（攻击方式英文字母全小写提交如下例：xxe攻击）：**  
  
这题其实没绷住，www中的内容是一个phpmyadmin，然后留了个shell、3389的服务的bat，隐藏用户、sql弱口令。这道题就有一种本来应该是选择题的或者主观题，给你留了个死答案的填空题。  
  
尝试了：弱口令、弱口令攻击、弱口令漏洞、文件上传、文件上传攻击、文件上传漏洞、弱密码**、等。但是根据log文件属实是没看到哪里有这类的攻击，在ftp的log中，能够看到ftp连接后有木马投放的操作...所以答案 ↓  
  
答案：ftp攻击。  
  
抽象吧？你整个ftp弱口令我都...  
  
2025年，ftp在御网杯的带领下，成功变成一种攻击方式。  
  
你但凡是问个...对什么进行的攻击、FTP暴力破解，这答案也就合适了。（懒得喷，此处省略一万字）  
  
**6.请你恢复被病毒感染的文件获取到敏感信息flag：**  
  
使用KasperskyRakhniDecryptor工具，修复了flag.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVttUmk5mTqFBHXu5r1Rj2JkMzgM3mj7ibZiaQq70Oiaj1RLPvcyEutv3zA/640?wx_fmt=png&from=appmsg "")  
  
**7.请你对恶意样本（.bat文件）进行分析获取恶意域名：**  
  
诶？奇怪不奇怪？刚刚的exe这会儿又来个bat？  
  
查看资源管理器的历史记录，找到一个bat文件，提交其中的域名即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVGmZklacaibDjRyTwp9nMjFH02uvcL2YYF4A23yjQBsVcrv7CGM5Pv7Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/98w89icYGQfc96SwZKF6hEasKqibSh0NvVPhPSoYC3NkxNhlulibKhKuxNY0w72yVpPYm73C2covPx7Ha7fWKStmA/640?wx_fmt=png&from=appmsg "")  
## 实网渗透  
  
渗透靶机一: 全是蜜罐罐，懒得看了。提示说密码爆破，但是看着
```
ssh、海康威视、邮箱管理系统
```

  
都像是蜜罐，就懒得看了。毕竟
```
HFish
```

  
都出来了，没意思。  
  
渗透靶机二：第一问是
```
dirsearch
```

  
的
```
flag.txt
```

  
（虽然我是按照往年惯例直接访问的，但是非要个原因那就
```
dirsearch
```

  
一下吧），后面是一个
```
MS17-010
```

  
，拿下即可。  
  
  

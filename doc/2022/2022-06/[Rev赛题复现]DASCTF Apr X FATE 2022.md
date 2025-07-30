#  [Rev赛题复现]DASCTF Apr X FATE 2022   
t0hka1  看雪学苑   2022-06-25 18:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8GGERW94gZr6hHM6vpgyCqRs4aTQeSzCNMibxZfCloib4Kw1w28x7icuBV0SOerL4A26kE1wG0kDL5Hw/640?wx_fmt=jpeg "")  
  
本文为看雪论坛精华文章看雪论坛作者ID：t0hka1  
  
  
总共4题，贴了3题，还有一道go逆向的直接看这位师傅的吧。（  
https://bbs.pediy.com/thread-273162.htm）  
  
## Crackme  
  
   
  
几个关键点：mfc逆向，win32 加密api的识别，  
ZwSetInformationThread反调试。  
  
  
看程序图标是个mfc的程序，先打开看看，随便输入一点东西，看到弹窗弹出：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ88tUVKvzuiaA4pFugXJbEe2dtP8Wvdr5dZKU6Th36vGKqnRcAY9HTQzg/640?wx_fmt=png "")  
  
直接拖进ida搜索Wrong!!!字符串，借此通过查看引用跳转到主函数。  
  
   
  
先简单的修复一下变量名：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8wl5mJDgnxSeCibngssNtcic3VoiazgzypV5Ca4YpTyxxjt4gY3ctYGcgg/640?wx_fmt=png "")  
  
大概可以看到key的前4位经过一次sub_403510，后4位也经过一次sub_403510，整个key8位又经过一次sub_403510。  
  
   
  
随后进入sub_403510函数看一看，看到有一堆为win32 加密api的函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8QtZsQYWAUKPSv3wYtJW0Zf6h4nZayFj9I9ZGHAzU22dyYTNOgOxH6Q/640?wx_fmt=png "")  
  
那就对照着MSDN一个个函数查阅一下：  
  
   
  
CryptAcquireContext 函数用于获取特定加密服务提供程序 （CSP） 中特定密钥容器的句柄。此返回的句柄用于调用使用所选 CSP 的 CryptoAPI 函数。  
```
BOOL CryptAcquireContextA(
[out] HCRYPTPROV *phProv,
[in]  LPCSTR     szContainer,
[in]  LPCSTR     szProvider,
[in]  DWORD      dwProvType,
[in]  DWORD      dwFlags
);
```  
  
  
  
CryptCreateHash 函数启动数据流的哈希。它创建加密服务提供程序 （CSP） 哈希对象的句柄并将其返回给调用应用程序。此句柄用于对 CryptHashData 和 CryptHashSessionKey 的后续调用，以哈希会话密钥和其他数据流。  
```
BOOL CryptCreateHash(
[in]  HCRYPTPROV hProv,
[in]  ALG_ID     Algid,
[in]  HCRYPTKEY  hKey,
[in]  DWORD      dwFlags,
[out] HCRYPTHASH *phHash
);
```  
  
  
  
注意这里Algid是标识要使用的哈希算法的参数，通过不同的值的传入选择不同的hash算法，可查下面的链接：  
ALG_ID (Wincrypt.h) - Win32 apps | Microsoft Docs  
（  
https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8iaysk9pbXU70EHNFxCZR919fibE64lpgyflMsmS79viaZQJ19GrQpELicg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8eRpicJ4oLwIL4ibYlI0mA2NRFcuR0ahQ37U9hgXt2zPKlhnlZSCHLYeQ/640?wx_fmt=png "")  
  
  
CryptHashData 函数将数据添加到指定的哈希对象。此函数和CryptHashSessionKey  
可以多次调用，以计算长数据流或不连续数据流的哈希值。  
```
BOOL CryptHashData(
[in] HCRYPTHASH hHash,
[in] const BYTE *pbData,
[in] DWORD      dwDataLen,
[in] DWORD      dwFlags
);
```  
  
  
  
CryptGetHashParam   
函数检索控制哈希对象操作的数据。可以使用此函数检索实际的哈希值。  
```
BOOL CryptGetHashParam(
[in]      HCRYPTHASH hHash,
[in]      DWORD      dwParam,
[out]     BYTE       *pbData,
[in, out] DWORD      *pdwDataLen,
[in]      DWORD      dwFlags
);
```  
  
  
  
CryptEncrypt  
 函数对数据进行加密。用于加密数据的算法由 CSP 模块持有的密钥指定，并由 hKey 参数引用。  
```
BOOL CryptEncrypt(
[in]      HCRYPTKEY  hKey,
[in]      HCRYPTHASH hHash,
[in]      BOOL       Final,
[in]      DWORD      dwFlags,
[in, out] BYTE       *pbData,
[in, out] DWORD      *pdwDataLen,
[in]      DWORD      dwBufLen
);
```  
  
  
程序大概的逻辑就是这样：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8MnJJBicoyNVAf6OLXnDX2JGUxQdaicxibnaMybSicbg4uoVVhl9icac8rjQ/640?wx_fmt=png "")  
  
然后我们就通过动调去拿数据，这里有两种方式，一种是通过ida patch反调试函数的方式，一种是通过od 的sharp od插件直接绕过。  
  
### 绕反调试方法一：先用ida绕过反调试  
  
  
对比各种反调试和去IAT表找导入函数没有找到，后面在strings界面可以发现ZwSetInformationThread反调试的特征ZwSetInformationThread - CTF Wiki (ctf-wiki.org)（  
https://ctf-wiki.org/reverse/windows/anti-debug/zwsetinformationthread/  
）  
  
   
  
ZwSetInformationThread通过为线程设置 ThreadHideFromDebugger，可以禁止线程产生调试事件。  
  
  
绕过: ZwSetInformationThread 函数的第 2 个参数为 ThreadHideFromDebugger，其值为 0x11。调试执行到该函数时，若发现第 2 个参数值为 0x11，跳过或者将 0x11 修改为其他值即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8FCasXa4zORKHDWDna3PFuibG0vBSw0weLzudox9wM9VDApiaQ7023NBw/640?wx_fmt=png "")  
  
看来是自己实现调用dll导入的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8E6uuzLMevgRmvUUZCbfr3Q8QKszaPJm6zH8gTeiaiavicSR31eGhwIibMw/640?wx_fmt=png "")  
  
类似于这种写法：![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8FjqckDk93UQ7z4VT9RicP7KLQDFq4GWfiavR6MEtEiaxYRJdWRRgIv9kg/640?wx_fmt=png "")  
  
  
我们可以先在调用处下一个断点，跑起来之后再修改patch 0x11 改掉，我这里patch成了0x9。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ80SeIv19bLLwO9zg1AibPDgliayXiaccOIMdDSQVtEpatcTweF7CmF0XXA/640?wx_fmt=png "")  
  
然后继续下断点拿密文。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8uPyUYibMXZH1yHazIHhH7NcQNxoaEDrsicFDCmwFkxzASx2T1ic11DR6A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ85XU7gZ57nMTCa5qXNXIkbDO6Lpia6H5cTkic0u7oQF5PUaDbBRDCCdQA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8kfrppV7Id8iayGHQxuDE2yjtV3CASKI2wvOMniciaMh4EjeQtuetF6owg/640?wx_fmt=png "")  
  
然后再扔到md5解密网站解密。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8w9JUvaAZlvIcZJqPSqsBETdUmkqVqec04UICzHypxscRnBorgwyLZw/640?wx_fmt=png "")  
  
类似的拿到sha1解密后的key后四位 https://crackstation.net/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8pHowa7Q2sCoMYFCNc74UGshibtsfEWkWSmXx5klGJNfrtBaVCYdstCA/640?wx_fmt=png "")  
  
key:NocTuRne  
  
   
  
md5(key):C0804C74E05B4C7440AC4D7480954C74  
###   
### 绕反调试方法二：OD odsharp插件直接绕  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ85AcpWOxHAkBibd0CvibIvXbTRKXozGeWBcoYNYicDX7iciaLalexU6dOgfw/640?wx_fmt=png "")  
  
之后就是模拟调用win32 的aes解密api来解密的过程了。  
```
#include <Windows.h>
#include <stdio.h>
#include <wincrypt.h>

int main(){
    BYTE pbData[] = {0x5c,0x53,0xa4,0xa4,0x1d,0x52,0x43,0x7a,0x9f,0xa1,0xe9,0xc2,0x6c,0xa5,0x90,0x90,0x0};  //key_buf
    BYTE flag_encrypt[] = {0x5B, 0x9C, 0xEE, 0xB2, 0x3B, 0xB7, 0xD7, 0x34, 0xF3, 0x1B, 0x75, 0x14, 0xC6, 0xB2, 0x1F, 0xE8, 0xDE, 0x33, 0x44, 0x74, 0x75, 0x1B, 0x47, 0x6A, 0xD4, 0x37, 0x51, 0x88, 0xFC, 0x67, 0xE6, 0x60, 0xDA, 0x0D, 0x58, 0x07, 0x81, 0x43, 0x53, 0xEA, 0x7B, 0x52, 0x85, 0x6C, 0x86, 0x65, 0xAF, 0xB4,0x0};
    DWORD dwDataLen = 0x10;
    DWORD ddwDataLen;
    DWORD* pdwDataLen = &ddwDataLen;
    *pdwDataLen = 0x20;


    BOOL v6; // [esp+4h] [ebp-18h]
    HCRYPTKEY phKey; // [esp+Ch] [ebp-10h] BYREF
    HCRYPTPROV phProv; // [esp+10h] [ebp-Ch] BYREF
    HCRYPTHASH phHash; // [esp+14h] [ebp-8h] BYREF

    phProv = 0;
    phHash = 0;
    phKey = 0;
    v6 = CryptAcquireContextA(&phProv, 0, 0, 0x18u, 0xF0000000);
    if (v6)
    {
        v6 = CryptCreateHash(phProv, 0x8003u, 0, 0, &phHash);
        if (v6)
        {
            v6 = CryptHashData(phHash, pbData, dwDataLen, 0);
            if (v6)
            {
                v6 = CryptDeriveKey(phProv, 0x660Eu, phHash, 1u, &phKey);// key的md5值再生成aes密钥
                if (v6)
                    v6 = CryptDecrypt(phKey, 0, 1, 0, flag_encrypt, pdwDataLen);
                    printf("%s", flag_encrypt);
            }
        }
    }
    if (phKey)
        CryptDestroyKey(phKey);
    if (phHash)
        CryptDestroyHash(phHash);
    if (phProv)
        CryptReleaseContext(phProv, 0);
    return v6;
}
```  
  
  
  
拿到flag！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8gw6MbGfryUKTxk3GXficuWBy5uIkDicpHEEFVy7fTpzxRzibAqwcNVFrw/640?wx_fmt=png "")  
###   
### 补充方法：Hook Windows API 求解  
  
  
另外经mas0n师傅补充，附上frida来hook求解的方法。  
```
  var baseAddr = Process.findModuleByName('Crackme_1.exe');

// input 32 length flag, e.g. 11111111111111111111111111111111
// key: NocTuRne
// frida attach -p 48964 -l agent\hook_win.js


// memcmp
var hookAddr = ptr(0x0109D4BC);
Interceptor.attach(hookAddr, {
    onEnter: function(args) {
        let Buf1 = args[0];
        let Buf2 = args[1];
        let Size = args[2];
        console.log("-----\n[Size]\n", Size);
        let size = Size.toInt32();
        console.log("-----\n[Buf1]\n", Buf1.readByteArray(size));
        console.log("-----\n[Buf2]\n", Buf2.readByteArray(size));
        console.log("---------------------------");
    },
    onLeave: function(arg) {
        return arg;
    }
})

var libAddr = Process.findModuleByName('ADVAPI32.dll');
var fn_CryptEncrypt = libAddr.getExportByName("CryptEncrypt");
var fn_CryptDecrypt = libAddr.getExportByName("CryptDecrypt");

var flag = null;
Interceptor.replace(fn_CryptEncrypt, fn_CryptDecrypt);
Interceptor.attach(fn_CryptDecrypt, {
    onEnter: function(args) {
        args[4].writeByteArray([0x5b,0x9c,0xee,0xb2,0x3b,0xb7,0xd7,0x34,0xf3,0x1b,0x75,0x14,0xc6,0xb2,0x1f,0xe8,0xde,0x33,0x44,0x74,0x75,0x1b,0x47,0x6a,0xd4,0x37,0x51,0x88,0xfc,0x67,0xe6,0x60,0xda,0x0d,0x58,0x07,0x81,0x43,0x53,0xea,0x7b,0x52,0x85,0x6c,0x86,0x65,0xaf,0xb4]);
        args[5].writeInt(0x40);
        flag = args[4];
        console.log("hook fn_CryptDecrypt");
        return args;
    },
    onLeave: function(arg) {
        console.log(flag.readCString());
        return arg;
    }
})
```  
##   
##   
## 奇怪的交易  
  
  
拖进ida里发现经过upx加壳，  
直接upx -d脱壳。  
  
   
  
接着再使用pyinstxtractor解包得到一堆文件(比较坑的地方是本地python环境必须与源程序的python环境相同才能解包PYZ-00.pyz)，下面是彻底解包后的几个关键的文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8Mlqwng2GEfb20WTBKrOu8Sq61GGgiapEx1EFJPwOubvADSBVesqgGkg/640?wx_fmt=png "")  
  
奇怪的交易.pyc文件内容如下：  
  
  
python反编译 - 在线工具 (tool.lu)（  
https://tool.lu/pyc/  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ85pECeGHsLopw8RzXvYWPuE8AqysiaDiaHtP20V7krKD3DbCtlRcsL33g/640?wx_fmt=png "")  
  
这  
样其实逻辑很明显还是有问题的，题目特意用的Python3.10版本，导致反编译结果会不正确。  
  
   
  
通过pycdump可以dump出opcode，对比进行变量名和代码逻辑的修复。  
  
   
  
可以参考下面的文章：  
  
   
  
Python字节码文档 Python字节码详解(介绍了Python的特有类型以及遍历等操作)（  
https://blog.csdn.net/weixin_46263782/article/details/120930191  
）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8wF3sQzic0xiaJgzdAgSFwXsFvaVOsGYcTvOZavwWZyUI2DOz6ZGq2ung/640?wx_fmt=jpeg "")  
  
  
修复后的 奇怪的交易.py  
```
from cup import *
from libnum import *

if __name__ == '__main__':
    flag = input('请输入flag')
    pub_key = [
        0x649EE967E7916A825CC9FD3320BEABF263BEAC68C080F52824A0F521EDB6B78577EC52BF1C9E78F4BB71192F9A23F1A17AA76E5979E4D953329D3CA65FB4A71DA57412B59DFD6AEDF0191C5555D3E5F582B81B5E6B23163E9889204A81AFFDF119FE25C92F4ED59BD3285BCD7AAE14824240D2E33C5A97848F4EB7AAC203DE6330D2B4D8FF61691544FBECD120F99A157B3D2F58FA51B2887A9D06CA383C44D071314A12B17928B96F03A06E959A5AFEFA0183664F52CD32B9FC72A04B45913FCB2D5D2D3A415A14F611CF1EAC2D6C785142A8E9CC41B67A6CD85001B06EDB8CA767D367E56E0AE651491BF8A8C17A38A1835DB9E4A9292B1D86D5776C98CC25,
        0x647327833ACFEF1F9C83E74E171FC300FA347D4A6769476C33DA82C95120ACB38B62B33D429206FE6E9BB0BB7AB748A1036971BEA36EC47130B749C1C9FF6FE03D0F7D9FC5346EB0E575BDFA6C530AA57CD676894FC080D2DD049AB59625F4B9C78BCFD95CDCD2793E440E26E189D251121CB6EB177FEDB596409034E8B0C5BBD9BD9342235DBB226C9170EFE347FF0FD2CFF9A1F7B647CC83E4D8F005FD7125A89251C768AFE70BDD54B88116814D5030F499BCAC4673CCCC342FB4B6AC58EA5A64546DC25912B6C430529F6A7F449FD96536DE269D1A1B015A4AC6B6E46EE19DCE8143726A6503E290E4BAE6BD78319B5878981F6CFFDB3B818209341FD68B]
    m = libnum.s2n(flag)
    c = str(pow(m, pub_key[1], pub_key[0]))  # 极长的一串东西
    store = []
    cipher = [3532577106, 1472742623, 3642468664, 4193500461, 2398676029, 617653972, 1474514999, 1471783658, 1012864704,
              3615627536, 993855884, 438456717, 3358938551, 3906991208, 198959101, 3317190635, 3656923078, 613157871,
              2398768861, 97286225, 2336972940, 1471645170, 3233163154, 583597118, 2863776301, 3183067750, 1384330715,
              2929694742, 3522431804, 2181488067, 3303062236, 3825712422, 145643141, 2148976293, 2940910035, 506798154,
              994590281, 2231904779, 3389770074, 2814269052, 1105937096, 1789727804, 3757028753, 2469686072, 1162286478,
              680814033, 2934024098, 2162521262, 4048876895, 2121620700, 4240287315, 2391811140, 3396611602, 3091349617,
              3031523010, 2486958601, 3164065171, 1285603712, 798920280, 2337813135, 4186055520, 3523024366, 1077514121,
              1436444106, 2731983230, 1507202797, 500756149, 198754565, 2382448647, 880454148, 1970517398, 3217485349,
              1161840191, 560498076, 1782600856, 2643721918, 1285196205, 788797746, 1195724574, 4061612551, 103427523,
              2502688387, 4147162188, 617564657, 978211984, 1781482121, 2205798970, 3939973102, 3826603515, 659557668,
              2582884932, 1561884856, 2217488804, 1189296962, 169145316, 2781742156, 1323893433, 824667876, 408202876,
              3759637634, 4094868412, 1508996065, 162419237, 3732146944, 3083560189, 3955940127, 2393776934, 2470191468,
              3620861513, 481927014, 2756226070, 3154651143, 1261069441, 2063238535, 2222237213, 101459755, 3159774417,
              1721190841, 1078395785, 176506553, 3552913423, 1566142515, 1938949000, 1499289517, 3315102456, 829714860,
              3843359394, 952932374, 1283577465, 2045007203, 3957761944, 3767891405, 2917089623, 3296133521, 482297421,
              1734231412, 3670478932, 2575334979, 2827842737, 3413631016, 1533519803, 4008428470, 3890643173, 272960248,
              317508587, 3299937500, 2440520601, 27470488, 1666674386, 1737927609, 750987808, 2385923471, 2694339191,
              562925334, 2206035395]

    i = 0
    # rsa 生成的密文遍历加密
    while i < len(c):  # i<155
        index = 0
        for ii in c[i:i + 4]:
            index = (index << 8) + ord(ii)
        store.append(index)

        i += 4
        if not i < len(c):
            key = [54, 54, 54, 54]
            store_len = len(store)
            res = encrypt(store_len, store, key)
            if store == cipher:
                print('You are right!')
                input('')
                quit()
            else:
                print('Why not drink a cup of tea and have a rest?')

        continue
```  
  
  
  
发现从cup包导入了一个encrypt函数。  
  
   
  
以下是对经key加密后的cup.pyc.encrypted的解密脚本  
  
[原创]Python逆向——Pyinstaller逆向-软件逆向-看雪论坛-安全社区|安全招聘|bbs.pediy.com  
  
（  
https://bbs.pediy.com/thread-271253.htm  
）  
```
      #!/usr/bin/env python3
import tinyaes
import zlib

CRYPT_BLOCK_SIZE = 16

# 从crypt_key.pyc获取key，也可自行反编译获取
key = bytes('0000000000000tea', 'utf-8')

inf = open('cup.pyc.encrypted', 'rb') # 打开加密文件
outf = open('output.pyc', 'wb') # 输出文件

# 按加密块大小进行读取
iv = inf.read(CRYPT_BLOCK_SIZE)

cipher = tinyaes.AES(key, iv)

# 解密
plaintext = zlib.decompress(cipher.CTR_xcrypt_buffer(inf.read()))

# 补pyc头(最后自己补也行)
outf.write(b'\x6f\x0d\x0d\x0a\0\0\0\0\0\0\0\0\0\0\0\0')

# 写入解密数据
outf.write(plaintext)

inf.close()
outf.close()
```  
  
  
解密得到发现是一个python实现的xxtea加密，最基础的版本，甚至连key都没变。  
  
   
  
python实现xxtea加解密参考链接  
  
（  
https://www.icode9.com/content-1-1126418.html  
）  
  
```
#!/usr/bin/env python
# visit https://tool.lu/pyc/ for more information
import libnum
from ctypes import *

def MX(z, y, total, key, p, e):
    temp1 = (z.value >> 5 ^ y.value << 2) + (y.value >> 3 ^ z.value << 4)
    temp2 = (total.value ^ y.value) + (key[p & 3 ^ e.value] ^ z.value)
    return c_uint32(temp1 ^ temp2)


def encrypt(ᘗ, ᘖ, ᘘ):
    ᘜ = 0x9E3779B9L
    ᘛ = 6 + 52 // ᘗ
    total = c_uint32(0)
    ᘔ = c_uint32(ᘖ[ᘗ - 1])
    ᘕ = c_uint32(0)
    if ᘛ > 0:
        total.value += ᘜ
        ᘕ.value = total.value >> 2 & 3
        ᘚ = c_uint32(ᘖ[0])
        ᘖ[ᘗ - 1] = c_uint32(ᘖ[ᘗ - 1] + MX(ᘔ, ᘚ, total, ᘘ, ᘗ - 1, ᘕ).value).value
        ᘔ.value = ᘖ[ᘗ - 1]
        ᘛ -= 1
        if not ᘛ > 0:
            return ᘖ
```  
  
  
先解密xxtea得到结果rsa加密的密文c。  
```
from ctypes import *


def MX(z, y, total, key, p, e):
    temp1 = (z.value>>5 ^ y.value<<2) + (y.value>>3 ^ z.value<<4)
    temp2 = (total.value ^ y.value) + (key[(p&3) ^ e.value] ^ z.value)

    return c_uint32(temp1 ^ temp2)


def encrypt(n, v, key):
    delta = 0x9e3779b9
    rounds = 6 + 52//n

    total = c_uint32(0)
    z = c_uint32(v[n-1])
    e = c_uint32(0)

    while rounds > 0:
        total.value += delta 
        e.value = (total.value >> 2) & 3
        for p in range(n-1):
            y = c_uint32(v[p+1])
            v[p] = c_uint32(v[p] + MX(z,y,total,key,p,e).value).value
            z.value = v[p]
        y = c_uint32(v[0])
        v[n-1] = c_uint32(v[n-1] + MX(z,y,total,key,n-1,e).value).value
        z.value = v[n-1]
        rounds -= 1

    return v


def decrypt(n, v, key):
    delta = 0x9E3779B9
    rounds = 6 + 52//n

    total = c_uint32(rounds * delta)
    y = c_uint32(v[0])
    e = c_uint32(0)

    while rounds > 0:
        e.value = (total.value >> 2) & 3
        for p in range(n-1, 0, -1):
            z = c_uint32(v[p-1])
            v[p] = c_uint32((v[p] - MX(z,y,total,key,p,e).value)).value
            y.value = v[p]
        z = c_uint32(v[n-1]) 
        v[0] = c_uint32(v[0] - MX(z,y,total,key,0,e).value).value
        y.value = v[0] 
        total.value -= delta
        rounds -= 1

    return v


#  test 
if __name__ == "__main__":
    # 该算法中每次可加密不只64bit的数据，并且加密的轮数由加密数据长度决定

    k = [54, 54, 54, 54]
    n = 155

    res=[3532577106, 1472742623, 3642468664, 4193500461, 2398676029, 617653972, 1474514999, 1471783658, 1012864704, 3615627536, 993855884, 438456717, 3358938551, 3906991208, 198959101, 3317190635, 3656923078, 613157871, 2398768861, 97286225, 2336972940, 1471645170, 3233163154, 583597118, 2863776301, 3183067750, 1384330715, 2929694742, 3522431804, 2181488067, 3303062236, 3825712422, 145643141, 2148976293, 2940910035, 506798154, 994590281, 2231904779, 3389770074, 2814269052, 1105937096, 1789727804, 3757028753, 2469686072, 1162286478, 680814033, 2934024098, 2162521262, 4048876895, 2121620700, 4240287315, 2391811140, 3396611602, 3091349617, 3031523010, 2486958601, 3164065171, 1285603712, 798920280, 2337813135, 4186055520, 3523024366, 1077514121, 1436444106, 2731983230, 1507202797, 500756149, 198754565, 2382448647, 880454148, 1970517398, 3217485349, 1161840191, 560498076, 1782600856, 2643721918, 1285196205, 788797746, 1195724574, 4061612551, 103427523, 2502688387, 4147162188, 617564657, 978211984, 1781482121, 2205798970, 3939973102, 3826603515, 659557668, 2582884932, 1561884856, 2217488804, 1189296962, 169145316, 2781742156, 1323893433, 824667876, 408202876, 3759637634, 4094868412, 1508996065, 162419237, 3732146944, 3083560189, 3955940127, 2393776934, 2470191468, 3620861513, 481927014, 2756226070, 3154651143, 1261069441, 2063238535, 2222237213, 101459755, 3159774417, 1721190841, 1078395785, 176506553, 3552913423, 1566142515, 1938949000, 1499289517, 3315102456, 829714860, 3843359394, 952932374, 1283577465, 2045007203, 3957761944, 3767891405, 2917089623, 3296133521, 482297421, 1734231412, 3670478932, 2575334979, 2827842737, 3413631016, 1533519803, 4008428470, 3890643173, 272960248, 317508587, 3299937500, 2440520601, 27470488, 1666674386, 1737927609, 750987808, 2385923471, 2694339191, 562925334, 2206035395]

    res = decrypt(n, res, k)

    # print(res)
    for i in res:
        print(chr(i>>24),end="")
        print(chr((i&0x00ff0000)>>16),end="")
        print(chr((i&0x0000ff00)>>8),end="")
        print(chr(i&0x000000ff),end="")

 #c= 10610336534759505889607399322387179316771488492347274741918862678692508953185876570981227584004676580623553664818853686933004290078153620168054665086468417541382824708104480882577200529822968531743002301934310349005341104696887943182074473298650903541494918266823037984054778903666406545980557074219162536057146090758158128189406073809226361445046225524917089434897957301396534515964547462425719205819342172669899546965221084098690893672595962129879041507903210851706793788311452973769358455761907303633956322972510500253009083922781934406731633755418753858930476576720874219359466503538931371444470303193503733920039
```  
  
  
接下来是一个低解密指数 rsa 就可以得到flag了。  
```
import gmpy2
from Crypto.PublicKey import RSA
import ContinuedFractions, Arithmetic
from Crypto.Util.number import long_to_bytes


def wiener_hack(e, n):
    # firstly git clone https://github.com/pablocelayes/rsa-wiener-attack.git !
    frac = ContinuedFractions.rational_to_contfrac(e, n)
    convergents = ContinuedFractions.convergents_from_contfrac(frac)
    for (k, d) in convergents:
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            discr = s * s - 4 * n
            if (discr >= 0):
                t = Arithmetic.is_perfect_square(discr)
                if t != -1 and (s + t) % 2 == 0:
                    return d
    return False


def main():
    pub_key = [
    0x649EE967E7916A825CC9FD3320BEABF263BEAC68C080F52824A0F521EDB6B78577EC52BF1C9E78F4BB71192F9A23F1A17AA76E5979E4D953329D3CA65FB4A71DA57412B59DFD6AEDF0191C5555D3E5F582B81B5E6B23163E9889204A81AFFDF119FE25C92F4ED59BD3285BCD7AAE14824240D2E33C5A97848F4EB7AAC203DE6330D2B4D8FF61691544FBECD120F99A157B3D2F58FA51B2887A9D06CA383C44D071314A12B17928B96F03A06E959A5AFEFA0183664F52CD32B9FC72A04B45913FCB2D5D2D3A415A14F611CF1EAC2D6C785142A8E9CC41B67A6CD85001B06EDB8CA767D367E56E0AE651491BF8A8C17A38A1835DB9E4A9292B1D86D5776C98CC25,
    0x647327833ACFEF1F9C83E74E171FC300FA347D4A6769476C33DA82C95120ACB38B62B33D429206FE6E9BB0BB7AB748A1036971BEA36EC47130B749C1C9FF6FE03D0F7D9FC5346EB0E575BDFA6C530AA57CD676894FC080D2DD049AB59625F4B9C78BCFD95CDCD2793E440E26E189D251121CB6EB177FEDB596409034E8B0C5BBD9BD9342235DBB226C9170EFE347FF0FD2CFF9A1F7B647CC83E4D8F005FD7125A89251C768AFE70BDD54B88116814D5030F499BCAC4673CCCC342FB4B6AC58EA5A64546DC25912B6C430529F6A7F449FD96536DE269D1A1B015A4AC6B6E46EE19DCE8143726A6503E290E4BAE6BD78319B5878981F6CFFDB3B818209341FD68B]
    # 0->n,1->e

    n = pub_key[0]
    e = pub_key[1]
    c = 10610336534759505889607399322387179316771488492347274741918862678692508953185876570981227584004676580623553664818853686933004290078153620168054665086468417541382824708104480882577200529822968531743002301934310349005341104696887943182074473298650903541494918266823037984054778903666406545980557074219162536057146090758158128189406073809226361445046225524917089434897957301396534515964547462425719205819342172669899546965221084098690893672595962129879041507903210851706793788311452973769358455761907303633956322972510500253009083922781934406731633755418753858930476576720874219359466503538931371444470303193503733920039
    d = wiener_hack(e, n)
    m = pow(c, d, n)
    print(long_to_bytes(m)) #  flag{You_Need_Some_Tea}


if __name__ == "__main__":
    main()
```  
##   
##   
## FakePica  
  
  
先用BlackDex脱个壳，然后把解密后的dex文件pull到自己的电脑上后拖进jadx。  
  
   
  
看到主要是一个登录逻辑：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8ypNKUKhlXIe4tc5B6tX6rTic1tmduh0hab7rMvtEghxaY8uibe1aw0JQ/640?wx_fmt=png "")  
  
   
  
题目逻辑非常简单，可以直接Aes解密，但由于主类里有了解密的方法，肯定是要选择更加有意思的方法来玩玩，我这里的做法是直接采用frida来hook。  
  
   
  
先hook绕过认证：  
```
console.log("Script loaded successfully");
Java.perform(function x(){
    console.log("inside java perform function");
    //定位类
    var my_class = Java.use("com.pica.picapica.MainActivity");
    console.log("Java.use Successfully");
    my_class.check.implementation = function(x,y){
        return true;
    }
})
```  
  
  
返回页面如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8na2QicnXqHYTdFVz30ktVN8yh1C3vYZiaqzDyzm0fUNn8ibtyqMwoI1lg/640?wx_fmt=png "")  
  
   
  
看到有两个解密相关的方法，果断继续hook。  
```
console.log("Script loaded successfully");
Java.perform(function x(){
    console.log("inside java perform function");
    //定位类
    var my_class = Java.use("com.pica.picapica.MainActivity");
    console.log("Java.use Successfully");
    my_class.check.implementation = function(x,y){
        var email=this.decryptByHexString(this.bytesConvertHexString(this.content0.value),this.key.value);
        var password=this.decryptByHexString(this.bytesConvertHexString(this.content1.value),this.key.value);
        console.log("flag{"+email+password+"}"); 
        return true;
    }
})
```  
  
  
直接拿到flag。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8wOIZuXiaStJlkSpSEyfy8tu0NcibueyFV2TMQUavHEXT5Jek73ibzNqZA/640?wx_fmt=png "")  
  
奇怪的交易这题附件过大，这里就直接贴我的链接了：  
  
奇怪的交易  
  
http://49.235.65.44:8888/down/QOUeSq0RV5tS  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HkbL29l0jKvV2RorU6wUQ8WlBZS46URXQxSvqLkNQJTDRvzmGOln0QQZL0SDFrdA9oKWKOk6VhfA/640?wx_fmt=png "")  
  
  
**看雪ID：t0hka1**  
  
https://bbs.pediy.com/user-home-860779.htm  
  
*本文由看雪论坛 t0hka1 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458447393&idx=5&sn=6d82ff01f82a6dda33188cdc22938983&chksm=b18fdeab86f857bd3804504bd2add426b5a0a678624e2f06f04d2e5b4d7df7216e5831e5e8cd&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1.[从2021年西湖论剑一道题看高版本libc解题思路](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458454436&idx=2&sn=7d347ab070f6e5b638b60a7c2c687a4f&chksm=b18e392e86f9b038fdd2929854f83aa40ebed88fea4e8358d971e8600ac34c6849909b38eead&scene=21#wechat_redirect)  
  
  
2.[向Typora学习electron安全攻防](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458454336&idx=1&sn=e35986593ff8bf4d3778ff8d2bf2f7c8&chksm=b18e39ca86f9b0dc6d365d664f0092648c3b38ead690be61f1711daf443da18d570623219618&scene=21#wechat_redirect)  
  
  
3.[游戏安全之借坡下驴](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458454249&idx=1&sn=07279453ab2e5807c7548972a7769b52&chksm=b18e386386f9b175e72c07315131a311527604e1a9074352c3fdb1a5408458b039c76e440a3c&scene=21#wechat_redirect)  
  
  
4.[EXP编写学习之绕过SafeSEH](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458453650&idx=1&sn=80fd959ccaf32602fca0cc7462497228&chksm=b18e361886f9bf0e105675b2206100d43cebf617bf488de3bdedf767ed1a85768818145f8596&scene=21#wechat_redirect)  
  
  
5.[CVE-2016-0165提权漏洞学习笔记](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458453618&idx=2&sn=dba42df66438701cda904d463e51e760&chksm=b18e36f886f9bfeefd2de981ac20b75516801e14ee248a182751e0b64855fe6df533fe2c4a41&scene=21#wechat_redirect)  
  
  
6.[CVE-2015-0057提权漏洞学习笔记](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458453553&idx=1&sn=40ec3ed6489c7a60e2ce2fe693f3a2cf&chksm=b18e36bb86f9bfad5b2fa3b2c5ee5a250a4ff20d5bded533dec8be647afd3ac728a112a4da2d&scene=21#wechat_redirect)  
****  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicd7icG69uHMQX9DaOnSPpTgamYf9cLw1XbJLEGr5Eic62BdV6TRKCjWVSQ/640?wx_fmt=gif "")  
  
点击“阅读原文”，了解更多！  

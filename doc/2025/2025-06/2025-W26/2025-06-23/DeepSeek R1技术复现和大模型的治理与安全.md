> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5OTk4MDE2MA==&mid=2655284631&idx=1&sn=0f2b418860e8c2dc075739e21e9ca0cb

#  DeepSeek R1技术复现和大模型的治理与安全  
 计算机与网络安全   2025-06-23 13:57  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibXEVVXdANicnicAeHAUVDqCu9xHIL9IbQibUGQhibWHR9q1KJztKRtqvx8Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibn5seiaul5ecqHNwUPTngtwvvdtCoQyWsWIG1r8H5ibCviaVc04Nu1wia8A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibYDQicibficZWMuU1zyIkRoTEhVWQdIP5wIDI6spicnrsr5xfnaaIDEgSsg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibRngRoHadZ48ribRicVzribgKoyMBHriaj0biby6JY0ZeiaB55b8ZL2KzBNuQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibyrN6GQ8TG6SBHnRouAoDY37MBxotVSVDSiaybrIMG6ujicWCBiabS1c0A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibvrQ9jcfsqXguDuOm96Eqf0MG9ic5Bf8KNiafQN6MSl5rxdgtlJrBatnA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibc3pOpmzAyY6QILjvsxBficicT25Le3spxIE9icIVVqutVHPXtWGPyLLAw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibqDfjIOqoRICAAku6QaZgtxhkhdgRJibdpY2U8Pruq2KxgibibRHIGP8icQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMib1BwQj9eEvnxhfVkNJppwbXl6U0orIbYAfPnRpw0EeSicmoW2jiaYVHaA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibibR2PIqxtF8icVKh0lAiaNRAbnnpNznZibeqE4dSBmTicpZ6eTA4KS6vmGg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibyeiczHx80eLnXFMUFaIOiaicJSGxibsvHhPhPprCUSicn1IXIstdk8G2OAQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibR05K9pwH1gAmVuUHTcHX5ckGklmIWZkdia6iaeVWXM54kLjdvlvy0aug/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibuU861SZnD2a4slC7ndAAHnaznJ8TvBA8EVGx7oc9GqPavdibKWoTULw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibsZIa76h1MKX0WeY2hsBFDe1EGYu8Kv10urestgOLHovNHsq3TCOyCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibqgg1ZicwuJLE5k2BP2oczaRRuc0iaygAM8gg0p9XZHeBJszl2Bnf6iceQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibbs9U7qXiaDtGMe84uricoJLKTbeIeuUKPb44ROYg0mdhPYuR0pPWLFSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibmPazHQGbibkJIvF2k10VApbVWI8DON7AcMdGJDYM6nbvpKoNIlTkUXg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibiazUJPxZd62MSeiajLbiawXTO5RyZjFqKuPj1PyLib2RGgwa8e1RJE3fsA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibnrZBtepOlVzqvtur4T1M9uP5rCQWVPo2fIXUALibZJ6kexTyHI3EB5Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibRGOv855kYzQaocnXqFpbW0jfj5CPjC0gNNMuxcQBLrj6OsKNkdIBqQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMib5EG3iblPI0oVPeTYic98eGUXicXnic699p643ORJ9GxiciaXLJwJIBlb6zkA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibibVLjASqLZzpCbcIWPOZ0qEmPAbO0ylsnpbQI0mkbw3Y69RnaKwOpbw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibSOm0vtHbkL0A4zLOUgM8e3ujwvAjVdD6BVGZMQ0jzdNrPEzibYqVUfg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibllLK2rV8wuaoFZdD6MfA5ZbldlpaLticswHCibAhThNjHxJ8jicURZ28w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibslxq0SHaXibmnkibnSDEd6L1Q12R7HYHe9SCXCEuZpAgF1AgUHwY49UA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibBOU6CLXeDsg6lxgZM6yZOD6RAPCSTVS2hj7hlsc1JN2xHI0A07JicRQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibOia8YhhJ93X3jGTxzCibQL7WsMiaJufk4vXwIFMyKLicTrrReAGjEYf9Cw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibGFfgdDVU6ibNByFW8Na6Bibex0z3Hic7HWLF70ibb1xFPrMngVAIub8bUQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibRonhHARRZfh1ZlFWfT2Pn5C5u5DjMRIpLICCibdwq9zsiaaQ0E3jiaYibQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibS6ibuRicysibCrT84Ql775PRo3R8OrgkVvQ8kUz6AkOQCsO57y3NE3krA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibDc0UBXw0lkNBWZYSJcnzdXB0rjpBH0bicWm2icpOTYEYwONSJJt5qNrg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibwibJRWB1834neKd0lP0jELKVA8RKObBjvicnFtVoeddWuCOvr8KJT8RA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibtXD9dxPmNA8l6bENb0ic6ZFyHm3ia5OLNub3bEHpMKae6ArvYJdlhcMg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibU6edGKgicmic1bLAySX2vEF8DPBAsWQnbpiceEBgsMRp0kS7rZskSYiarQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibsicFVRL8W7oVPJyN9GewOI5VhOmhKcj47hGs6CGiaNGmOAD3sS1GiaicLA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMib31S0U65fExCicPia6ibV64oRgvJ0puYhmUP6Ae4uY4qqiaPP06TkIyiaibicg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VcRPEU1K2ofEokKhxurPCjTfRHEDwAMibYibrTJXA1w9LFeKhK9XUwN9VQa1m0xKFeL2riaA2opqTOhTgbpkK0IBg/640?wx_fmt=png&from=appmsg "")  
  
**扫码加入知识星球：**  
**人工智能、算力算网**  
  
**下载本篇和全套资料**  
  
人工智能、人工智能安全、人工智能+、算力算网  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/VcRPEU1K2ocrickwS8jlJmx9dm99x7cetLeUNE9GbqVJTnxP9aVBCGWd75Z8Lhq5X1cY05TRibpRUnqEDRsI0CsA/640?wx_fmt=jpeg "")  
  
****  
**|**  
 -  
  

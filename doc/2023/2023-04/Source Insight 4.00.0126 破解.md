#  Source Insight 4.00.0126 破解   
原创 吾爱pojie  吾爱破解论坛   2023-04-13 14:20  
  
**作者****论****坛账号：粱念念**  
  
  
文件下载：链接：https://pan.baidu.com/s/1xSZBiSF7R465iB3r2x0Tow 提取码：sujd  
  
使用方法：安装 Source Insight4 后，将 exe 文件放到 Source Insight4 的安装目录。将 si.lic 放到 C:\ProgramData\Source Insight\4.0 目录下。  
  
版本：Source Insight 4.00.0126  
  
修改 PE，关闭随机基址。  
# 一、序列号检验  
  
对获取文件框文本的 API 下断点，输入序列号，断点命中在 GetWindowsTextW() 函数。  
  
序列号格式检验的函数  
```
BOOL __cdecl sub_514BA0(char *szSerial, void *ArgcList_608, void *ArgcList_60C, void *ArgcList_604, int n_1){
  char v5; // al
  char v6; // al
  char v7; // al
  char v8; // al
  int v10; // [esp+4h] [ebp-18h] BYREF
  char Destination[20]; // [esp+8h] [ebp-14h] BYREF

  _strupr(szSerial);
  if ( strlen(szSerial) != 19 )
    return 0;
  if ( szSerial[4] != '-' )
    return 0;
  if ( szSerial[9] != '-' )
    return 0;
  if ( szSerial[14] != '-' )
    return 0;
  if ( *szSerial != 'S' )
    return 0;
  if ( n_1 )
  {
    v5 = szSerial[6];
    if ( v5 != 'R' && v5 != 'G' && v5 != 'D' && v5 != 'F' )
      return 0;
  }
  v6 = szSerial[1];
  if ( v6 < '0' || v6 > '9' )
    return 0;
  *ArgcList_604 = v6 - '0';                     // *ArgcList_604 = szSerial[1] - '0';
  v7 = szSerial[2];
  switch ( v7 )                                 // *ArgcList_604 = [1 3 0 0]
  {
    case 'T':
      *ArgcList_60C = 1;
      break;
    case 'B':
      *ArgcList_60C = 3;
      break;
    case 'S':
      *ArgcList_60C = 0;
      break;
    case 'U':
      *ArgcList_60C = 0;
      break;
    default:
      return 0;
  }
  v8 = szSerial[3];
  if ( v8 == 'G' )
  {
    *ArgcList_608 = 1;
  }
  else
  {
    if ( v8 != 'R' )
      return 0;
    *ArgcList_608 = 0;
  }
  if ( !n_1 )
    return 1;
  strcpy(Destination, szSerial);
  Destination[15] = 0;
  sub_514370(Destination, 15, &unk_604F70, &v10);// 根据序列号的前 15 位生成后四位
  return *(szSerial + 15) == v10;               // 判断生成的后四位和序列号中的后四位是否相等。
}
```  
  
序列号长度：19序列号格式：XXXX-XXXX-XXXX-XXXXSerial[0] = 'S'Serial[1] = [0-9] => ArgcList_604 = szSerial[1] - '0' = 4Serial[2] = [T B S U] => ArgcList_60C = [1 3 0 0] = 1Serial[3] = G => *ArgcList_608 = 1Serial[6] = [R G D F]  
  
根据规则乱造一个序列号：S4SG-ARCD-EFGH-XXXX，后四位可有 sub_514370() 函数生成。  
  
生成后四位的算法  
```
int __cdecl sub_514370(_BYTE *szSerial, unsigned int nSerialLength, char *pTable, int nResult){
  unsigned int i; // esi
  unsigned __int8 v5; // cl
  unsigned int j; // eax
  int result; // eax

  for ( i = 0; i < 4; *(i + nResult - 1) = byte_604E50[v5 % 26] )
  {
    v5 = pTable[(i + *szSerial)];
    for ( j = 1; j < nSerialLength; ++j )
      v5 = pTable[v5 ^ szSerial[j]];
    result = nResult;
    ++i;
  }
  return result;
}
```  
  
根据算法写注册机  
```
unsigned char g_szAlphabetTable[] =
{
  0x4B, 0x56, 0x39, 0x36, 0x47, 0x4D, 0x4A, 0x59, 0x48, 0x37,
  0x51, 0x46, 0x35, 0x54, 0x43, 0x57, 0x34, 0x55, 0x33, 0x58,
  0x5A, 0x50, 0x52, 0x53, 0x44, 0x4E, 0x00
};

int __cdecl sub_514370(char* szSerial, unsigned int nSerialLength, char* pTable, char* pLastFourCharacters){
    unsigned int i; // esi
    unsigned __int8 v5; // cl
    unsigned int j; // eax
    int result; // eax

    for (i = 0; i < 4; *(i + pLastFourCharacters - 1) = g_szAlphabetTable[v5 % 26])
    {
        v5 = pTable[(i + *szSerial)];
        for (j = 1; j < nSerialLength; ++j)
            v5 = pTable[v5 ^ szSerial[j]];
        result = pLastFourCharacters;
        ++i;
    }
    return result;
}

int main(int argc, char* argv[]){
    // "S4SG-XRXX-XXXX-XXXX"
    char szSerial[20] = { 'S', '4', 'S', 'G', '-', 'A', 'R', 'C', 'D', '-', 'E', 'F', 'G', 'H', '-', 'X', 'X', 'X', 'X' , 0 };
    char aryLastFourCharacters[4] = {0};
    sub_514370(szSerial, 15, g_aryTable, &aryLastFourCharacters);
    *(PULONG)(szSerial + 15) = *(PLONG)aryLastFourCharacters;
    printf("Serial: %s", szSerial);
}
```  
  
生成的后四位为：”36V6”，最后序列号为：“S4SG-ARCD-EFGH-36V6”。  
# 二、网络验证  
  
输入序列号后，填写信息，然后会出现提示信息 "Now activating your license... Please wait..."，打开 Fiddler 抓包，发现有发请求，但是返回的数据包里面没有可用信息。这时可以对 HttpSendRequestW() 函数下断点。  
  
网络验证关键代码  
```
int __usercall sub_425860@<eax>(
        char *Str,
        int a3,
        const CHAR *lpMultiByteStr,
        char *lpOptional,
        _BYTE *lpBuffer,
        int a7)
{
  int v6; // ebp MAPDST
  DWORD v7; // edi
  DWORD v8; // ebx
  INTERNET_PORT v9; // si
  void *v10; // eax
  void *v12; // eax
  void *v13; // ebp
  void *v14; // eax
  void *v15; // esi
  int LastError; // eax
  int v18; // [esp+0h] [ebp-11Ch]
  int result; // [esp+Ch] [ebp-110h] BYREF
  DWORD dwNumberOfBytesRead; // [esp+10h] [ebp-10Ch] BYREF
  DWORD dwBufferLength; // [esp+14h] [ebp-108h] BYREF
  HINTERNET hInternet; // [esp+18h] [ebp-104h]
  char v23[256]; // [esp+1Ch] [ebp-100h] BYREF

  v7 = strlen(lpOptional);
  result = 0x3E8;
  dwBufferLength = 4;
  v8 = 67420928;
  if ( a3 )
  {
    v8 = 75817728;
    v9 = 443;
  }
  else
  {
    v9 = 80;
  }
  v10 = sub_455BE0("Source Insight", 0, 0, 0, 0);
  hInternet = v10;
  if ( v10 )
  {
    v12 = sub_455D90(v10, Str, v9, 0, 0, 3u, 0, 0);
    v13 = v12;
    if ( v12 )
    {
      v14 = sub_455F60(v12, "POST", lpMultiByteStr, 0, 0, 0, v8, 0);
      v15 = v14;
      if ( v14 )
      {
        sub_456190(v14, "Content-Type: application/x-www-form-urlencoded", 0xFFFFFFFF, 0x20000000u);
        sub_456190(v15, "Accept: text/plain", 0xFFFFFFFF, 0x20000000u);
        sprintf(v23, "Content-length: %d\n", v7);
        sub_456190(v15, v23, 0xFFFFFFFF, 0x20000000u);
        if ( HttpSendRequestW(v15, 0, 0, lpOptional, v7) )
        {
          HttpQueryInfoW(v15, 0x20000013u, &result, &dwBufferLength, 0);
          if ( result == 0xC8 ) // 网络验证通过的分支。
          {
            if ( InternetReadFile(v15, lpBuffer, a7 - 1, &dwNumberOfBytesRead) )
            {
              lpBuffer[dwNumberOfBytesRead] = 0;
              result = 0xC8;
            }
            else
            {
              lpBuffer[dwNumberOfBytesRead] = 0;
              sub_413440(0, 0, "InternetReadFile Error", v6);
              result = 1007;
            }
          }
        }
        else
        {
          LastError = GetLastError();
          result = (LastError == 12045) + 1004;
          sub_413440(0, 0, "HttpSendRequest Error %d", LastError);
        }
        InternetCloseHandle(v15);
      }
      else
      {
        sub_413440(0, 0, "HttpOpenRequest failed.", v6);
        result = 1006;
      }
      InternetCloseHandle(v13);
    }
    else
    {
      sub_413440(0, 0, "InternetConnect failed.", v6);
      result = 0x3EA;
    }
    InternetCloseHandle(hInternet);
    return result;
  }
  else
  {
    sub_413440(0, 0, "InternetOpen failed.", v18);
    return 0x3E9;
  }
}
```  
  
发送请求后，会通过 HttpQueryInfoW() 获取返回的信息。获取的值等于 0xC8，则表示网页验证通过。这里我们直接修改二进制，让 HttpQueryInfoW() 函数的 result 参数直接等于 0xC8。  
```
00425A0D     | BB C8000000            | mov ebx,C8                                 |
00425A12     | 895C24 10              | mov dword ptr ss:[esp+10],ebx              | 将 [esp+10] 改为 C8
```  
  
生成请求数据包的函数  
```
int __thiscall sub_515290(_DWORD *this, char *pBuffer, int n_1FA0){
  BOOL v4; // ebp
  char *pPackage; // eax
  char *pPackage2; // esi
  int result; // eax
  int dwNumberOfProcessors; // eax
  int v9; // eax
  int v10; // edi
  char v11[12]; // [esp+Ch] [ebp-20Ch] BYREF
  char Buffer[256]; // [esp+18h] [ebp-200h] BYREF
  char v13[256]; // [esp+118h] [ebp-100h] BYREF
  int v14; // [esp+224h] [ebp+Ch]

  v4 = this[387] == 1;
  pPackage = sub_425300(0x2000u, 0);
  pPackage2 = pPackage;
  if ( !pPackage )
    return 492;
  *pPackage = 0;
  sub_425E70("serial", this + 4, pPackage, 0x2000);
  sub_425F00("product_version_major", HIBYTE(dword_659510), pPackage2, 0x2000);
  sub_425F00("product_version_minor", BYTE2(dword_659510), pPackage2, 0x2000);
  sub_425F00("product_version_build", dword_659510, pPackage2, 0x2000);
  sub_425E70("user_name", this + 260, pPackage2, 0x2000);
  sub_425E70("user_org", this + 516, pPackage2, 0x2000);
  sub_425E70("user_email", this + 772, pPackage2, 0x2000);
  sub_425E70("prevserial", this + 1028, pPackage2, 0x2000);
  sub_425E70("upgradeserial", this + 1284, pPackage2, 0x2000);
  if ( v14 )
  {
    dwNumberOfProcessors = 12;
  }
  else
  {
    dwNumberOfProcessors = SystemInfo.dwNumberOfProcessors;
    if ( SystemInfo.dwNumberOfProcessors == 12 )
      dwNumberOfProcessors = 8;
  }
  sub_425F00("cpu_count", dwNumberOfProcessors, pPackage2, 0x2000);
  if ( *this == 3 )
    sub_425E70("localactivation", "true", pPackage2, 0x2000);
  else
    sub_425E70("localactivation", "false", pPackage2, 0x2000);
  sub_425E70("usersid", this + 2412, pPackage2, 0x2000);
  sub_425E70("volumeid", this + 2156, pPackage2, 0x2000);
  sub_425E70("compname", this + 2668, pPackage2, 0x2000);
  _itoa_s(this[731], Buffer, 0xFFu, 10);
  sub_425E70("os_version_major", Buffer, pPackage2, 0x2000);
  _itoa_s(this[732], Buffer, 0xFFu, 10);
  sub_425E70("os_version_minor", Buffer, pPackage2, 0x2000);
  _itoa_s(this[733], Buffer, 0xFFu, 10);
  sub_425E70("os_version_build", Buffer, pPackage2, 0x2000);
  if ( this[734] )
    sub_425E70("os_server", "true", pPackage2, 0x2000);
  else
    sub_425E70("os_server", "false", pPackage2, 0x2000);
  sub_425E70("app_type", "release", pPackage2, 0x2000);
  sub_514880(v11);
  sub_425E70("requestid", v11, pPackage2, 0x2000);
  sub_5143E0(v11, v13);
  sub_425E70("local_time", v13, pPackage2, 0x2000);
  if ( !v4 || *(this + 4) )
    v9 = (sub_425860)(this[535], 1, this[0x218], pPackage2, pBuffer, n_1FA0);// 发送数据包 /request_activation/
  else
    v9 = (sub_425860)(this[535], 1, this[0x219], pPackage2, pBuffer, n_1FA0);// 发送数据包 /create_trial_license/
  v10 = v9;
  sub_412C90();                                 // 清理数据
  sub_424E30(pPackage2);                        // 释放缓冲区
  result = v10;
  switch ( v10 )
  {
    case 0x3E9:
      result = 465;
      break;
    case 0x3EA:
      result = 466;
      break;
    case 0x3EB:
    case 0x3EE:
      result = 467;
      break;
    case 0x3EC:
      result = 480;
      break;
    case 0x3ED:
      result = 496;
      break;
    case 0x3EF:
      result = 484;
      break;
    default:
      return result;
  }
  return result;
}
```  
  
网页验证通过后，会修改注册表和 C:\ProgramData\Source Insight\4.0\si.lic 文件。  
```
int __thiscall sub_5171D0(const CHAR *this, int a2){
  int result; // eax
  int v4; // [esp+4h] [ebp-3FA4h] BYREF
  int v5[2024]; // [esp+8h] [ebp-3FA0h] BYREF
  char Str[8192]; // [esp+1FA8h] [ebp-2000h] BYREF

  memset(Str, 0, sizeof(Str));
  result = sub_515290(this, v5, 0x1FA0);        // 网络验证
  if ( result == 0xC8 )
  {
    if ( a2 )
    {
      if ( sub_514610(this + 0x75C, &v4, 0x1FA0) == 0xC8 )// 有文件，但是没内容。才返回 C8
        sub_516FF0(this, &v4);                  // 写注册表
      return 0xC8;
    }
    else
    {                                           // 网页验证完后，会进入这个分支。
      sub_412990();                             // 生成注册信息写到 FileHandle 为 3 的文件中。
      if ( sub_425C80(&v4, &v5[2023], 0x2000u) && strlen(&v5[2023]) >= 8 )// v5 是服务器返回的东西。这里我们的 v5 是空的。
      {
        sub_516FF0(this, &Str[4]);              // 写注册表
        return sub_5148C0(this + 0x75C, &Str[4]);// 重写文件
      }
      else
      {
        return 0x1D0;                           // 修改返回值为 C8
      }
    }
  }
  return result;
}
```  
  
如果是正版的序列号，返回的 HTTP 数据包会有数据，给我们回写到注册表和 C:\ProgramData\Source Insight\4.0\si.lic 的文件中。但是这里我们没有数据，所以这里我们修改二进制将 return 0x1D0 改为 return 0xC8。  
```
00517282     | B8 C8000000            | mov eax,C8                                 |
```  
# 三、检查 si.lic 文件的数据  
  
将 C:\ProgramData\Source Insight\4.0\si.lic 的内容进行 XML 格式化，并对文件中各个字段的数据进行检查。  
```
005167D0     | 64:A1 00000000         | mov eax,dword ptr fs:[0]                   | eax:&"ActId"
005167D6     | 6A FF                  | push FFFFFFFF                              |
005167D8     | 68 FB365D00            | push sourceinsight4.5D36FB                 |
005167DD     | 50                     | push eax                                   | eax:&"ActId"
005167DE     | 64:8925 00000000       | mov dword ptr fs:[0],esp                   |
005167E5     | 81EC 10040000          | sub esp,410                                |
005167EB     | 53                     | push ebx                                   |
005167EC     | 56                     | push esi                                   |
005167ED     | 33DB                   | xor ebx,ebx                                |
005167EF     | 57                     | push edi                                   |
005167F0     | 8BF1                   | mov esi,ecx                                |
005167F2     | 33C0                   | xor eax,eax                                | eax:&"ActId"
005167F4     | 895C84 1C              | mov dword ptr ss:[esp+eax*4+1C],ebx        |
005167F8     | 899C84 1C020000        | mov dword ptr ss:[esp+eax*4+21C],ebx       |
005167FF     | 40                     | inc eax                                    | eax:&"ActId"
00516800     | 3D 80000000            | cmp eax,80                                 | eax:&"ActId"
00516805     | 72 ED                  | jb sourceinsight4.5167F4                   |
00516807     | 899C24 24040000        | mov dword ptr ss:[esp+424],ebx             |
0051680E     | 8D4424 1C              | lea eax,dword ptr ss:[esp+1C]              |
00516812     | 50                     | push eax                                   | eax:&"ActId"
00516813     | 8D8E 5C070000          | lea ecx,dword ptr ds:[esi+75C]             | esi+75C:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
00516819     | 51                     | push ecx                                   |
0051681A     | E8 71E9FFFF            | call sourceinsight4.515190                 | 解释文件中数据，并保存。
0051681F     | 83C4 08                | add esp,8                                  |
00516822     | 8D5424 0C              | lea edx,dword ptr ss:[esp+C]               |
00516826     | 52                     | push edx                                   |
00516827     | 68 CCD05E00            | push sourceinsight4.5ED0CC                 | 5ED0CC:"Type"
0051682C     | 8D4C24 24              | lea ecx,dword ptr ss:[esp+24]              | [esp+24]:"ActId"00516830     | 899E 0C060000          | mov dword ptr ds:[esi+60C],ebx             |00516836     | E8 85DDFFFF            | call sourceinsight4.5145C0                 | 取出 Type 字段的值0051683B     | 85C0                   | test eax,eax                               | eax:&"ActId"0051683D     | 74 58                  | je sourceinsight4.516897                   |0051683F     | 8B7C24 0C              | mov edi,dword ptr ss:[esp+C]               |00516843     | 68 DCA25F00            | push sourceinsight4.5FA2DC                 | 5FA2DC:"Trial"00516848     | 57                     | push edi                                   |00516849     | E8 DCA50B00            | call sourceinsight4.5D0E2A                 | stricmp(["Type"], "Trial")0051684E     | 83C4 08                | add esp,8                                  |00516851     | 85C0                   | test eax,eax                               | eax:&"ActId"00516853     | 75 0C                  | jne sourceinsight4.516861                  |00516855     | C786 0C060000 01000000 | mov dword ptr ds:[esi+60C],1               |0051685F     | EB 36                  | jmp sourceinsight4.516897                  |00516861     | 68 8C616000            | push sourceinsight4.60618C                 | 60618C:"Beta"00516866     | 57                     | push edi                                   |00516867     | E8 BEA50B00            | call sourceinsight4.5D0E2A                 |0051686C     | 83C4 08                | add esp,8                                  |0051686F     | 85C0                   | test eax,eax                               | eax:&"ActId"00516871     | 75 0C                  | jne sourceinsight4.51687F                  |00516873     | C786 0C060000 03000000 | mov dword ptr ds:[esi+60C],3               |0051687D     | EB 18                  | jmp sourceinsight4.516897                  |0051687F     | 68 80616000            | push sourceinsight4.606180                 | 606180:"Standard"00516884     | 57                     | push edi                                   |00516885     | E8 A0A50B00            | call sourceinsight4.5D0E2A                 |0051688A     | 83C4 08                | add esp,8                                  |0051688D     | 85C0                   | test eax,eax                               | eax:&"ActId"0051688F     | 75 06                  | jne sourceinsight4.516897                  |00516891     | 899E 0C060000          | mov dword ptr ds:[esi+60C],ebx             |00516897     | 8D4424 0C              | lea eax,dword ptr ss:[esp+C]               |0051689B     | 50                     | push eax                                   | eax:&"ActId"0051689C     | 68 D0656000            | push sourceinsight4.6065D0                 | 6065D0:"LicensedUser"005168A1     | 8D4C24 24              | lea ecx,dword ptr ss:[esp+24]              | [esp+24]:"ActId"005168A5     | E8 16DDFFFF            | call sourceinsight4.5145C0                 | 取出 ["LicensedUser"] 的值005168AA     | 85C0                   | test eax,eax                               | eax:&"ActId"005168AC     | 0F84 36030000          | je sourceinsight4.516BE8                   |005168B2     | 8B4C24 0C              | mov ecx,dword ptr ss:[esp+C]               |005168B6     | 51                     | push ecx                                   |005168B7     | 8D96 04010000          | lea edx,dword ptr ds:[esi+104]             |005168BD     | 52                     | push edx                                   |005168BE     | E8 BD4E0A00            | call sourceinsight4.5BB780                 | strcpy(edx, ["LicensedUser"])005168C3     | 83C4 08                | add esp,8                                  |005168C6     | 8D4424 0C              | lea eax,dword ptr ss:[esp+C]               |005168CA     | 50                     | push eax                                   | eax:&"ActId"005168CB     | 68 C0656000            | push sourceinsight4.6065C0                 | 6065C0:"Organization"005168D0     | 8D4C24 24              | lea ecx,dword ptr ss:[esp+24]              | [esp+24]:"ActId"005168D4     | E8 E7DCFFFF            | call sourceinsight4.5145C0                 | 取出 ["Organization"] 的值005168D9     | 85C0                   | test eax,eax                               | eax:&"ActId"005168DB     | 74 14                  | je sourceinsight4.5168F1                   |005168DD     | 8B4C24 0C              | mov ecx,dword ptr ss:[esp+C]               |005168E1     | 51                     | push ecx                                   |005168E2     | 8D96 04020000          | lea edx,dword ptr ds:[esi+204]             |005168E8     | 52                     | push edx                                   |005168E9     | E8 924E0A00            | call sourceinsight4.5BB780                 | strcpy(edx, ["Organization"])005168EE     | 83C4 08                | add esp,8                                  |005168F1     | 8D4424 0C              | lea eax,dword ptr ss:[esp+C]               |005168F5     | 50                     | push eax                                   | eax:&"ActId"005168F6     | 68 B8656000            | push sourceinsight4.6065B8                 | 6065B8:"Email"005168FB     | 8D4C24 24              | lea ecx,dword ptr ss:[esp+24]              | [esp+24]:"ActId"005168FF     | E8 BCDCFFFF            | call sourceinsight4.5145C0                 | 取出 ["Email"] 的值00516904     | 85C0                   | test eax,eax                               | eax:&"ActId"00516906     | 74 14                  | je sourceinsight4.51691C                   |00516908     | 8B4C24 0C              | mov ecx,dword ptr ss:[esp+C]               |0051690C     | 51                     | push ecx                                   |0051690D     | 8D96 04030000          | lea edx,dword ptr ds:[esi+304]             |00516913     | 52                     | push edx                                   |00516914     | E8 674E0A00            | call sourceinsight4.5BB780                 | strcpy(edx, ["Email"])00516919     | 83C4 08                | add esp,8                                  |0051691C     | 8D4424 0C              | lea eax,dword ptr ss:[esp+C]               |00516920     | 50                     | push eax                                   | eax:&"ActId"00516921     | 68 B0656000            | push sourceinsight4.6065B0                 | 6065B0:"Serial"00516926     | 8D4C24 24              | lea ecx,dword ptr ss:[esp+24]              | [esp+24]:"ActId"0051692A     | E8 91DCFFFF            | call sourceinsight4.5145C0                 | 取出 ["Serial"] 的值0051692F     | 85C0                   | test eax,eax                               | eax:&"ActId"00516931     | 0F84 B1020000          | je sourceinsight4.516BE8                   |00516937     | 8B4C24 0C              | mov ecx,dword ptr ss:[esp+C]               |0051693B     | 55                     | push ebp                                   |0051693C     | 51                     | push ecx                                   |0051693D     | 8D6E 04                | lea ebp,dword ptr ds:[esi+4]               |00516940     | 55                     | push ebp                                   |00516941     | E8 3A4E0A00            | call sourceinsight4.5BB780                 | strcpy(edx, ["Serial"])00516946     | 83C4 08                | add esp,8                                  |00516949     | 8D5424 10              | lea edx,dword ptr ss:[esp+10]              |0051694D     | 52                     | push edx                                   |0051694E     | 68 A8656000            | push sourceinsight4.6065A8                 | 6065A8:"ActId"00516953     | 8D4C24 28              | lea ecx,dword ptr ss:[esp+28]              | [esp+28]:"Serial"00516957     | E8 64DCFFFF            | call sourceinsight4.5145C0                 | 取出 ["ActId"] 的值0051695C     | 85C0                   | test eax,eax                               | eax:&"ActId"0051695E     | 0F84 66020000          | je sourceinsight4.516BCA                   |00516964     | 8B4424 10              | mov eax,dword ptr ss:[esp+10]              |00516968     | 50                     | push eax                                   | eax:&"ActId"00516969     | 8DBE 3A060000          | lea edi,dword ptr ds:[esi+63A]             |0051696F     | 57                     | push edi                                   |00516970     | E8 0B4E0A00            | call sourceinsight4.5BB780                 | strcpy(edx, ["ActId"])00516975     | 68 7F1B0000            | push 1B7F                                  |0051697A     | 6A 32                  | push 32                                    |0051697C     | 6A 04                  | push 4                                     |0051697E     | 68 701A6500            | push sourceinsight4.651A70                 |00516983     | 57                     | push edi                                   |00516984     | E8 E7CBEEFF            | call sourceinsight4.403570                 | 检查 ["ActId"] 的值00516989     | 33C9                   | xor ecx,ecx                                |0051698B     | 3BC3                   | cmp eax,ebx                                | eax:&"ActId"0051698D     | 0F9FC1                 | setg cl                                    |00516990     | 68 9C656000            | push sourceinsight4.60659C                 | 60659C:"Deferred"00516995     | 57                     | push edi                                   |00516996     | 8BD9                   | mov ebx,ecx                                |00516998     | E8 8DA40B00            | call sourceinsight4.5D0E2A                 | stricmp(["ActId"], "Deferred")0051699D     | 83C4 24                | add esp,24                                 |005169A0     | 85C0                   | test eax,eax                               | eax:&"ActId"005169A2     | 75 38                  | jne sourceinsight4.5169DC                  |005169A4     | C706 02000000          | mov dword ptr ds:[esi],2                   |005169AA     | C78424 28040000 FFFFFF | mov dword ptr ss:[esp+428],FFFFFFFF        |005169B5     | 8D4C24 20              | lea ecx,dword ptr ss:[esp+20]              |005169B9     | E8 22DBFFFF            | call sourceinsight4.5144E0                 | 释放掉保存的文件数据005169BE     | B8 C8000000            | mov eax,C8                                 | eax:&"ActId"005169C3     | 5D                     | pop ebp                                    |005169C4     | 5F                     | pop edi                                    |005169C5     | 5E                     | pop esi                                    |005169C6     | 5B                     | pop ebx                                    |005169C7     | 8B8C24 10040000        | mov ecx,dword ptr ss:[esp+410]             |005169CE     | 64:890D 00000000       | mov dword ptr fs:[0],ecx                   |005169D5     | 81C4 1C040000          | add esp,41C                                |005169DB     | C3                     | ret                                        |005169DC     | 33D2                   | xor edx,edx                                |005169DE     | 85DB                   | test ebx,ebx                               |005169E0     | 0F94C2                 | sete dl                                    |005169E3     | 8D4424 14              | lea eax,dword ptr ss:[esp+14]              |005169E7     | 8D4C24 18              | lea ecx,dword ptr ss:[esp+18]              |005169EB     | 52                     | push edx                                   |005169EC     | 50                     | push eax                                   | eax:&"ActId"005169ED     | 51                     | push ecx                                   |005169EE     | 8D5424 28              | lea edx,dword ptr ss:[esp+28]              | [esp+28]:"Serial"005169F2     | 52                     | push edx                                   |005169F3     | 55                     | push ebp                                   |005169F4     | E8 A7E1FFFF            | call sourceinsight4.514BA0                 | 检查 ["Serial"]
005169F9     | 83C4 14                | add esp,14                                 |
005169FC     | 85C0                   | test eax,eax                               | eax:&"ActId"
005169FE     | 74 0C                  | je sourceinsight4.516A0C                   |
00516A00     | 8B4424 18              | mov eax,dword ptr ss:[esp+18]              |
00516A04     | 3B86 0C060000          | cmp eax,dword ptr ds:[esi+60C]             | eax:&"ActId"
00516A0A     | 74 1B                  | je sourceinsight4.516A27                   |
00516A0C     | C78424 28040000 FFFFFF | mov dword ptr ss:[esp+428],FFFFFFFF        |
00516A17     | 8D4C24 20              | lea ecx,dword ptr ss:[esp+20]              |
00516A1B     | E8 C0DAFFFF            | call sourceinsight4.5144E0                 |
00516A20     | B8 EF010000            | mov eax,1EF                                | eax:&"ActId"
00516A25     | EB 9C                  | jmp sourceinsight4.5169C3                  |
00516A27     | 0FB60D 13956500        | movzx ecx,byte ptr ds:[659513]             |
00516A2E     | 8B7C24 14              | mov edi,dword ptr ss:[esp+14]              |
00516A32     | 3BF9                   | cmp edi,ecx                                |
00516A34     | 0F85 BA000000          | jne sourceinsight4.516AF4                  |
00516A3A     | 55                     | push ebp                                   |
00516A3B     | B9 40846600            | mov ecx,sourceinsight4.668440              |
00516A40     | E8 CB6FF4FF            | call sourceinsight4.45DA10                 |
00516A45     | 85C0                   | test eax,eax                               | eax:&"ActId"
00516A47     | 74 1E                  | je sourceinsight4.516A67                   |
00516A49     | C78424 28040000 FFFFFF | mov dword ptr ss:[esp+428],FFFFFFFF        |
00516A54     | 8D4C24 20              | lea ecx,dword ptr ss:[esp+20]              |
00516A58     | E8 83DAFFFF            | call sourceinsight4.5144E0                 |
00516A5D     | B8 CC010000            | mov eax,1CC                                | eax:&"ActId"
00516A62     | E9 5CFFFFFF            | jmp sourceinsight4.5169C3                  |
00516A67     | 85DB                   | test ebx,ebx                               |
00516A69     | 75 37                  | jne sourceinsight4.516AA2                  |
00516A6B     | 8D5424 10              | lea edx,dword ptr ss:[esp+10]              |
00516A6F     | 52                     | push edx                                   |
00516A70     | 68 94656000            | push sourceinsight4.606594                 | 606594:"HWID"
00516A75     | 8D4C24 28              | lea ecx,dword ptr ss:[esp+28]              | [esp+28]:"Serial"00516A79     | C706 01000000          | mov dword ptr ds:[esi],1                   |00516A7F     | E8 3CDBFFFF            | call sourceinsight4.5145C0                 |00516A84     | 85C0                   | test eax,eax                               | eax:&"ActId"00516A86     | 0F84 3E010000          | je sourceinsight4.516BCA                   |00516A8C     | 8B4424 10              | mov eax,dword ptr ss:[esp+10]              |00516A90     | 50                     | push eax                                   | eax:&"ActId"00516A91     | 8D8E 28060000          | lea ecx,dword ptr ds:[esi+628]             |00516A97     | 51                     | push ecx                                   |00516A98     | E8 E34C0A00            | call sourceinsight4.5BB780                 |00516A9D     | 83C4 08                | add esp,8                                  |00516AA0     | EB 06                  | jmp sourceinsight4.516AA8                  |00516AA2     | C706 03000000          | mov dword ptr ds:[esi],3                   |00516AA8     | 8D5424 10              | lea edx,dword ptr ss:[esp+10]              |00516AAC     | 52                     | push edx                                   |00516AAD     | 68 10AC5D00            | push sourceinsight4.5DAC10                 | 5DAC10:"Version"00516AB2     | 8D4C24 28              | lea ecx,dword ptr ss:[esp+28]              | [esp+28]:"Serial"00516AB6     | E8 05DBFFFF            | call sourceinsight4.5145C0                 | 取出 ["Version"] 的值00516ABB     | 85C0                   | test eax,eax                               | eax:&"ActId"00516ABD     | 0F84 07010000          | je sourceinsight4.516BCA                   |00516AC3     | 8B4424 10              | mov eax,dword ptr ss:[esp+10]              |00516AC7     | 8A00                   | mov al,byte ptr ds:[eax]                   | eax:&"ActId"00516AC9     | 3C 30                  | cmp al,30                                  | 30:'0'00516ACB     | 0F8C F9000000          | jl sourceinsight4.516BCA                   |00516AD1     | 3C 39                  | cmp al,39                                  | 39:'9'00516AD3     | 0F8F F1000000          | jg sourceinsight4.516BCA                   |00516AD9     | 0FBEC0                 | movsx eax,al                               | eax:&"ActId"00516ADC     | 83C0 D0                | add eax,FFFFFFD0                           | eax:&"ActId"00516ADF     | 8986 04060000          | mov dword ptr ds:[esi+604],eax             | eax:&"ActId"00516AE5     | 0FB60D 13956500        | movzx ecx,byte ptr ds:[659513]             |00516AEC     | 3BC1                   | cmp eax,ecx                                | eax:&"ActId"00516AEE     | 75 04                  | jne sourceinsight4.516AF4                  |00516AF0     | 3BC7                   | cmp eax,edi                                | eax:&"ActId"00516AF2     | 74 1E                  | je sourceinsight4.516B12                   |00516AF4     | C78424 28040000 FFFFFF | mov dword ptr ss:[esp+428],FFFFFFFF        |00516AFF     | 8D4C24 20              | lea ecx,dword ptr ss:[esp+20]              |00516B03     | E8 D8D9FFFF            | call sourceinsight4.5144E0                 |00516B08     | B8 EA010000            | mov eax,1EA                                | eax:&"ActId"00516B0D     | E9 B1FEFFFF            | jmp sourceinsight4.5169C3                  |00516B12     | 8D5424 10              | lea edx,dword ptr ss:[esp+10]              |00516B16     | 33DB                   | xor ebx,ebx                                |00516B18     | 52                     | push edx                                   |00516B19     | 68 88656000            | push sourceinsight4.606588                 | 606588:"Expiration"00516B1E     | 8D4C24 28              | lea ecx,dword ptr ss:[esp+28]              | [esp+28]:"Serial"00516B22     | 899E 18060000          | mov dword ptr ds:[esi+618],ebx             |00516B28     | 899E 14060000          | mov dword ptr ds:[esi+614],ebx             |00516B2E     | 899E 10060000          | mov dword ptr ds:[esi+610],ebx             |00516B34     | E8 87DAFFFF            | call sourceinsight4.5145C0                 | 取出 ["Expiration"] 的值00516B39     | 85C0                   | test eax,eax                               | eax:&"ActId"00516B3B     | 74 1F                  | je sourceinsight4.516B5C                   |00516B3D     | 8B4424 10              | mov eax,dword ptr ss:[esp+10]              |00516B41     | 50                     | push eax                                   | eax:&"ActId"00516B42     | 8D8E 10060000          | lea ecx,dword ptr ds:[esi+610]             |00516B48     | E8 E394F3FF            | call sourceinsight4.450030                 |00516B4D     | 8D8E 10060000          | lea ecx,dword ptr ds:[esi+610]             |00516B53     | E8 8881F3FF            | call sourceinsight4.44ECE0                 |00516B58     | 85C0                   | test eax,eax                               | eax:&"ActId"00516B5A     | 74 50                  | je sourceinsight4.516BAC                   |00516B5C     | 8D4C24 10              | lea ecx,dword ptr ss:[esp+10]              |00516B60     | 51                     | push ecx                                   |00516B61     | 68 D8A65E00            | push sourceinsight4.5EA6D8                 | 5EA6D8:"Date"00516B66     | 8D4C24 28              | lea ecx,dword ptr ss:[esp+28]              | [esp+28]:"Serial"00516B6A     | 899E 24060000          | mov dword ptr ds:[esi+624],ebx             |00516B70     | 899E 20060000          | mov dword ptr ds:[esi+620],ebx             |00516B76     | 899E 1C060000          | mov dword ptr ds:[esi+61C],ebx             |00516B7C     | E8 3FDAFFFF            | call sourceinsight4.5145C0                 | 取出 ["Date"] 的值00516B81     | 85C0                   | test eax,eax                               | eax:&"ActId"00516B83     | 0F84 21FEFFFF          | je sourceinsight4.5169AA                   |00516B89     | 8B5424 10              | mov edx,dword ptr ss:[esp+10]              |00516B8D     | 52                     | push edx                                   |00516B8E     | 8D8E 1C060000          | lea ecx,dword ptr ds:[esi+61C]             |00516B94     | E8 9794F3FF            | call sourceinsight4.450030                 | 检查日期的有效性00516B99     | 8D8E 1C060000          | lea ecx,dword ptr ds:[esi+61C]             |00516B9F     | E8 3C81F3FF            | call sourceinsight4.44ECE0                 |00516BA4     | 85C0                   | test eax,eax                               | 检查年、月、日的有效性00516BA6     | 0F85 FEFDFFFF          | jne sourceinsight4.5169AA                  |00516BAC     | C78424 28040000 FFFFFF | mov dword ptr ss:[esp+428],FFFFFFFF        |00516BB7     | 8D4C24 20              | lea ecx,dword ptr ss:[esp+20]              |00516BBB     | E8 20D9FFFF            | call sourceinsight4.5144E0                 |00516BC0     | B8 E3010000            | mov eax,1E3                                | eax:&"ActId"00516BC5     | E9 F9FDFFFF            | jmp sourceinsight4.5169C3                  |00516BCA     | C78424 28040000 FFFFFF | mov dword ptr ss:[esp+428],FFFFFFFF        |00516BD5     | 8D4C24 20              | lea ecx,dword ptr ss:[esp+20]              |00516BD9     | E8 02D9FFFF            | call sourceinsight4.5144E0                 |00516BDE     | B8 D5010000            | mov eax,1D5                                | eax:&"ActId"00516BE3     | E9 DBFDFFFF            | jmp sourceinsight4.5169C3                  |00516BE8     | C78424 24040000 FFFFFF | mov dword ptr ss:[esp+424],FFFFFFFF        |00516BF3     | 8D4C24 1C              | lea ecx,dword ptr ss:[esp+1C]              |00516BF7     | E8 E4D8FFFF            | call sourceinsight4.5144E0                 |00516BFC     | 8B8C24 1C040000        | mov ecx,dword ptr ss:[esp+41C]             |00516C03     | 5F                     | pop edi                                    |00516C04     | 5E                     | pop esi                                    |00516C05     | B8 D5010000            | mov eax,1D5                                | eax:&"ActId"00516C0A     | 5B                     | pop ebx                                    |00516C0B     | 64:890D 00000000       | mov dword ptr fs:[0],ecx                   |00516C12     | 81C4 1C040000          | add esp,41C                                |00516C18     | C3                     | ret                                        |
```  
  
si.lic 文件中 ActId 字段的值为 Deferred，无法通过 call sourceinsight4.403570 的 ActId 的检验。进入到 sourceinsight4.403570 函数内部后，sub_403240() 会返回一张存有很多 ActId 的表，那 ActId 表的第一项和 si.lic 文件中 ActId 字段的值进行比较。这里我们直接将软件内的 ActId 拷贝到 si.lic 文件中。  
```
int __cdecl CheckActId(char *pData, int a2, size_t Size_4, int n_x32, int n_1B7F){
  int v5; // esi
  void *ppTable; // ebp
  int v7; // edi

  v5 = 0;
  ppTable = sub_403240(a2, Size_4, n_x32, n_1B7F);// 返回了存有很多的 ActId 的表
  if ( n_x32 <= 0 )
  {
LABEL_4:
    sub_425090(ppTable);
    ReleaseBlock(ppTable);
    return 0;
  }
  else
  {
    while ( 1 )
    {
      v7 = CheckActIdHeaderFourCharacter(*(ppTable + v5), Size_4, pData);
      if ( v7 == Size_4 ) // 只比较前面四个字符
        break;
      if ( ++v5 >= n_x32 )
        goto LABEL_4;
    }
    sub_425090(ppTable);
    ReleaseBlock(ppTable);
    return v7;
  }
}
```  
  
修改 si.lic 中的 ActId 字段。  
```
ActId="673A44D35B3608E5C603D775C76216F555E000D04B6718E33E93F35887A8A360D2F468E313DC7B3E047E08F10A51B75561B5L55576B63BF2D7750F09557AF661F14849F94F2652A903A10E9074E61EA4FE7E83A6F5090AD61F3F365D1C67DA22A478FA17"
```  
# 四、si.lic 文件检验码验证  
  
读取 si.lic 文件的内容，去除掉空白字符，通过 call sourceinsight4.403210 生成校验码1，然后再使用去除掉空白字符的文件内容和 “Value” 字段的值通过 call sourceinsight4.402F00 函数生成校验码2，对比两个校验码。相同则验证通过，否则验证失败。  
```
00515F90     | B8 24210000            | mov eax,2124                         |
00515F95     | E8 36850A00            | call sourceinsight4.5BE4D0           |
00515F9A     | 56                     | push esi                             |
00515F9B     | 8BB424 2C210000        | mov esi,dword ptr ss:[esp+212C]      |
00515FA2     | 68 A01F0000            | push 1FA0                            |
00515FA7     | 8D8424 8C010000        | lea eax,dword ptr ss:[esp+18C]       |
00515FAE     | 50                     | push eax                             |
00515FAF     | 56                     | push esi                             |
00515FB0     | E8 5BE6FFFF            | call sourceinsight4.514610           | 打开文件，并读取内容。
00515FB5     | 83C4 0C                | add esp,C                            |
00515FB8     | 3D C8000000            | cmp eax,C8                           |
00515FBD     | 0F85 49010000          | jne sourceinsight4.51610C            |
00515FC3     | 8B8C24 30210000        | mov ecx,dword ptr ss:[esp+2130]      |
00515FCA     | 51                     | push ecx                             | ecx:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
00515FCB     | 8D9424 8C010000        | lea edx,dword ptr ss:[esp+18C]       |
00515FD2     | 52                     | push edx                             |
00515FD3     | E8 88F8FFFF            | call sourceinsight4.515860           | 文件内容追加 C 盘的 GUID 生成一个 20 位的校验值
00515FD8     | 56                     | push esi                             |
00515FD9     | E8 0257F4FF            | call sourceinsight4.45B6E0           | 将文件内容转换为 XML 格式
00515FDE     | 83C4 0C                | add esp,C                            |
00515FE1     | 85C0                   | test eax,eax                         |
00515FE3     | 75 0D                  | jne sourceinsight4.515FF2            |
00515FE5     | B8 CC010000            | mov eax,1CC                          |
00515FEA     | 5E                     | pop esi                              |
00515FEB     | 81C4 24210000          | add esp,2124                         |
00515FF1     | C3                     | ret                                  |
00515FF2     | 68 085E6000            | push sourceinsight4.605E08           | 605E08:"Signature"
00515FF7     | 8BC8                   | mov ecx,eax                          | ecx:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
00515FF9     | E8 722AF4FF            | call sourceinsight4.458A70           | 判断是否有 "Sigature" 字段
00515FFE     | 8BF0                   | mov esi,eax                          |
00516000     | 85F6                   | test esi,esi                         |
00516002     | 74 E1                  | je sourceinsight4.515FE5             |
00516004     | 68 889D5E00            | push sourceinsight4.5E9D88           | 5E9D88:"Value"
00516009     | 8BCE                   | mov ecx,esi                          | ecx:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
0051600B     | E8 4032F4FF            | call sourceinsight4.459250           | 检查 "Value" 是否存在
00516010     | 85C0                   | test eax,eax                         |
00516012     | 74 D1                  | je sourceinsight4.515FE5             |
00516014     | 55                     | push ebp                             |
00516015     | 57                     | push edi                             |
00516016     | 8B78 18                | mov edi,dword ptr ds:[eax+18]        |
00516019     | 8B46 20                | mov eax,dword ptr ds:[esi+20]        |
0051601C     | 8D8C24 90010000        | lea ecx,dword ptr ss:[esp+190]       |
00516023     | 51                     | push ecx                             | ecx:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
00516024     | C68404 94010000 00     | mov byte ptr ss:[esp+eax+194],0      |
0051602C     | E8 AFE8F2FF            | call sourceinsight4.4448E0           | 拷贝一个新的文件数据
00516031     | 8BE8                   | mov ebp,eax                          |
00516033     | 83C4 04                | add esp,4                            |
00516036     | 85ED                   | test ebp,ebp                         |
00516038     | 75 0F                  | jne sourceinsight4.516049            |
0051603A     | 5F                     | pop edi                              |
0051603B     | 5D                     | pop ebp                              |
0051603C     | B8 EC010000            | mov eax,1EC                          |
00516041     | 5E                     | pop esi                              |
00516042     | 81C4 24210000          | add esp,2124                         |
00516048     | C3                     | ret                                  |
00516049     | 55                     | push ebp                             |
0051604A     | 8D9424 94010000        | lea edx,dword ptr ss:[esp+194]       |
00516051     | 68 0C606000            | push sourceinsight4.60600C           | 60600C:"\n\r\t "
00516056     | 52                     | push edx                             |
00516057     | E8 14EAF2FF            | call sourceinsight4.444A70           | 取出掉文件数据中的空白字符
0051605C     | 83C4 0C                | add esp,C                            |
0051605F     | 8D4424 10              | lea eax,dword ptr ss:[esp+10]        |
00516063     | 50                     | push eax                             |
00516064     | 68 80000000            | push 80                              |
00516069     | 68 B0070000            | push 7B0                             |
0051606E     | 55                     | push ebp                             |
0051606F     | E8 6C4E0A00            | call sourceinsight4.5BAEE0           | 算算新长度
00516074     | 83C4 04                | add esp,4                            |
00516077     | 40                     | inc eax                              |
00516078     | 50                     | push eax                             |
00516079     | 55                     | push ebp                             |
0051607A     | E8 91D1EEFF            | call sourceinsight4.403210           | 根据新的文件数据重新生成新的 20 位序列号
0051607F     | 8D4C24 20              | lea ecx,dword ptr ss:[esp+20]        |
00516083     | 51                     | push ecx                             | ecx:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
00516084     | 8D9424 A8000000        | lea edx,dword ptr ss:[esp+A8]        |
0051608B     | 52                     | push edx                             |
0051608C     | 57                     | push edi                             |
0051608D     | E8 6ECEEEFF            | call sourceinsight4.402F00           | 根据 ["Value"] 的值和文件内容生成一个 20 位序列号00516092     | 83C4 20                | add esp,20                           |00516095     | 817C24 0C 80000000     | cmp dword ptr ss:[esp+C],80          |0051609D     | 75 50                  | jne sourceinsight4.5160EF            |0051609F     | B8 80000000            | mov eax,80                           |005160A4     | 8D4C24 10              | lea ecx,dword ptr ss:[esp+10]        |005160A8     | 8DB424 90000000        | lea esi,dword ptr ss:[esp+90]              | esi:EntryPoint005160AF     | 90                     | nop                                        |005160B0     | 8B16                   | mov edx,dword ptr ds:[esi]                 | edx:EntryPoint, esi:EntryPoint005160B2     | 3B11                   | cmp edx,dword ptr ds:[ecx]                 | edx:EntryPoint, ecx:EntryPoint005160B4     | 75 39                  | jne sourceinsight4_original.5160EF         |005160B6     | 83E8 04                | sub eax,4                                  |005160B9     | 83C1 04                | add ecx,4                                  | ecx:EntryPoint005160BC     | 83C6 04                | add esi,4                                  | esi:EntryPoint005160BF     | 83F8 04                | cmp eax,4                                  |005160C2     | 73 EC                  | jae sourceinsight4.5160B0            |005160C4     | 85C0                   | test eax,eax                         |005160C6     | 74 20                  | je sourceinsight4.5160E8             |005160C8     | 8A11                   | mov dl,byte ptr ds:[ecx]             | ecx:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"005160CA     | 3A16                   | cmp dl,byte ptr ds:[esi]             |005160CC     | 75 21                  | jne sourceinsight4.5160EF            |005160CE     | 83F8 01                | cmp eax,1                            |005160D1     | 76 15                  | jbe sourceinsight4.5160E8            |005160D3     | 8A51 01                | mov dl,byte ptr ds:[ecx+1]           | ecx+1:":\\ProgramData\\Source Insight\\4.0\\si4.lic"005160D6     | 3A56 01                | cmp dl,byte ptr ds:[esi+1]           |005160D9     | 75 14                  | jne sourceinsight4.5160EF            |005160DB     | 83F8 02                | cmp eax,2                            |005160DE     | 76 08                  | jbe sourceinsight4.5160E8            |005160E0     | 8A41 02                | mov al,byte ptr ds:[ecx+2]           | ecx+2:"\\ProgramData\\Source Insight\\4.0\\si4.lic"005160E3     | 3A46 02                | cmp al,byte ptr ds:[esi+2]           |005160E6     | 75 07                  | jne sourceinsight4.5160EF            |005160E8     | BE 01000000            | mov esi,1                            |005160ED     | EB 02                  | jmp sourceinsight4.5160F1            |005160EF     | 33F6                   | xor esi,esi                          |005160F1     | 55                     | push ebp                             |005160F2     | E8 39EDF0FF            | call sourceinsight4.424E30           |005160F7     | 83C4 04                | add esp,4                            |005160FA     | 8BC6                   | mov eax,esi                          |005160FC     | F7D8                   | neg eax                              |005160FE     | 1BC0                   | sbb eax,eax                          |00516100     | 25 FAFEFFFF            | and eax,FFFFFEFA                     |00516105     | 5F                     | pop edi                              |00516106     | 05 CE010000            | add eax,1CE                          |0051610B     | 5D                     | pop ebp                              |0051610C     | 5E                     | pop esi                              |0051610D     | 81C4 24210000          | add esp,2124                         |00516113     | C3                     | ret                                  |
```  
  
这里我们将验证码比较部分，去除掉验证码不相同的判断。  
```
005160B2     | 3B11                   | cmp edx,dword ptr ds:[ecx]                 | edx:EntryPoint, ecx:EntryPoint
005160B4     | 75 39                  | jne sourceinsight4_original.5160EF         |
```  
  
改为  
```
0051609F     | B8 80000000            | mov eax,80                           |
005160A4     | 8D4C24 10              | lea ecx,dword ptr ss:[esp+10]        |
005160A8     | 8DB424 90000000        | lea esi,dword ptr ss:[esp+90]        |
005160AF     | 90                     | nop                                  |
005160B0     | 8B16                   | mov edx,dword ptr ds:[esi]           |
005160B2     | 90                     | nop                                  |
005160B3     | 90                     | nop                                  |
005160B4     | 90                     | nop                                  |
005160B5     | 90                     | nop                                  |
005160B6     | 83E8 04                | sub eax,4                            |
005160B9     | 83C1 04                | add ecx,4                            |
005160BC     | 83C6 04                | add esi,4                            |
005160BF     | 83F8 04                | cmp eax,4                            |
005160C2     | 73 EC                  | jae sourceinsight4.5160B0            |
```  
# 五、硬件设备的验证  
  
硬件设备的检验的关键代码  
```
00517920     | 81EC 00010000          | sub esp,100                          |
00517926     | 56                     | push esi                             |
00517927     | 57                     | push edi                             | edi:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
00517928     | 68 7F1B0000            | push 1B7F                            |
0051792D     | 6A 32                  | push 32                              |
0051792F     | 8BF1                   | mov esi,ecx                          |
00517931     | 6A 04                  | push 4                               |
00517933     | 8D86 3A060000          | lea eax,dword ptr ds:[esi+63A]       | esi+63A:"673A44D35B3608E5C603D775C76216F555E000D04B6718E33E93F35887A8A360D2F468E313DC7B3E047E08F10A51B75561B5L55576B63BF2D7750F09557AF661F14849F94F2652A903A10E9074E61EA4FE7E83A6F5090AD61F3F365D1C67DA22A478FA17"
00517939     | 68 701A6500            | push sourceinsight4.651A70           |
0051793E     | 50                     | push eax                             |
0051793F     | E8 2CBCEEFF            | call sourceinsight4.403570           | 检查 ActId 
00517944     | 8BF8                   | mov edi,eax                          | edi:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
00517946     | 83C4 14                | add esp,14                           |
00517949     | 85FF                   | test edi,edi                         | edi:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
0051794B     | 75 0B                  | jne sourceinsight4.517958            |
0051794D     | 5F                     | pop edi                              | edi:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
0051794E     | 33C0                   | xor eax,eax                          |
00517950     | 5E                     | pop esi                              |
00517951     | 81C4 00010000          | add esp,100                          |
00517957     | C3                     | ret                                  |
00517958     | 8D4C24 08              | lea ecx,dword ptr ss:[esp+8]         |
0051795C     | 6A 00                  | push 0                               |
0051795E     | 51                     | push ecx                             |
0051795F     | E8 7CF5FFFF            | call sourceinsight4.516EE0           | 根据软件信息、token、硬件信息等生成一个序列
00517964     | 83C4 08                | add esp,8                            |
00517967     | 85C0                   | test eax,eax                         |
00517969     | 74 E2                  | je sourceinsight4.51794D             |
0051796B     | 8D5424 08              | lea edx,dword ptr ss:[esp+8]         |
0051796F     | 52                     | push edx                             |
00517970     | 8D8437 3A060000        | lea eax,dword ptr ds:[edi+esi+63A]   |
00517977     | 50                     | push eax                             |
00517978     | E8 83400A00            | call sourceinsight4.5BBA00           | 序列比较
0051797D     | 83C4 08                | add esp,8                            |
00517980     | F7D8                   | neg eax                              |
00517982     | 1BC0                   | sbb eax,eax                          |
00517984     | 5F                     | pop edi                              | edi:"C:\\ProgramData\\Source Insight\\4.0\\si4.lic"
00517985     | 40                     | inc eax                              |
00517986     | 5E                     | pop esi                              |
00517987     | 81C4 00010000          | add esp,100                          |
0051798D     | C3                     | ret                                  |
```  
  
call sourceinsight4.516EE0 会根据软件信息、token、硬件信息等生成一个序列，然后将这个序列会和一个 "44D35B3608E5C603D775C76216F555E000D04B6718E33E93F35887A8A360D2F468E313DC7B3E047E08F10A51B75561B5L55576B63BF2D7750F09557AF661F14849F94F2652A903A10E9074E61EA4FE7E83A6F5090AD61F3F365D1C67DA22A478FA17" 的序列做比较。相同，则验证通过。  
  
这里我们将函数的返回 eax 改为 1，表示验证通过。  
```
00517978     | E8 83400A00            | call sourceinsight4_fix6.5BBA00            |
0051797D     | 83C4 08                | add esp,8                                  |
00517980     | 31C0                   | xor eax,eax                                |
00517982     | 90                     | nop                                        |
00517983     | 90                     | nop                                        |
00517984     | 5F                     | pop edi                                    | edi:EntryPoint
00517985     | 40                     | inc eax                                    |
00517986     | 5E                     | pop esi                                    | esi:EntryPoint
00517987     | 81C4 00010000          | add esp,100                                |
0051798D     | C3                     | ret                                        |
```  
# 六、验证  
  
破解成功  
  
  
  
**-官方论坛**  
  
www.52pojie.cn  
  
  
**--推荐给朋友**  
  
公众微信号：吾爱破解论坛  
  
或搜微信号：pojie_52  
  

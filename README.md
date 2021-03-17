## 结论: 

```
oppo 搜索api:
https://api-cn.store.heytapmobi.com/search/v1/completion/card?size=10&start=0&associa_type=1&keyword=网易亲时光

必备header:
t: 1612490906391
id: 300000000078961///
sign: 73e7a8763ff6d8c06f89111177e44be2
oak: cdb09c43063ea6bb
ocs: Android%2FMuMu%2F23%2F6.0.1%2FUNKNOWN%2F2%2FV417IR+release-keys%2F81040

需要弄清楚sign如何计算
```

## 
```
public static final String PARAM = "ocs";
request.addHeader(PARAM, str2);


addSign(request, str2, currentTimeMillis, openId);

str = ocs
j = currentTimeMillis
str2 = openid
str3 = uri.getPath();
str4 = uri.getQuery();


StringBuilder sb = new StringBuilder(str);
sb.append(j);
sb.append(str2);
sb.append(str3);
sb.append(str4);
String c = OcsTool.c(sb.toString(), sb.length());
request.addHeader(SIGN, c);

u = "cdb09c43063ea6bb08f4fe8a43775179bdc58acb383220be" + ocs + currentTimeMillis + openid + uri.getPath() + uri.getQuery()
sign = md5(u + len(u) + "STORENEWMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANYFY/UJGSzhIhpx6YM5KJ9yRHc7YeURxzb9tDvJvMfENHlnP3DtVkOIjERbpsSd76fjtZnMWY60TpGLGyrNkvuV40L15JQhHAo9yURpPQoI0eg3SLFmTEI/MUiPRCwfwYf2deqKKlsmMSysYYHX9JiGzQuWiYZaawxprSuiqDGvAgMBAAECgYEAtQ0QV00gGABISljNMy5aeDBBTSBWG2OjxJhxLRbndZM81OsMFysgC7dq+bUS6ke1YrDWgsoFhRxxTtx/2gDYciGp/c/h0Td5pGw7T9W6zo2xWI5oh1WyTnn0Xj17O9CmOk4fFDpJ6bapL+fyDy7gkEUChJ9+p66WSAlsfUhJ2TECQQD5sFWMGE2IiEuz4fIPaDrNSTHeFQQr/ZpZ7VzB2tcG7GyZRx5YORbZmX1jR7l3H4F98MgqCGs88w6FKnCpxDK3AkEA225CphAcfyiH0ShlZxEXBgIYt3V8nQuc/g2KJtiV6eeFkxmOMHbVTPGkARvt5VoPYEjwPTg43oqTDJVtlWagyQJBAOvEeJLno9aHNExvznyD4/pR4hec6qqLNgMyIYMfHCl6d3UodVvC1HO1/nMPl+4GvuRnxuoBtxj/PTe7AlUbYPMCQQDOkf4sVv58tqslO+I6JNyHy3F5RCELtuMUR6rG5x46FLqqwGQbO8ORq+m5IZHTV/Uhr4h6GXNwDQRh1EpVW0gBAkAp/v3tPI1riz6UuG0I6uf5er26yl5evPyPrjrD299L4Qy/1EIunayC7JYcSGlR01+EDYYgwUkec+QgrRC/NstV")

```



## 例子
计算例子
```
from typing import Mapping
import requests
import hashlib
import time
from urllib.parse import urlparse

url = 'https://api-cn.store.heytapmobi.com/search/v1/completion/card?size=10&start=0&associa_type=1&keyword={}'

prefix = r'cdb09c43063ea6bb08f4fe8a43775179bdc58acb383220be'
suffix = r'STORENEWMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANYFY/UJGSzhIhpx6YM5KJ9yRHc7YeURxzb9tDvJvMfENHlnP3DtVkOIjERbpsSd76fjtZnMWY60TpGLGyrNkvuV40L15JQhHAo9yURpPQoI0eg3SLFmTEI/MUiPRCwfwYf2deqKKlsmMSysYYHX9JiGzQuWiYZaawxprSuiqDGvAgMBAAECgYEAtQ0QV00gGABISljNMy5aeDBBTSBWG2OjxJhxLRbndZM81OsMFysgC7dq+bUS6ke1YrDWgsoFhRxxTtx/2gDYciGp/c/h0Td5pGw7T9W6zo2xWI5oh1WyTnn0Xj17O9CmOk4fFDpJ6bapL+fyDy7gkEUChJ9+p66WSAlsfUhJ2TECQQD5sFWMGE2IiEuz4fIPaDrNSTHeFQQr/ZpZ7VzB2tcG7GyZRx5YORbZmX1jR7l3H4F98MgqCGs88w6FKnCpxDK3AkEA225CphAcfyiH0ShlZxEXBgIYt3V8nQuc/g2KJtiV6eeFkxmOMHbVTPGkARvt5VoPYEjwPTg43oqTDJVtlWagyQJBAOvEeJLno9aHNExvznyD4/pR4hec6qqLNgMyIYMfHCl6d3UodVvC1HO1/nMPl+4GvuRnxuoBtxj/PTe7AlUbYPMCQQDOkf4sVv58tqslO+I6JNyHy3F5RCELtuMUR6rG5x46FLqqwGQbO8ORq+m5IZHTV/Uhr4h6GXNwDQRh1EpVW0gBAkAp/v3tPI1riz6UuG0I6uf5er26yl5evPyPrjrD299L4Qy/1EIunayC7JYcSGlR01+EDYYgwUkec+QgrRC/NstV'


def getSign(keyword: str):
    u = urlparse(url.format(keyword))

    headers = {
        "t": str(int(round(time.time() * 1000))),
        "id": "id",
        "oak": "cdb09c43063ea6bb",
        "ocs": "ocs"
    }

    data = prefix + headers["ocs"] + headers["t"] + headers["id"] + u.path + u.query
    sign = data + str(len(data)) + suffix
    headers["sign"] = hashlib.md5(sign.encode("utf-8")).hexdigest()

    resp = requests.get(u.geturl(), headers=headers)
    print(resp.text)
    
    

getSign("uu加速器")


```


```
https://api-cn.store.heytapmobi.com/search/v1/completion/card?size=1&start=0&associa_type=1&keyword=uu加速器

header:
t:1612490906391
id:300000000078961
sign:BD6065375794A47F930159DB7BB6F3FD
oak:cdb09c43063ea6bb
ocs:testphone
```

## sign 计算方式解析
### 加密函数所在
> 参考资料 https://www.jianshu.com/p/87ce6f565d37
```
文件: libocstool.so
Java_com_heytap_cdo_client_OcsTool_c
```


### 反汇编结果：
```
int __fastcall Java_com_heytap_cdo_client_OcsTool_c(int *a1, int a2, int a3, int a4)
{
  int v5; // r0
  int v6; // r9
  int v7; // r11
  int v8; // r5
  int v9; // r8
  int v10; // r0
  int v11; // r10
  int v12; // r5
  int v14; // r5
  char *v15; // r5
  int v16; // r0
  int v17; // r6
  int v18; // r0
  int v19; // r5
  int v20; // r9
  int v21; // r5
  int v22; // r0
  int v23; // r8
  int v26; // [sp+Ch] [bp-14h]
  int v27; // [sp+10h] [bp-10h]

  v5 = *a1;
  if ( byte_604C != 1 )
    return (*(int (__fastcall **)(int *, const char *))(v5 + 668))(a1, "-");
  v27 = (*(int (__fastcall **)(int *, const char *))(v5 + 24))(a1, "java/lang/String");
  v6 = (*(int (__fastcall **)(int *, int, const char *, const char *))(*a1 + 132))(a1, v27, "getBytes", "()[B");
  v7 = (*(int (__fastcall **)(int *, const char *))(*a1 + 24))(a1, "java/security/MessageDigest");
  v8 = (*(int (__fastcall **)(int *, int, const char *, const char *))(*a1 + 452))(
         a1,
         v7,
         "getInstance",
         "(Ljava/lang/String;)Ljava/security/MessageDigest;");
  v9 = (*(int (__fastcall **)(int *, int, const char *, const char *))(*a1 + 132))(a1, v7, "update", "([B)V");
  v26 = (*(int (__fastcall **)(int *, int, const char *, const char *))(*a1 + 132))(a1, v7, "digest", "()[B");
  v10 = (*(int (__fastcall **)(int *, const char *))(*a1 + 668))(a1, "MD5");
  v11 = _JNIEnv::CallStaticObjectMethod(a1, v7, v8, v10);
  if ( k2 )
  {
    v12 = (*(int (__fastcall **)(int *, int))(*a1 + 704))(a1, 48);
    (*(void (__fastcall **)(int *, int, _DWORD, int, int))(*a1 + 832))(a1, v12, 0, 48, k2);
    _JNIEnv::CallVoidMethod(a1, v11, v9, v12);
    (*(void (__fastcall **)(int *, int))(*a1 + 92))(a1, v12);
  }
  else
  {
    _android_log_print(3, LOG_TAG, "::c k2 is null.");
  }
  v14 = _JNIEnv::CallObjectMethod(a1, a3, v6);
  _JNIEnv::CallVoidMethod(a1, v11, v9, v14);
  (*(void (__fastcall **)(int *, int))(*a1 + 92))(a1, v14);
  v15 = (char *)malloc(0xBu);
  sprintf(v15, "%d", a4 + 48);
  v16 = (*(int (__fastcall **)(int *, char *))(*a1 + 668))(a1, v15);
  v17 = _JNIEnv::CallObjectMethod(a1, v16, v6);
  _JNIEnv::CallVoidMethod(a1, v11, v9, v17);
  free(v15);
  (*(void (__fastcall **)(int *, int))(*a1 + 92))(a1, v17);
  v18 = (*(int (__fastcall **)(int *, char *))(*a1 + 668))(a1, OBSCURE_CODE);
  v19 = _JNIEnv::CallObjectMethod(a1, v18, v6);
  _JNIEnv::CallVoidMethod(a1, v11, v9, v19);
  (*(void (__fastcall **)(int *, int))(*a1 + 92))(a1, v19);
  v20 = _JNIEnv::CallObjectMethod(a1, v11, v26);
  v21 = (*(int (__fastcall **)(int *, const char *))(*a1 + 24))(a1, "com/nearme/common/util/HashUtil");
  v22 = (*(int (__fastcall **)(int *, int, const char *, const char *))(*a1 + 452))(
          a1,
          v21,
          "toHex",
          "([B)Ljava/lang/String;");
  v23 = _JNIEnv::CallStaticObjectMethod(a1, v21, v22, v20);
  (*(void (__fastcall **)(int *, int))(*a1 + 92))(a1, v11);
  (*(void (__fastcall **)(int *, int))(*a1 + 92))(a1, v7);
  (*(void (__fastcall **)(int *, int))(*a1 + 92))(a1, v27);
  (*(void (__fastcall **)(int *, int))(*a1 + 92))(a1, v20);
  (*(void (__fastcall **)(int *, int))(*a1 + 92))(a1, v21);
  return v23;
}
```


### 大致逻辑
```
int __fastcall Java_com_heytap_cdo_client_OcsTool_c(JNIEnv *a1, int a2, int str, int len) {
    // prepare something
    // ...
    // get method or class
    // ...
    MD5 = findclass().getInstance()
    
    
    // update key
    if key {
        MD5.update(key.getBytes())
    } else {
        log("key is null")
    }
    
    // update str
    MD5.update(str.getBytes())
    
    // update len.  key长度为48
    MD5.update(str(len+48).getBytes())
    
    // update OBSCURE_CODE
    MD5.update(OBSCURE_CODE.getBytes())
    
    // release ref
    
    return MD5.digest()
}
```

### OBSCURE_CODE 为常量内容
```
.rodata:000035F2 aStorenewmiicea DCB "STORENEWMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANYFY/UJ"
.rodata:000035F2                                         ; DATA XREF: Java_com_heytap_cdo_client_OcsTool_c+194↑o
.rodata:000035F2                                         ; .data:OBSCURE_CODE↓o
.rodata:000035F2                 DCB "GSzhIhpx6YM5KJ9yRHc7YeURxzb9tDvJvMfENHlnP3DtVkOIjERbpsSd76fjtZnM"
.rodata:000035F2                 DCB "WY60TpGLGyrNkvuV40L15JQhHAo9yURpPQoI0eg3SLFmTEI/MUiPRCwfwYf2deqK"
.rodata:000035F2                 DCB "KlsmMSysYYHX9JiGzQuWiYZaawxprSuiqDGvAgMBAAECgYEAtQ0QV00gGABISljN"
.rodata:000035F2                 DCB "My5aeDBBTSBWG2OjxJhxLRbndZM81OsMFysgC7dq+bUS6ke1YrDWgsoFhRxxTtx/"
.rodata:000035F2                 DCB "2gDYciGp/c/h0Td5pGw7T9W6zo2xWI5oh1WyTnn0Xj17O9CmOk4fFDpJ6bapL+fy"
.rodata:000035F2                 DCB "Dy7gkEUChJ9+p66WSAlsfUhJ2TECQQD5sFWMGE2IiEuz4fIPaDrNSTHeFQQr/ZpZ"
.rodata:000035F2                 DCB "7VzB2tcG7GyZRx5YORbZmX1jR7l3H4F98MgqCGs88w6FKnCpxDK3AkEA225CphAc"
.rodata:000035F2                 DCB "fyiH0ShlZxEXBgIYt3V8nQuc/g2KJtiV6eeFkxmOMHbVTPGkARvt5VoPYEjwPTg4"
.rodata:000035F2                 DCB "3oqTDJVtlWagyQJBAOvEeJLno9aHNExvznyD4/pR4hec6qqLNgMyIYMfHCl6d3Uo"
.rodata:000035F2                 DCB "dVvC1HO1/nMPl+4GvuRnxuoBtxj/PTe7AlUbYPMCQQDOkf4sVv58tqslO+I6JNyH"
.rodata:000035F2                 DCB "y3F5RCELtuMUR6rG5x46FLqqwGQbO8ORq+m5IZHTV/Uhr4h6GXNwDQRh1EpVW0gB"
.rodata:000035F2                 DCB "AkAp/v3tPI1riz6UuG0I6uf5er26yl5evPyPrjrD299L4Qy/1EIunayC7JYcSGlR"
.rodata:000035F2                 DCB "01+EDYYgwUkec+QgrRC/NstV",0
```

### key获取

#### apk中
```
com.heytap.cdo.client.OcsTool 
loadLibrary后调用 OcsTool.a(AppUtil.getAppContext())
```

#### libocstool.so中
```
int __fastcall Java_com_heytap_cdo_client_OcsTool_a(int a1, int a2, int a3) {
    // prepare something
    // ...
    // get method or class
    // ...
    ...
    init_keys(v14, packagename_struct);
    ...
}

init_keys(a1, a2) {
    ...
    if ( !strcmp(v5, "com.oppo.market") )
    {
      v6 = "cdb09c43063ea6bb";
      v7 = "09bdc58acb383220be08f4fe8a43775179";
    }
    else if ( !strcmp(v5, "com.heytap.market") )
    {
      v6 = "cdb09c43063ea6bb";
      v7 = "09bdc58acb383220be08f4fe8a43775179";
    }
    ...
    result = (void *)init_keys2(v6, v7);
}

int __fastcall init_keys2(char *a1, char *a2)
{
  _BYTE *v4; // r6
  int i; // r0
  int v6; // r0
  char v7; // r3
  int v8; // r2
  int result; // r0

  v4 = malloc(0x11u);
  k = (int)v4;
  key = (int)malloc(0x31u);
  for ( i = 0; i != 16; ++i )
  {
    v4[i] = a1[i];
    *(_BYTE *)(key + i) = *(_BYTE *)(k + i);
    v4 = (_BYTE *)k;
  }
  v6 = 0;
  *(_BYTE *)(k + 16) = 0;
  do
  {
    *(_BYTE *)(key + v6 + 16) = a2[v6 + 18];
    v7 = a2[v6 + 2];
    v8 = key + v6++;
    *(_BYTE *)(v8 + 32) = v7;
  }
  while ( v6 != 16 );
  result = key;
  *(_BYTE *)(key + 48) = 0;
  return result;
}
```

#### 改为python计算结果
```
def init_key(a1, a2):
    key = [c for c in a1] + [''] * 32

    i = 0
    while True:
        key[i+16] = a2[i+18]

        v7 = a2[i+2]
        
        key[i+32] = v7
        i = i + 1

        if i == 16:
            break
    
    print(''.join(key))
        

if __name__ == "__main__":
    init_key("cdb09c43063ea6bb", "09bdc58acb383220be08f4fe8a43775179")
    # print cdb09c43063ea6bb08f4fe8a43775179bdc58acb383220be
```

#### key
```
cdb09c43063ea6bb08f4fe8a43775179bdc58acb383220be
```

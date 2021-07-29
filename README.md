# SM2_related

提供Sm3WithSm2的Java端签名，Golang端验签的demo（已测试成功）

签名返回格式：b64Encode(r || s)

公私🔑的生成可使用openssl：

```sh
openssl ecparam -genkey -name SM2 -out sm2PriKey.pem
openssl ec -in sm2PriKey.pem -pubout -out sm2PubKey.pem
openssl ec -in sm2PriKey.pem -text
openssl pkcs8 -topk8 -inform PEM -in sm2PriKey.pem -outform pem -nocrypt -out sm2PriKeyPkcs8.pem
# 私钥读取需要pkcs8
```

参考链接：

https://segmentfault.com/a/1190000019528217

https://blog.csdn.net/pridas/article/details/86118774
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func RSAGenKey(bits int) error {
	/*
		生成私钥
	*/
	//1、使用RSA中的GenerateKey方法生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	//2、通过X509标准将得到的RAS私钥序列化为：ASN.1 的DER编码字符串
	privateStream := x509.MarshalPKCS1PrivateKey(privateKey)
	//3、将私钥字符串设置到pem格式块中
	block1 := pem.Block{
		Type:  "private key",
		Bytes: privateStream,
	}
	//4、通过pem将设置的数据进行编码，并写入磁盘文件
	fPrivate, err := os.Create("privateKey.pem")
	if err != nil {
		return err
	}
	defer fPrivate.Close()
	err = pem.Encode(fPrivate, &block1)
	if err != nil {
		return err
	}

	/*
		生成公钥
	*/
	publicKey:=privateKey.PublicKey
	publicStream,err:=x509.MarshalPKIXPublicKey(&publicKey)
	//publicStream:=x509.MarshalPKCS1PublicKey(&publicKey)
	block2:=pem.Block{
		Type:"public key",
		Bytes:publicStream,
	}
	fPublic,err:=os.Create("publicKey.pem")
	if err!=nil {
		return  err
	}
	defer fPublic.Close()
	pem.Encode(fPublic,&block2)
	return nil
}
//对数据进行加密操作
func  EncyptogRSA(src []byte,path string) (res []byte,err error) {
	//1.获取秘钥（从本地磁盘读取）
	f,err:=os.Open(path)
	if err!=nil {
		return
	}
	defer f.Close()
	fileInfo,_:=f.Stat()
	b:=make([]byte,fileInfo.Size())
	f.Read(b)
	// 2、将得到的字符串解码
	block,_:=pem.Decode(b)

	// 使用X509将解码之后的数据 解析出来
	//x509.MarshalPKCS1PublicKey(block):解析之后无法用，所以采用以下方法：ParsePKIXPublicKey
	keyInit,err:=x509.ParsePKIXPublicKey(block.Bytes)  //对应于生成秘钥的x509.MarshalPKIXPublicKey(&publicKey)
	//keyInit1,err:=x509.ParsePKCS1PublicKey(block.Bytes)
	if err!=nil {
		return
	}
	fmt.Println(keyInit)

	str1 := "-----BEGIN public key-----\nMFowDQYJKoZIhvcNAQEBBQADSQAwRgI/DnUiG+kSiTrE9w5FntHNqBPaBW75yXnG\naFt49hTh5dWdFMLQu4272KPYB4Up6e0pu3czSaUS3GlFYoCIUoZXAgMBAAE=\n-----END public key-----"
	block1,_ := pem.Decode([]byte(str1))
	keyInit1,_ := x509.ParsePKIXPublicKey(block1.Bytes)


	//4.使用公钥加密数据
	pubKey:=keyInit1.(*rsa.PublicKey)
	res,err=rsa.EncryptPKCS1v15(rand.Reader,pubKey,src)
	return
}
//对数据进行解密操作
func DecrptogRSA(src []byte,path string)(res []byte,err error)  {
	//1.获取秘钥（从本地磁盘读取）
	f,err:=os.Open(path)
	if err!=nil {
		return
	}
	defer f.Close()
	fileInfo,_:=f.Stat()
	b:=make([]byte,fileInfo.Size())
	f.Read(b)
	block,_:=pem.Decode(b)//解码
	privateKey,err:=x509.ParsePKCS1PrivateKey(block.Bytes)//还原数据
	res,err=rsa.DecryptPKCS1v15(rand.Reader,privateKey,src)
	return
}

func main() {

	//rsa.GenerateKey()
	//err:=RSAGenKey(500)
	//if err!=nil {
	//	fmt.Println(err)
	//	return
	//}
	//fmt.Println("秘钥生成成功！")
	str:="山重水复疑无路，柳暗花明又一村！"
	fmt.Println("加密之前的数据为：",string(str))
	dataSec,_:=EncyptogRSA([]byte(str),"publicKey.pem")
	fmt.Println("加密之后的数据为：",string(dataSec))
	data,_ := DecrptogRSA(dataSec,"privateKey.pem")
	fmt.Println("解密之后的数据为：",string(data))



	str1 := "-----BEGIN private key-----\nMIIBMwIBAAI/DnUiG+kSiTrE9w5FntHNqBPaBW75yXnGaFt49hTh5dWdFMLQu427\n2KPYB4Up6e0pu3czSaUS3GlFYoCIUoZXAgMBAAECPwI0vU+k8L8fyI4qD1V8jfTn\nkozhshucCTpDOuHRreZy2MKRd6XYp5Z10biVpbXBHTCu8ujQgtdsH3uInhO4gQIg\nA9foS503JNri1R4dJNQI1gATqi6lbMsxS59Tz4UbwvsCIAPC/LCxfJ6aHz5WbHDD\nXDSUGv9OlJFGPIziEpSBDgtVAh9zJlajIa8Ihv+WNKb4wcf53lNOfkHLTguhq/df\nhq49AiAApvcvH6buzOQr58onhwfeqetAZvyFb7sh5jS4gOPRfQIgAv9GA4VeYFYu\nMmmlx5Npls5zmiyL+sjacUuR+TpbY3c=\n-----END private key-----\n"
	block,_ := pem.Decode([]byte(str1))
	private,_ := x509.ParsePKCS1PrivateKey(block.Bytes)
	// 使用X509将解码之后的数据解析出来
	//x509.MarshalPKCS1PublicKey(block):解析之后无法用，所以采用以下方法：ParsePKIXPublicKey
	//keyInit,err:=x509.ParsePKIXPublicKey(block.Bytes)  //对应于生成秘钥的x509.MarshalPKIXPublicKey(&publicKey)
	//keyInit,err:=x509.ParsePKCS8PrivateKey(block.Bytes)
	//keyInit1,err:=x509.ParsePKCS1PublicKey(block.Bytes)

	fmt.Println(dataSec)
	res,_ := rsa.DecryptPKCS1v15(rand.Reader,private,dataSec)
	fmt.Println("res:",string(res))
}
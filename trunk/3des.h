#ifndef UTlDes_h__
#define UTlDes_h__

namespace UTlDes
{
	/*-------------------------------------------------------------------------------------

	说明：
	使用者可选择1轮DES加密或3轮DES加密，通常1轮DES加密即可满足要求。

	因并非每个用户需要保留原始的明文，故考虑到效率，加密函数直接修改明文使之变成密文
	而不输出一份新的密文，如需保留明文，请在加密前复制一份。

	des加密后的密文长度一定为64bit的整倍数，所以对明文的长度也要求为<*64bit的整倍数*>
	即4,8,12,16……字节长度的数据。

	---------------------------------------------------------------------------------------*/


	unsigned char* Encrypt(unsigned char* source, unsigned long length);

	unsigned char* Decrypt(unsigned char* source, unsigned long length);

	unsigned char* Encrypt3(unsigned char* source, unsigned long length);

	unsigned char* Decrypt3(unsigned char* source, unsigned long length);



	/////////////////////////////////////////////////////////////////////////////////////
	//以下为通用的Des函数

	//	Des加密
	//	参数：
	//	[IN/OUT] unsigned char* source						源数据
	//	[IN]     const unsigned char SubKey[16][6]			16个子密钥
	//	[IN]     unsigned long length				长度（字节数）
	unsigned char* CommonEncrypt(unsigned char* source, const unsigned char SubKey[16][6], unsigned long length);

	//	Des解密
	unsigned char* CommonDecrypt(unsigned char* source, const unsigned char SubKey[16][6], unsigned long length);

	//	3Des加密
	unsigned char* CommonEncrypt3(unsigned char* source, const unsigned char SubKey[16][6], unsigned long length);

	//	3Des解密
	unsigned char* CommonDecrypt3(unsigned char* source, const unsigned char SubKey[16][6], unsigned long length);

	// 产生子密钥
	// [IN]  const char* PreKey		初始密钥
	// [OUT] char SubKey[16][6]		16个子密钥
	bool MakeKey(const unsigned char* PreKey, unsigned char SubKey[16][6]);

}



#endif // UTlDes_h__
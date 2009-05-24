#ifndef UTlDes_h__
#define UTlDes_h__

namespace UTlDes
{
	/*-------------------------------------------------------------------------------------

	˵����
	ʹ���߿�ѡ��1��DES���ܻ�3��DES���ܣ�ͨ��1��DES���ܼ�������Ҫ��

	�򲢷�ÿ���û���Ҫ����ԭʼ�����ģ��ʿ��ǵ�Ч�ʣ����ܺ���ֱ���޸�����ʹ֮�������
	�������һ���µ����ģ����豣�����ģ����ڼ���ǰ����һ�ݡ�

	des���ܺ�����ĳ���һ��Ϊ64bit�������������Զ����ĵĳ���ҲҪ��Ϊ<*64bit��������*>
	��4,8,12,16�����ֽڳ��ȵ����ݡ�

	---------------------------------------------------------------------------------------*/


	unsigned char* Encrypt(unsigned char* source, unsigned long length);

	unsigned char* Decrypt(unsigned char* source, unsigned long length);

	unsigned char* Encrypt3(unsigned char* source, unsigned long length);

	unsigned char* Decrypt3(unsigned char* source, unsigned long length);



	/////////////////////////////////////////////////////////////////////////////////////
	//����Ϊͨ�õ�Des����

	//	Des����
	//	������
	//	[IN/OUT] unsigned char* source						Դ����
	//	[IN]     const unsigned char SubKey[16][6]			16������Կ
	//	[IN]     unsigned long length				���ȣ��ֽ�����
	unsigned char* CommonEncrypt(unsigned char* source, const unsigned char SubKey[16][6], unsigned long length);

	//	Des����
	unsigned char* CommonDecrypt(unsigned char* source, const unsigned char SubKey[16][6], unsigned long length);

	//	3Des����
	unsigned char* CommonEncrypt3(unsigned char* source, const unsigned char SubKey[16][6], unsigned long length);

	//	3Des����
	unsigned char* CommonDecrypt3(unsigned char* source, const unsigned char SubKey[16][6], unsigned long length);

	// ��������Կ
	// [IN]  const char* PreKey		��ʼ��Կ
	// [OUT] char SubKey[16][6]		16������Կ
	bool MakeKey(const unsigned char* PreKey, unsigned char SubKey[16][6]);

}



#endif // UTlDes_h__
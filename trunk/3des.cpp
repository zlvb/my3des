#include "3Des.h"
#include <memory.h>

using namespace my3des;

///////////////////////////////////////////////////////////////////
//------------------------< 初始密钥 >----------------------------
const static unsigned char POL_PREKEY[8] = {0x18,0x4,0x83,0x8,0x10,0x23,0x52};
///////////////////////////////////////////////////////////////////

//初始置换
void InitialPermutation(unsigned char* i);

//终结置换
void FinalPermutation(unsigned char* i);

//56位密钥分组和16轮循环左移
void RLKey(unsigned char* PreKey,const int round);

//置换
void PerT_KPA(const unsigned char* s,unsigned char* r);
void PerT_KPB(const unsigned char* s,unsigned char* r);

//f函数
void DesF(const unsigned char* s,const unsigned char* key,unsigned char* r);

//des函数
unsigned char* Des(unsigned char* s, const unsigned char SubKey[16][6], unsigned long sl, bool DE);

static unsigned char THE_SUBKEY[16][6];
static bool __RET = MakeKey(POL_PREKEY,THE_SUBKEY);

/*>--------------------------------------------------------------<*/
/*>	解密
/*>--------------------------------------------------------------<*/
unsigned char* my3des::Decrypt( unsigned char* source, unsigned long length )
{
	return my3des::CommonDecrypt(source, THE_SUBKEY, length);
}
/*>--------------------------------------------------------------<*/
/*>	加密
/*>--------------------------------------------------------------<*/
unsigned char* my3des::Encrypt( unsigned char* source, unsigned long length )
{
	return my3des::CommonEncrypt(source,THE_SUBKEY,length);
}
/*>--------------------------------------------------------------<*/
/*>	3des加密
/*>--------------------------------------------------------------<*/
unsigned char* my3des::Decrypt3( unsigned char* source, unsigned long length )
{
	return my3des::CommonDecrypt3(source, THE_SUBKEY, length);
}
/*>--------------------------------------------------------------<*/
/*>	3des加密
/*>--------------------------------------------------------------<*/
unsigned char* my3des::Encrypt3( unsigned char* source, unsigned long length )
{
	return my3des::CommonEncrypt3(source,THE_SUBKEY,length);
}
/*>--------------------------------------------------------------<*/
/*>	加密
/*>--------------------------------------------------------------<*/
unsigned char* my3des::CommonEncrypt(unsigned char* s, const unsigned char skey[16][6],unsigned long sl)
{
	Des(s,skey,sl,false);
	return s;
}
/*>--------------------------------------------------------------<*/
/*>	解密
/*>--------------------------------------------------------------<*/
unsigned char* my3des::CommonDecrypt(unsigned char* s, const unsigned char skey[16][6],unsigned long sl)
{
	Des(s,skey,sl,true);
	return s;
}
/*>--------------------------------------------------------------<*/
/*>	3des加密
/*>--------------------------------------------------------------<*/
unsigned char* my3des::CommonEncrypt3(unsigned char* s, const unsigned char skey[16][6],unsigned long sl)
{
	Des(s,skey,sl,false);
	Des(s,skey,sl,false);
	Des(s,skey,sl,false);
	return s;
}
/*>--------------------------------------------------------------<*/
/* 3des解密
/*>--------------------------------------------------------------<*/
unsigned char* my3des::CommonDecrypt3(unsigned char* s, const unsigned char skey[16][6],unsigned long sl)
{
	Des(s,skey,sl,true);
	Des(s,skey,sl,true);
	Des(s,skey,sl,true);
	return s;
}
/*>--------------------------------------------------------------<*/
/* 产生子密钥
/*>--------------------------------------------------------------<*/
bool my3des::MakeKey(const unsigned char* PreKey,unsigned char NeKey[16][6])
{
	unsigned char A[7];
	PerT_KPA(PreKey,A);
	RLKey(A,1);
	PerT_KPB(A,NeKey[0]);
	RLKey(A,2);
	PerT_KPB(A,NeKey[1]);
	RLKey(A,3);
	PerT_KPB(A,NeKey[2]);
	RLKey(A,4);
	PerT_KPB(A,NeKey[3]);
	RLKey(A,5);
	PerT_KPB(A,NeKey[4]);
	RLKey(A,6);
	PerT_KPB(A,NeKey[5]);
	RLKey(A,7);
	PerT_KPB(A,NeKey[6]);
	RLKey(A,8);
	PerT_KPB(A,NeKey[7]);
	RLKey(A,9);
	PerT_KPB(A,NeKey[8]);
	RLKey(A,10);
	PerT_KPB(A,NeKey[9]);
	RLKey(A,11);
	PerT_KPB(A,NeKey[10]);
	RLKey(A,12);
	PerT_KPB(A,NeKey[11]);
	RLKey(A,13);
	PerT_KPB(A,NeKey[12]);
	RLKey(A,14);
	PerT_KPB(A,NeKey[13]);
	RLKey(A,15);
	PerT_KPB(A,NeKey[14]);
	RLKey(A,16);
	PerT_KPB(A,NeKey[15]);

	return true;
}

//S盒表-S1
const unsigned char S1[4][16] = 
{
	14,  4, 13,  1, 2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
		0, 15,  7,  4, 14, 2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
		4,  1, 14,  8, 13, 6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
		15, 12,  8,  2,  4, 9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
};

//S盒表-S2
const unsigned char S2[4][16] = 
{
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
		0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
		13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
};

//S盒表-S3
const unsigned char S3[4][16] = 
{
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
		13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
		1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
};

//S盒表-S4
const unsigned char S4[4][16] = 
{
	7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
		10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
		3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
};

//S盒表-S5
const unsigned char S5[4][16] = 
{
	2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
		4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
		11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
};

//S盒表-S6
const unsigned char S6[4][16] = 
{
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
		9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
		4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
};

//S盒表-S7
const unsigned char S7[4][16] = 
{
	4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
		1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
		6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
};

//S盒表-S8
const unsigned char S8[4][16] = 
{
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
		7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
		2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};


#define PUTONEBITTOABYTE(so, i, val, oneByte) \
{\
	enum { S_bit = val - 1 };\
	enum { S_byte = S_bit >> 3 };\
	enum { S_bit_in_byte = S_bit - ((S_bit>>3)<<3) };\
	enum { C_Byte = i>>3 };	\
	enum { C_bit = (i-((i>>3)<<3)) };\
	oneByte[C_Byte] |= ((((so[S_byte]<<S_bit_in_byte) >> 7) & 1) << (7 - C_bit));	\
}

#define XOR32(m,n) 	*(int*)m ^= *(int*)n;
#define XOR48(m,n)	\
	*(int*)m ^= *(int*)n;\
	*(short*)(m+4)^=*(short*)(n+4);

#define DO_DES(i,P1,P2,fresult)	\
{\
	DesF(P1,subkey[i],fresult);\
	XOR32(fresult,P2);\
	*(int*)P2 = *(int*)P1;\
	*(int*)P1 = *(int*)fresult;\
}

unsigned char* Des(unsigned char* s, const unsigned char subkey[16][6], unsigned long sl2, bool DE)
{

	unsigned long siplen = sl2;
	unsigned long sfnlen = sl2;
	unsigned char *IPs = s;
	unsigned char *FNs = s;
	while (siplen > 0)
	{
		InitialPermutation (IPs);//初始置换
		IPs += 8;
		siplen -= 8;
	}

	while(sl2 > 0)
	{
		unsigned char *L = s;//64位明文左半部
		unsigned char *R = &s[4];//64位明文右半部

		if (DE)
		{//解密16轮
			unsigned char fresultM[4];//F函数的结果
			unsigned char *fresult = fresultM;
			DO_DES(15,L,R,fresult)	DO_DES(14,L,R,fresult)	DO_DES(13,L,R,fresult)	DO_DES(12,L,R,fresult)	
				DO_DES(11,L,R,fresult)	DO_DES(10,L,R,fresult)	DO_DES(9,L,R,fresult)	DO_DES(8,L,R,fresult)	
				DO_DES(7,L,R,fresult)	DO_DES(6,L,R,fresult)	DO_DES(5,L,R,fresult)	DO_DES(4,L,R,fresult)	
				DO_DES(3,L,R,fresult)	DO_DES(2,L,R,fresult)	DO_DES(1,L,R,fresult)	DO_DES(0,L,R,fresult)	
		}
		else
		{//加密16轮
			unsigned char fresultM[4];//F函数的结果
			unsigned char *fresult = fresultM;
			DO_DES(0,R,L,fresult)	DO_DES(1,R,L,fresult)	DO_DES(2,R,L,fresult)	DO_DES(3,R,L,fresult)	
				DO_DES(4,R,L,fresult)	DO_DES(5,R,L,fresult)	DO_DES(6,R,L,fresult)	DO_DES(7,R,L,fresult)	
				DO_DES(8,R,L,fresult)	DO_DES(9,R,L,fresult)	DO_DES(10,R,L,fresult)	DO_DES(11,R,L,fresult)	
				DO_DES(12,R,L,fresult)	DO_DES(13,R,L,fresult)	DO_DES(14,R,L,fresult)	DO_DES(15,R,L,fresult)	
		}

		sl2 -= 8;
		s += 8;
	}

	while (sfnlen > 0)
	{
		FinalPermutation (FNs);//终结置换
		FNs += 8;
		sfnlen -= 8;
	}

	return s;
}

//f函数
void DesF(const unsigned char* s,const unsigned char* key,unsigned char* r)
{
	unsigned char rt[6] = {0};

	/////////////////////PerT_PE(s,rt);

	//memset (r,0,6);


	//扩展置换E序列
	/*
	32	1	2	3	4	5	
	4	5	6	7	8	9	
	8	9	10	11	12	13	
	12	13	14	15	16	17	
	16	17	18	19	20	21	
	20	21	22	23	24	25	
	24	25	26	27	28	29	
	28	29	30	31	32	1
	*/

	PUTONEBITTOABYTE(s, 0, 32, rt);
	PUTONEBITTOABYTE(s, 1, 1, rt);
	PUTONEBITTOABYTE(s, 2, 2, rt);
	PUTONEBITTOABYTE(s, 3, 3, rt);
	PUTONEBITTOABYTE(s, 4, 4, rt);
	PUTONEBITTOABYTE(s, 5, 5, rt);
	PUTONEBITTOABYTE(s, 6, 4, rt);
	PUTONEBITTOABYTE(s, 7, 5, rt);
	PUTONEBITTOABYTE(s, 8, 6, rt);
	PUTONEBITTOABYTE(s, 9, 7, rt);
	PUTONEBITTOABYTE(s, 10, 8, rt);
	PUTONEBITTOABYTE(s, 11, 9, rt);
	PUTONEBITTOABYTE(s, 12, 8, rt);
	PUTONEBITTOABYTE(s, 13, 9, rt);
	PUTONEBITTOABYTE(s, 14, 10, rt);
	PUTONEBITTOABYTE(s, 15, 11, rt);
	PUTONEBITTOABYTE(s, 16, 12, rt);
	PUTONEBITTOABYTE(s, 17, 13, rt);
	PUTONEBITTOABYTE(s, 18, 12, rt);
	PUTONEBITTOABYTE(s, 19, 13, rt);
	PUTONEBITTOABYTE(s, 20, 14, rt);
	PUTONEBITTOABYTE(s, 21, 15, rt);
	PUTONEBITTOABYTE(s, 22, 16, rt);
	PUTONEBITTOABYTE(s, 23, 17, rt);
	PUTONEBITTOABYTE(s, 24, 16, rt);
	PUTONEBITTOABYTE(s, 25, 17, rt);
	PUTONEBITTOABYTE(s, 26, 18, rt);
	PUTONEBITTOABYTE(s, 27, 19, rt);
	PUTONEBITTOABYTE(s, 28, 20, rt);
	PUTONEBITTOABYTE(s, 29, 21, rt);
	PUTONEBITTOABYTE(s, 30, 20, rt);
	PUTONEBITTOABYTE(s, 31, 21, rt);
	PUTONEBITTOABYTE(s, 32, 22, rt);
	PUTONEBITTOABYTE(s, 33, 23, rt);
	PUTONEBITTOABYTE(s, 34, 24, rt);
	PUTONEBITTOABYTE(s, 35, 25, rt);
	PUTONEBITTOABYTE(s, 36, 24, rt);
	PUTONEBITTOABYTE(s, 37, 25, rt);
	PUTONEBITTOABYTE(s, 38, 26 ,rt);
	PUTONEBITTOABYTE(s, 39, 27, rt);
	PUTONEBITTOABYTE(s, 40, 28, rt);
	PUTONEBITTOABYTE(s, 41, 29, rt);
	PUTONEBITTOABYTE(s, 42, 28, rt);
	PUTONEBITTOABYTE(s, 43, 29, rt);
	PUTONEBITTOABYTE(s, 44, 30, rt);
	PUTONEBITTOABYTE(s, 45, 31, rt);
	PUTONEBITTOABYTE(s, 46, 32, rt);
	PUTONEBITTOABYTE(s, 47, 1, rt);

	/////////////////////////////////////////////
	XOR48(rt,key);

	unsigned char sboxout[4] = {0};
	/*
	-------------------- S盒子 -----------------------------------

	因为S盒的分配不是整字节的，因此把6个字节作下列方式的分割

	123456
	781234
	567812
	345678
	123456
	781234
	567812
	345678

	然后分别查表得出8个4位的结果
	把4位结果两两合并到一个字节输出

	*/
	////////////SBox(rt,sboxout);
	sboxout[0]=(S1[((((rt[0]>>7)&1)<<1 )|(((rt[0]<<5)>>7 )&1))][(((rt[0]<<1)>>4)&0xF)]<<4) | (S2[(((((rt[0]<<6)>>7)&1)<<1)|(((rt[1]<<3)>>7 )&1))][((( (rt[0]<<7)>>4 )&0x8)|((rt[1]>>5)&7))]);
	sboxout[1]=(S3[(((((rt[1]<<4)>>7)&1)<<1)|(((rt[2]<<1)>>7)&1))][((((rt[1]<<5)>>4 )&0xE)|((rt[2]>>7)&1))]<<4) | (S4[(((((rt[2]<<2)>>7)&1)<<1)|(rt[2]&1))][(((rt[2]<<3)>>4)&0xF)]);
	sboxout[2]=(S5[(((rt[3]>>7)&1)<<1)|(((rt[3]<<5)>>7 )&1)][(((rt[3]<<1)>>4)&0xF)]<<4) | (S6[(((((rt[3]<<6)>>7)&1)<<1)|(((rt[4]<<3)>>7 )&1))][((((rt[3]<<7)>>4 )&0xF)|((rt[4]>>5)&7))]);
	sboxout[3]=(S7[(((((rt[4]<<4)>>7)&1)<<1)|(((rt[5]<<1)>>7)&1))][((((rt[4]<<5)>>4 )&0xE)|((rt[5]>>7)&1))]<<4) | (S8[(((((rt[5]<<2)>>7)&1)<<1)|(rt[5]&1))][(((rt[5]<<3)>>4)&0xF)]);
	/////////////////////////////////////PerT_PP(sboxout,r);

	//memset (r, 0, 4);
	*(int*)r = 0;

	//压缩置换P序列
	/*
	16	7	20	21	
	29	12	28	17	
	1	15	23	26	
	5	18	31	10	
	2	8	24	14	
	32	27	3	9	
	19	13	30	6	
	22	11	4	25
	*/

	PUTONEBITTOABYTE(sboxout, 0, 16, r);
	PUTONEBITTOABYTE(sboxout, 1, 7, r);
	PUTONEBITTOABYTE(sboxout, 2, 20, r);
	PUTONEBITTOABYTE(sboxout, 3, 21, r);
	PUTONEBITTOABYTE(sboxout, 4, 29, r);
	PUTONEBITTOABYTE(sboxout, 5, 21, r);
	PUTONEBITTOABYTE(sboxout, 6, 28, r);
	PUTONEBITTOABYTE(sboxout, 7, 17, r);
	PUTONEBITTOABYTE(sboxout, 8, 1, r);
	PUTONEBITTOABYTE(sboxout, 9, 15, r);
	PUTONEBITTOABYTE(sboxout, 10, 23, r);
	PUTONEBITTOABYTE(sboxout, 11, 26, r);
	PUTONEBITTOABYTE(sboxout, 12, 5, r);
	PUTONEBITTOABYTE(sboxout, 13,18, r);
	PUTONEBITTOABYTE(sboxout, 14,31, r);
	PUTONEBITTOABYTE(sboxout, 15,10, r);
	PUTONEBITTOABYTE(sboxout, 16,2, r);
	PUTONEBITTOABYTE(sboxout, 17,8, r);
	PUTONEBITTOABYTE(sboxout, 18,24, r);
	PUTONEBITTOABYTE(sboxout, 19,14, r);
	PUTONEBITTOABYTE(sboxout, 20,32, r);
	PUTONEBITTOABYTE(sboxout, 21,27, r);
	PUTONEBITTOABYTE(sboxout, 22,3, r);
	PUTONEBITTOABYTE(sboxout, 23,9, r);
	PUTONEBITTOABYTE(sboxout, 24,19, r);
	PUTONEBITTOABYTE(sboxout, 25,13, r);
	PUTONEBITTOABYTE(sboxout, 26,30, r);
	PUTONEBITTOABYTE(sboxout, 27,6, r);
	PUTONEBITTOABYTE(sboxout, 28,22, r);
	PUTONEBITTOABYTE(sboxout, 29,11, r);
	PUTONEBITTOABYTE(sboxout, 30,4, r);
	PUTONEBITTOABYTE(sboxout, 31,25, r);
}

//56位密钥分2组并16轮循环左移
void RLKey(unsigned char* PreKey,const int round)
{
	//循环左移序列
	//1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1

	unsigned char p0 = PreKey[0];
	unsigned char p3 = PreKey[3];
	if(round<=2 || round==9 || round ==16)
	{
		PreKey[0] = ((PreKey[1]>>7)&1) | (PreKey[0]<<1);              //第1字节
		PreKey[1] = ((PreKey[2]>>7)&1) | (PreKey[1]<<1);              //第2字节
		PreKey[2] = ((PreKey[3]>>7)&1) | (PreKey[2]<<1);              //第3字节
		PreKey[3] = ( (((p0>>7)&1)<<4) | (((PreKey[3]>>4)&0xF)<<5) )  //第4字节前4位
			| ( ((PreKey[4]>>7)&1) | (((PreKey[3]<<4)>>3)&7) );       //第4字节后4位
		PreKey[4] = ((PreKey[5]>>7)&1) | (PreKey[4]<<1);              //第5字节
		PreKey[5] = ((PreKey[6]>>7)&1) | (PreKey[5]<<1);              //第6字节
		PreKey[6] = (((p3<<4)>>7)&1) | (PreKey[6]<<1);				  //第7字节
	}else{
		PreKey[0] = ((PreKey[1]>>6)&3) | (PreKey[0]<<2);              //第1字节
		PreKey[1] = ((PreKey[2]>>6)&3) | (PreKey[1]<<2);              //第2字节
		PreKey[2] = ((PreKey[3]>>6)&3) | (PreKey[2]<<2);              //第3字节
		PreKey[3] = ( (((p0>>6)&3)<<4) | (((PreKey[3]>>4)&0xF)<<6) )  //第4字节前4位
			| ( ((PreKey[4]>>6)&3) | (((PreKey[3]<<4)>>2)&0x3F) );    //第4字节后4位
		PreKey[4] = ((PreKey[5]>>6)&3) | (PreKey[4]<<2);              //第5字节
		PreKey[5] = ((PreKey[6]>>6)&3) | (PreKey[5]<<2);              //第6字节
		PreKey[6] = (((p3<<4)>>6)&3) | (PreKey[6]<<2);                //第7字节
	}
}

void PerT_KPA(const unsigned char* st,unsigned char* r)
{
	memset (r,0,7);

	//密钥置换A序列
	/*
	57	49	41	33	25	17	9	
	1	58	50	42	34	26	18	
	10	2	59	51	43	35	27	
	19	11	3	60	52	44	36	
	63	55	47	39	31	23	15	
	7	62	54	46	38	30	22	
	14	6	61	53	45	37	29	
	21	13	5	28	20	12	4
	*/	

	PUTONEBITTOABYTE(st, 0, 57, r);
	PUTONEBITTOABYTE(st, 1, 49, r);
	PUTONEBITTOABYTE(st, 2, 41, r);
	PUTONEBITTOABYTE(st, 3, 33, r);
	PUTONEBITTOABYTE(st, 4, 25, r);
	PUTONEBITTOABYTE(st, 5, 17, r);
	PUTONEBITTOABYTE(st, 6, 9, r);
	PUTONEBITTOABYTE(st, 7, 1, r);
	PUTONEBITTOABYTE(st, 8, 58, r);
	PUTONEBITTOABYTE(st, 9, 50, r);
	PUTONEBITTOABYTE(st, 10, 42, r);
	PUTONEBITTOABYTE(st, 11, 34, r);
	PUTONEBITTOABYTE(st, 12, 26, r);
	PUTONEBITTOABYTE(st, 13, 18, r);
	PUTONEBITTOABYTE(st, 14, 10, r);
	PUTONEBITTOABYTE(st, 15, 2, r);
	PUTONEBITTOABYTE(st, 16, 59, r);
	PUTONEBITTOABYTE(st, 17, 51, r);
	PUTONEBITTOABYTE(st, 18, 43, r);
	PUTONEBITTOABYTE(st, 19, 35, r);
	PUTONEBITTOABYTE(st, 20, 27, r);
	PUTONEBITTOABYTE(st, 21, 19, r);
	PUTONEBITTOABYTE(st, 22, 11, r);
	PUTONEBITTOABYTE(st, 23, 3, r);
	PUTONEBITTOABYTE(st, 24, 60, r);
	PUTONEBITTOABYTE(st, 25, 52, r);
	PUTONEBITTOABYTE(st, 26, 44, r);
	PUTONEBITTOABYTE(st, 27, 36, r);
	PUTONEBITTOABYTE(st, 28, 63, r);
	PUTONEBITTOABYTE(st, 29, 55, r);
	PUTONEBITTOABYTE(st, 30, 47, r);
	PUTONEBITTOABYTE(st, 31, 39, r);
	PUTONEBITTOABYTE(st, 32, 31, r);
	PUTONEBITTOABYTE(st, 33, 23, r);
	PUTONEBITTOABYTE(st, 34, 15, r);
	PUTONEBITTOABYTE(st, 35, 7, r);
	PUTONEBITTOABYTE(st, 36, 62, r);
	PUTONEBITTOABYTE(st, 37, 54, r);
	PUTONEBITTOABYTE(st, 38, 46, r);
	PUTONEBITTOABYTE(st, 39, 38, r);
	PUTONEBITTOABYTE(st, 40, 30, r);
	PUTONEBITTOABYTE(st, 41, 22, r);
	PUTONEBITTOABYTE(st, 42, 14, r);
	PUTONEBITTOABYTE(st, 43, 6, r);
	PUTONEBITTOABYTE(st, 44, 61, r);
	PUTONEBITTOABYTE(st, 45, 53, r);
	PUTONEBITTOABYTE(st, 46, 45, r);
	PUTONEBITTOABYTE(st, 47, 37, r);
	PUTONEBITTOABYTE(st, 48, 29, r);
	PUTONEBITTOABYTE(st, 49, 21, r);
	PUTONEBITTOABYTE(st, 50, 13, r);
	PUTONEBITTOABYTE(st, 51, 5, r);
	PUTONEBITTOABYTE(st, 52, 28, r);
	PUTONEBITTOABYTE(st, 53, 20, r);
	PUTONEBITTOABYTE(st, 54, 12, r);
	PUTONEBITTOABYTE(st, 55, 4, r);

}

void PerT_KPB(const unsigned char* st,unsigned char* r)
{
	memset (r,0,6);


	//密钥置换B序列
	/*
	14	17	11	24	1	5	
	3	28	15	6	21	10	
	23	19	12	4	26	8	
	16	7	27	20	13	2	
	41	52	31	37	47	55	
	30	40	51	45	33	48	
	44	49	39	56	34	53	
	46	42	50	36	29	32
	*/

	PUTONEBITTOABYTE(st, 0, 14, r);
	PUTONEBITTOABYTE(st, 1, 17, r);
	PUTONEBITTOABYTE(st, 2, 11, r);
	PUTONEBITTOABYTE(st, 3, 24, r);
	PUTONEBITTOABYTE(st, 4, 1, r);
	PUTONEBITTOABYTE(st, 5, 5, r);
	PUTONEBITTOABYTE(st, 6, 3, r);
	PUTONEBITTOABYTE(st, 7, 28, r);
	PUTONEBITTOABYTE(st, 8, 15, r);
	PUTONEBITTOABYTE(st, 9, 6, r);
	PUTONEBITTOABYTE(st, 10, 21,r);
	PUTONEBITTOABYTE(st, 11, 10, r);
	PUTONEBITTOABYTE(st, 12, 23, r);
	PUTONEBITTOABYTE(st, 13, 19, r);
	PUTONEBITTOABYTE(st, 14, 12, r);
	PUTONEBITTOABYTE(st, 15, 4, r);
	PUTONEBITTOABYTE(st, 16, 26, r);
	PUTONEBITTOABYTE(st, 17, 8, r);
	PUTONEBITTOABYTE(st, 18, 16, r);
	PUTONEBITTOABYTE(st, 19, 7, r);
	PUTONEBITTOABYTE(st, 20, 27, r);
	PUTONEBITTOABYTE(st, 21, 20, r);
	PUTONEBITTOABYTE(st, 22, 13, r);
	PUTONEBITTOABYTE(st, 23, 2, r);
	PUTONEBITTOABYTE(st, 24, 41, r);
	PUTONEBITTOABYTE(st, 25, 52, r);
	PUTONEBITTOABYTE(st, 26, 31, r);
	PUTONEBITTOABYTE(st, 27, 37, r);
	PUTONEBITTOABYTE(st, 28, 47, r);
	PUTONEBITTOABYTE(st, 29, 55, r);
	PUTONEBITTOABYTE(st, 30, 30, r);
	PUTONEBITTOABYTE(st, 31, 40, r);
	PUTONEBITTOABYTE(st, 32, 51, r);
	PUTONEBITTOABYTE(st, 33, 45, r);
	PUTONEBITTOABYTE(st, 34, 33, r);
	PUTONEBITTOABYTE(st, 35, 48, r);
	PUTONEBITTOABYTE(st, 36, 44, r);
	PUTONEBITTOABYTE(st, 37, 49, r);
	PUTONEBITTOABYTE(st, 38, 39, r);
	PUTONEBITTOABYTE(st, 39, 56, r);
	PUTONEBITTOABYTE(st, 40, 34, r);
	PUTONEBITTOABYTE(st, 41, 53, r);
	PUTONEBITTOABYTE(st, 42, 46, r);
	PUTONEBITTOABYTE(st, 43, 42, r);
	PUTONEBITTOABYTE(st, 44, 50, r);
	PUTONEBITTOABYTE(st, 45, 36, r);
	PUTONEBITTOABYTE(st, 46, 29, r);
	PUTONEBITTOABYTE(st, 47, 32, r);

}


//终结置换
void FinalPermutation(unsigned char* s)
{
	unsigned char st[8] = {0};

	//终结置换序列
	/*
	40	8	48	16	56	24	64	32	
	39	7	47	15	55	23	63	31	
	38	6	46	14	54	22	62	30	
	37	5	45	13	53	21	61	29	
	36	4	44	12	52	20	60	28	
	35	3	43	11	51	19	59	27	
	34	2	42	10	50	18	58	26	
	33	1	41	9	49	17	57	25	
	*/


	PUTONEBITTOABYTE(s,0,40,st);
	PUTONEBITTOABYTE(s,1,8,st);
	PUTONEBITTOABYTE(s,2,48,st);
	PUTONEBITTOABYTE(s,3,16,st);
	PUTONEBITTOABYTE(s,4,56,st);
	PUTONEBITTOABYTE(s,5,24,st);
	PUTONEBITTOABYTE(s,6,64,st);
	PUTONEBITTOABYTE(s,7,32,st);
	PUTONEBITTOABYTE(s,8,39,st);
	PUTONEBITTOABYTE(s,9,7,st);
	PUTONEBITTOABYTE(s,10,47,st);
	PUTONEBITTOABYTE(s,11,15,st);
	PUTONEBITTOABYTE(s,12,55,st);
	PUTONEBITTOABYTE(s,13,23,st);
	PUTONEBITTOABYTE(s,14,63,st);
	PUTONEBITTOABYTE(s,15,31,st);
	PUTONEBITTOABYTE(s,16,38,st);
	PUTONEBITTOABYTE(s,17,6,st);
	PUTONEBITTOABYTE(s,18,46,st);
	PUTONEBITTOABYTE(s,19,14,st);
	PUTONEBITTOABYTE(s,20,54,st);
	PUTONEBITTOABYTE(s,21,22,st);
	PUTONEBITTOABYTE(s,22,62,st);
	PUTONEBITTOABYTE(s,23,30,st);
	PUTONEBITTOABYTE(s,24,37,st);
	PUTONEBITTOABYTE(s,25,5,st);
	PUTONEBITTOABYTE(s,26,45,st);
	PUTONEBITTOABYTE(s,27,13,st);
	PUTONEBITTOABYTE(s,28,53,st);
	PUTONEBITTOABYTE(s,29,21,st);
	PUTONEBITTOABYTE(s,30,61,st);
	PUTONEBITTOABYTE(s,31,29,st);
	PUTONEBITTOABYTE(s,32,36,st);
	PUTONEBITTOABYTE(s,33,4,st);
	PUTONEBITTOABYTE(s,34,44,st);
	PUTONEBITTOABYTE(s,35,12,st);
	PUTONEBITTOABYTE(s,36,52,st);
	PUTONEBITTOABYTE(s,37,20,st);
	PUTONEBITTOABYTE(s,38,60,st);
	PUTONEBITTOABYTE(s,39,28,st);
	PUTONEBITTOABYTE(s,40,35,st);
	PUTONEBITTOABYTE(s,41,3,st);
	PUTONEBITTOABYTE(s,42,43,st);
	PUTONEBITTOABYTE(s,43,11,st);
	PUTONEBITTOABYTE(s,44,51,st);
	PUTONEBITTOABYTE(s,45,19,st);
	PUTONEBITTOABYTE(s,46,59,st);
	PUTONEBITTOABYTE(s,47,27,st);
	PUTONEBITTOABYTE(s,48,34,st);
	PUTONEBITTOABYTE(s,49,2,st);
	PUTONEBITTOABYTE(s,50,42,st);
	PUTONEBITTOABYTE(s,51,10,st);
	PUTONEBITTOABYTE(s,52,50,st);
	PUTONEBITTOABYTE(s,53,18,st);
	PUTONEBITTOABYTE(s,54,58,st);
	PUTONEBITTOABYTE(s,55,26,st);
	PUTONEBITTOABYTE(s,56,33,st);
	PUTONEBITTOABYTE(s,57,1,st);
	PUTONEBITTOABYTE(s,58,41,st);
	PUTONEBITTOABYTE(s,59,9,st);
	PUTONEBITTOABYTE(s,60,49,st);
	PUTONEBITTOABYTE(s,61,17,st);
	PUTONEBITTOABYTE(s,62,57,st);
	PUTONEBITTOABYTE(s,63,25,st);

	memcpy(s,st,8);
}

//初始置换
/*----------------------------------------------------------------------

算法说明

首先把当前8个字节全部置0
查表(initp)获得当前位置(64位中)应该放入置换后的第几位(initp[j])
如：当前是第1位则应该放入置换后的第58位。
然后查找当前位要放入的位应该在原来的第几个字节中，如当前第1位应该放第58位
第58位应该在原来的第8个字节中，并且在第8个字节的第2位
接着把第8个字节用移位变成为这样的形式b0000000，即把第2位移到第1位，其他都置0
然后把原来第8个字节移位后的形式与当前第1个字节相或，结果保存到当前第1个字节
这样循环8次就把全部64位置换好了

-----------------------------------------------------------------------*/

void InitialPermutation(unsigned char* s)
{
	unsigned char st[8] = {0};

	//初始置换
	/*
	58	50	42	34	26	18	10	2	
	60	52	44	36	28	20	12	4	
	62	54	46	38	30	22	14	6	
	64	56	48	40	32	24	16	8	
	57	49	41	33	25	17	9	1	
	59	51	43	35	27	19	11	3	
	61	53	45	37	29	21	13	5	
	63	55	47	39	31	23	15	7  
	*/

	PUTONEBITTOABYTE(s,0,58,st);
	PUTONEBITTOABYTE(s,1,50,st);
	PUTONEBITTOABYTE(s,2,42,st);
	PUTONEBITTOABYTE(s,3,34,st);
	PUTONEBITTOABYTE(s,4,26,st);
	PUTONEBITTOABYTE(s,5,18,st);
	PUTONEBITTOABYTE(s,6,10,st);
	PUTONEBITTOABYTE(s,7,2,st);
	PUTONEBITTOABYTE(s,8,60,st);
	PUTONEBITTOABYTE(s,9,52,st);
	PUTONEBITTOABYTE(s,10,44,st);
	PUTONEBITTOABYTE(s,11,36,st);
	PUTONEBITTOABYTE(s,12,28,st);
	PUTONEBITTOABYTE(s,13,20,st);
	PUTONEBITTOABYTE(s,14,12,st);
	PUTONEBITTOABYTE(s,15,4,st);
	PUTONEBITTOABYTE(s,16,62,st);
	PUTONEBITTOABYTE(s,17,54,st);
	PUTONEBITTOABYTE(s,18,46,st);
	PUTONEBITTOABYTE(s,19,38,st);
	PUTONEBITTOABYTE(s,20,30,st);
	PUTONEBITTOABYTE(s,21,22,st);
	PUTONEBITTOABYTE(s,22,14,st);
	PUTONEBITTOABYTE(s,23,6,st);
	PUTONEBITTOABYTE(s,24,64,st);
	PUTONEBITTOABYTE(s,25,56,st);
	PUTONEBITTOABYTE(s,26,48,st);
	PUTONEBITTOABYTE(s,27,40,st);
	PUTONEBITTOABYTE(s,28,32,st);
	PUTONEBITTOABYTE(s,29,24,st);
	PUTONEBITTOABYTE(s,30,16,st);
	PUTONEBITTOABYTE(s,31,8,st);
	PUTONEBITTOABYTE(s,32,57,st);
	PUTONEBITTOABYTE(s,33,49,st);
	PUTONEBITTOABYTE(s,34,41,st);
	PUTONEBITTOABYTE(s,35,33,st);
	PUTONEBITTOABYTE(s,36,25,st);
	PUTONEBITTOABYTE(s,37,17,st);
	PUTONEBITTOABYTE(s,38,9,st);
	PUTONEBITTOABYTE(s,39,1,st);
	PUTONEBITTOABYTE(s,40,59,st);
	PUTONEBITTOABYTE(s,41,51,st);
	PUTONEBITTOABYTE(s,42,43,st); 
	PUTONEBITTOABYTE(s,43,35,st);
	PUTONEBITTOABYTE(s,44,27,st);
	PUTONEBITTOABYTE(s,45,19,st);
	PUTONEBITTOABYTE(s,46,11,st);
	PUTONEBITTOABYTE(s,47,3,st);
	PUTONEBITTOABYTE(s,48,61,st);
	PUTONEBITTOABYTE(s,49,53,st);
	PUTONEBITTOABYTE(s,50,45,st);
	PUTONEBITTOABYTE(s,51,37,st);
	PUTONEBITTOABYTE(s,52,29,st);
	PUTONEBITTOABYTE(s,53,21,st);
	PUTONEBITTOABYTE(s,54,13,st);
	PUTONEBITTOABYTE(s,55,5,st);
	PUTONEBITTOABYTE(s,56,63,st);
	PUTONEBITTOABYTE(s,57,55,st);
	PUTONEBITTOABYTE(s,58,47,st);
	PUTONEBITTOABYTE(s,59,39,st);
	PUTONEBITTOABYTE(s,60,31,st);
	PUTONEBITTOABYTE(s,61,23,st);
	PUTONEBITTOABYTE(s,62,15,st);
	PUTONEBITTOABYTE(s,63,7,st);

	memcpy(s,st,8);
}
//////////////////////////////////////////////////////////////////////////

/*
#include "stdio.h"
struct TestUnit
{
TestUnit()
{
unsigned char mingwen[] = "Sdrtgbhy123fg69";
printf("Source: %s\n",mingwen);
my3des::Encrypt(mingwen,16);
printf("Encrypted: %s\n",mingwen);
my3des::Decrypt(mingwen,16);
printf("Decrypted: %s\n",mingwen);
}
};

static TestUnit Testit;
*/

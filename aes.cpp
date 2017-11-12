/*

��ǻ�� ����

Modified AES-128

12131619 ��ǻ�Ͱ��а� �����

2017. 11. 12

*/

#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <algorithm>
using namespace std;

//Sbox
static const unsigned char SBox[256] = {
	0xD4, 0xAD, 0x82, 0x7D, 0xA2, 0x59, 0xF0, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xCA, 0xC9, 0xFA, 0x47,
	0xA5, 0x34, 0xFD, 0x26, 0xE5, 0x3F, 0xCC, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0xB7, 0x93, 0x36, 0xF7,
	0xD3, 0xC2, 0x32, 0x0A, 0xAC, 0x06, 0x5C, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE0, 0x3A, 0x49, 0x24,
	0x12, 0x07, 0xC7, 0xC3, 0x80, 0x96, 0x9A, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x04, 0x23, 0x18, 0x05,
	0x01, 0x30, 0x7C, 0x7B, 0x67, 0x6B, 0xC5, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0x63, 0x77, 0xF2, 0x6F,
	0x1E, 0x9B, 0xF8, 0x11, 0x87, 0xD9, 0x94, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0xE1, 0x98, 0x69, 0x8E,
	0xCB, 0x6A, 0xD1, 0xED, 0xBE, 0xFC, 0x5B, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0x53, 0x00, 0x20, 0xB1,
	0xB6, 0xBC, 0xA3, 0x8F, 0xDA, 0x9D, 0xF5, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0x51, 0x40, 0x92, 0x38,
	0xA7, 0xC4, 0x0C, 0xEC, 0x7E, 0x97, 0x17, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0xCD, 0x13, 0x5F, 0x44,
	0x56, 0x6C, 0xC8, 0x6D, 0xF4, 0xD5, 0xA9, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xE7, 0x37, 0x8D, 0x4E,
	0x99, 0x41, 0xA1, 0x0D, 0x2D, 0xE6, 0x68, 0x0F, 0xB0, 0x54, 0xBB, 0x16, 0x8C, 0x89, 0xBF, 0x42,
	0xEE, 0x46, 0x81, 0xDC, 0xB8, 0x2A, 0x88, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0x60, 0x4F, 0x22, 0x90,
	0xDD, 0xE8, 0x78, 0x2E, 0x74, 0xA6, 0xC6, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0xBA, 0x25, 0x1C, 0xB4,
	0x35, 0x61, 0x3E, 0x66, 0x57, 0x03, 0x0E, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0x70, 0xB5, 0x48, 0xF6,
	0xF9, 0x45, 0xEF, 0xFB, 0x02, 0x4D, 0x85, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0xD0, 0xAA, 0x43, 0x33,
	0x3B, 0x52, 0x83, 0x1A, 0xD6, 0x6E, 0xA0, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x09, 0x2C, 0x1B, 0x5A
};

//���� �̸� ����
const string plainTextFile= "pt.bin";
const string keyFile = "key.bin";
const string cipherTextFile = "ct.bin";
const string decrpytFile = "pt2.bin";

//����� ��� ����
const int BLKSIZE = 16;					//block size
const int EXPANDEDKEY = 44;				//number of expansion keys
const int WORDSIZE = 4;					//size of WORD
const int MOD = 27;			//= 11011(2) (x^4 + x^3 + x + 1)
const int NUMOFROUNDS = 11;				//number of rounds

//WORD ������ Ÿ���� ����
class WORD {
public:
	unsigned char bytes[WORDSIZE];			//1word = 4 bytes   (abcd)

	//�����ڸ� �̿��Ͽ� 4��Ʈ �Է��� �ϳ��� word�� �ٲپ� �ش�.
	WORD(unsigned char a = 0, unsigned char b = 0, unsigned char c = 0, unsigned char d = 0) {
		bytes[0] = a;
		bytes[1] = b;
		bytes[2] = c;
		bytes[3] = d;
	}

	//�� WORD Ÿ�� ������ ���� ������ ���� ����� �ش�.
	WORD operator+(const WORD& ref) {
		WORD ret;
		for (int i = 0; i < WORDSIZE; ++i) {
			ret.bytes[i] = (this->bytes[i] ^ ref.bytes[i]);				//�� WORD ������ ��� byte���� XOR ������ �ش�.
		}
		return ret;
	}
};

//a * b in GF(2^8)
unsigned char multInGf(unsigned char a, unsigned char b) {
	unsigned char result = 0;
	bool flag = false;				//�ֻ��� ��Ʈ(index 7)�� 1�� set�Ǿ� �ִ����� ����
	for (int i = 0; i < 8; ++i) {
		if (b & (1 << i)) {
			//i�� ��Ʈ�� set�Ǿ� �ִ� ��� ������ �����Ѵ�.
			if (result == 0)
				result = a;
			else
				result ^= a;
		}

		if (a & (1 << 7)) {
			//�ֻ��� ��Ʈ(index 7)�� set�Ǿ� �ִٸ� flag�� true�� �ٲپ� �ش�.
			flag = true;
		}

		a <<= 1;

		if (flag) {
			a ^= MOD;
			flag = false;
		}
	}
	return result;
}

//addRoundKey -> �־��� roundKey�� state�� �����ش�.
void addRoundKey(const WORD* roundKey, unsigned char state[]) {
	for (int i = 0; i < WORDSIZE; ++i) {
		state[4 * i] ^= (roundKey + i)->bytes[0];
		state[4 * i + 1] ^= (roundKey + i)->bytes[1];
		state[4 * i + 2] ^= (roundKey + i)->bytes[2];
		state[4 * i + 3] ^= (roundKey + i)->bytes[3];
	}
}

//invAddRoundKey -> addRoundKey�� ������
void invAddRoundKey(const WORD* roundkey, unsigned char state[]) {
	//xor������ Ư���� �̿��Ͽ� �������� ������ �ѹ� �� ���������ν� �������� ȿ���� ����
	addRoundKey(roundkey, state);
}

//subByte -> state�� ��� byte�� Sbox�� ���� mapping ���ش�.
void subByte(unsigned char state[]) {
	for (int i = 0; i < BLKSIZE; ++i) {
		//(16 * ���� 4��Ʈ�� ǥ�� ��) �� ������ (���� 4��Ʈ�� ǥ�� ��)�� ���� ����ϴ� ���� ����
		//������ ���� �������� Sbox�� �������� �� �ִ�.
		state[i] = SBox[(state[i] & 0xF0) + (state[i] & 0x0F)];
	}
}

//invSubByte -> subByte�� ������
void invSubByte(unsigned char state[]) {
	//reverse Sbox�� SBox�� �ݴ�Ǵ� mapping�� �����ϱ� ������ �Ź� 256���� ������ ����
	//Sbox�� ���� ����Ʈ���� ������ ���� ã�� �� �� ���� index�� �� ���� �ȴ�.
	int found;
	for (int i = 0; i < BLKSIZE; ++i) {
		for (int j = 0; j < 256; ++j) {
			if (SBox[j] == state[i]) {
				found = j;
			}
		}
		state[i] = ((found / BLKSIZE) << 4) + (found % BLKSIZE);			//ã�� index�� ������ ȯ��
	}
}

//shiftRow -> ��õ� ��� �־��� ������ �� �࿡ ���� ������ ����ŭ�� ������ ����Ʈ ������ ������.
void shiftRow(unsigned char state[]) {
	int hold;
	for (int i = 0; i < 4; ++i) {
		//i��° ����(0������ ���� ��) �� i���� right shift�� ������� �̿��Ѵ�.
		for (int k = 0; k < i; ++k) {
			//one byte right shift
			hold = state[i + 4 * 3];
			for (int j = 3; j >= 1; --j) {
				state[i + 4 * j] = state[i + 4 * (j - 1)];
			}
			state[i] = hold;
		}
	}
}

//invShiftRow -> ShiftRow�� ������ -> �������� ����Ʈ ������ �������ش�.
void invShiftRow(unsigned char state[]) {
	int hold;
	for (int i = 0; i < 4; ++i) {
		for (int k = 0; k < i; ++k) {
			//one byte left shift
			hold = state[i];
			for (int j = 0; j < 3; ++j) {
				state[i + 4 * j] = state[i + 4 * (j + 1)];
			}
			state[i + 4 * 3] = hold;
		}
	}
}

//mixColumn -> ǥ�ؿ� ���ǵ� �迭�� ������ GF(2^8)�󿡼��� ��İ����� �����Ѵ�.
//��� �߰������� �̿��ϱ� ���� result��� �߰����� �迭�� ����Ͽ���.
void mixColumn(unsigned char state[]) {
	unsigned char result[BLKSIZE];
	//��İ����� GF(2^8)���� �����Ͽ���.
	for (int i = 0; i < 4; ++i) {
		result[4 * i] = multInGf(0x02, state[4 * i]) ^ multInGf(0x03, state[4 * i + 1]) ^ state[4 * i + 2] ^ state[4 * i + 3];
		result[4 * i + 1] = state[4 * i] ^ multInGf(0x02, state[4 * i + 1]) ^ multInGf(0x03, state[4 * i + 2]) ^ state[4 * i + 3];
		result[4 * i + 2] = state[4 * i] ^ state[4 * i + 1] ^ multInGf(0x02, state[4 * i + 2]) ^ multInGf(0x03, state[4 * i + 3]);
		result[4 * i + 3] = multInGf(0x03, state[4 * i]) ^ state[4 * i + 1] ^ state[4 * i + 2] ^ multInGf(0x02, state[4 * i + 3]);
	}
	for (int i = 0; i < BLKSIZE; ++i) {
		state[i] = result[i];
	}
}

//invMixColumn -> mixColumn�� ������, mixColumn���� ���� ����� ������� �������ν� �� �� �ִ�.
void invMixColumn(unsigned char state[]) {
	unsigned char result[BLKSIZE];
	for (int i = 0; i < 4; ++i) {
		result[4 * i] = multInGf(0x0e, state[4 * i]) ^ multInGf(0x0b, state[4 * i + 1]) ^ multInGf(0x0d, state[4 * i + 2]) ^ multInGf(0x09, state[4 * i + 3]);
		result[4 * i + 1] = multInGf(0x09, state[4 * i]) ^ multInGf(0x0e, state[4 * i + 1]) ^ multInGf(0x0b, state[4 * i + 2]) ^ multInGf(0x0d, state[4 * i + 3]);
		result[4 * i + 2] = multInGf(0x0d, state[4 * i]) ^ multInGf(0x09, state[4 * i + 1]) ^ multInGf(0x0e, state[4 * i + 2]) ^ multInGf(0x0b, state[4 * i + 3]);
		result[4 * i + 3] = multInGf(0x0b, state[4 * i]) ^ multInGf(0x0d, state[4 * i + 1]) ^ multInGf(0x09, state[4 * i + 2]) ^ multInGf(0x0e, state[4 * i + 3]);
	}
	for (int i = 0; i < BLKSIZE; ++i) {
		state[i] = result[i];
	}
}

//printHex -> �־��� target�� ���� hexadecimal�� ǥ������ ����Ѵ�.
void printHex(const unsigned char target[]) {
	for (int i = 0; i < BLKSIZE; ++i)
		cout << hex << setw(2) << setfill('0') << int(target[i]);
	cout << endl;
}

//printBinary -> �־��� x�� ���� binary ǥ������ ����Ѵ�.
void printBinary(unsigned char x) {
	string result = "";
	for (int i = 0; i < 8; ++i) {
		if (x % 2)
			result.push_back('1');
		else
			result.push_back('0');
		x /= 2;
	}
	reverse(result.begin(), result.end());
	cout << result;
}

//getRoundCont -> round�� �ش��ϴ� RoundConstant�� ���� ��ȯ�Ѵ�. (������� ������� ����)
unsigned char getRoundCont(int round) {
	if (round == 1) return 1;
	else return multInGf(2, getRoundCont(round - 1));			//2 * RC[i-1]
}

//addRoundCont -> WORD�� �־��� round�� constant���� �����ش�. (�� ���� ������ GF(2^8) ���� �����̴�.)
WORD addRoundCont(WORD wd, int round) {
	WORD ret;
	unsigned char roundCont = getRoundCont(round);
	for (int i = 0; i < WORDSIZE; ++i) {
		if (i)
			ret.bytes[i] = wd.bytes[i];
		else
			ret.bytes[i] = (wd.bytes[i] ^ roundCont);
	}
	return ret;
}

//rotWord -> wd WORD�� ��� ����Ʈ�� ���� �������� ����Ʈ ������ ���ش�.
WORD rotWord(WORD wd) {
	WORD ret;
	unsigned char hold = wd.bytes[0];
	for (int i = 0; i < WORDSIZE; ++i) {
		if (i == WORDSIZE - 1)
			ret.bytes[i] = hold;
		else
			ret.bytes[i] = wd.bytes[i + 1];
	}
	return ret;
}

//subWord -> �־��� wd WORD�� ���� Sbox�� �̿��Ͽ� ���Ӱ� mapping ���� ���� WORD�� ������ ��ȯ�Ͽ� ��ȯ���ش�.
WORD subWord(WORD wd) {
	WORD ret;
	for (int i = 0; i < WORDSIZE; ++i) {
		ret.bytes[i] = SBox[(wd.bytes[i] & 0xF0) + (wd.bytes[i] & 0x0F)];
	}
	return ret;
}

//keyExpansion -> roundKey�� �־��� key���� �̿��Ͽ� wd�� �迭�� ����ش�.
void keyExpansion(const unsigned char key[BLKSIZE], WORD wd[WORDSIZE * NUMOFROUNDS]) {
	WORD temp;
	for (int i = 0; i < WORDSIZE; ++i) {
		wd[i] = WORD(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
	}
	for (int i = WORDSIZE; i < WORDSIZE * NUMOFROUNDS; ++i) {
		temp = wd[i - 1];
		if ((i % 4) == 0) {
			temp = addRoundCont(subWord(rotWord(temp)), i / 4);
		}
		wd[i] = wd[i - 4] + temp;
	}
}

int main() {
	ifstream plaintextIn(plainTextFile, ios::in | ios::binary);
	ifstream keyIn(keyFile, ios::in | ios::binary);
	ofstream cipherOut(cipherTextFile, ios::out | ios::binary);
	ofstream decryptOut(decrpytFile, ios::out | ios::binary);
	
	if (!plaintextIn.is_open() || !keyIn.is_open() || !cipherOut.is_open() || !decryptOut.is_open()) {
		cerr << "error occur while opening file\n";
		exit(1);
	}

	unsigned char key[BLKSIZE];							//�Է� Ű�� ���� �迭
	unsigned char state[BLKSIZE];						//16byte block ���� �迭
	WORD roundKey[WORDSIZE * NUMOFROUNDS];				//roundKey�� ������ WORD������ �迭 (i�� ������ key���� roundKey[4*i ~ 4*i +3]�� ��ġ�ϰ� �ȴ�.

	//key �Է� ����
	for (int i = 0; i < BLKSIZE; ++i)
		keyIn.read((char*)&key[i], 1);

	//key �Է� ����
	keyIn.close();										

	//keyExpansion ����
	keyExpansion(key, roundKey);

	while (true) {
		//plainText�Է�
		for (int i = 0; i < BLKSIZE; ++i)
			plaintextIn.read((char*)&state[i], 1);

		if (plaintextIn.eof()) break;			//EOF check

		cout << "key: " << key << endl;
		//plainText �Է� �� encryption ����

		cout << "Input plain text : ";
		printHex(state);
		cout << endl;

		for (int i = 0; i < NUMOFROUNDS; ++i) {
			cout << "ROUND " << dec << i << endl;

			//0��° ���� ���� ��� ���尡 �����ϴ� �κ�
			if (i != 0) {
				//SubBytes
				subByte(state);
				cout << "\tSB : ";
				printHex(state);

				//ShiftRow
				shiftRow(state);
				cout << "\tSR : ";
				printHex(state);

				//0��, 10�� ���� ���� ��� ���尡 �����ϴ� �κ�
				if (i != NUMOFROUNDS - 1) {
					//MixColumn
					mixColumn(state);
					cout << "\tMC : ";
					printHex(state);
				}
			}

			//AddRoundKey
			addRoundKey(roundKey + 4 * i, state);
			cout << "\tAR : ";
			printHex(state);

		}

		//ct2.bin ���Ͽ� encrypt�� ������ ����
		cipherOut.write((char*)state, BLKSIZE);
		cout << endl << endl;

		cout << "Result Encryption: ";
		printHex(state);

		//decryption ����
		for (int i = 0; i < NUMOFROUNDS; ++i) {
			if (i != 0) {
				//invShiftRow
				invShiftRow(state);

				//invSubBytes
				invSubByte(state);
			}

			//invAddRoundKey  ��ȣȭ �ÿ��� Ű�� ������ �ݴ��ӿ� ����
			invAddRoundKey(roundKey + 4 * (NUMOFROUNDS - 1 - i), state);

			if (i != 0 && i != NUMOFROUNDS - 1) {
				//invMixColumn
				invMixColumn(state);
			}

		}

		cout << "Result Decryption: ";
		printHex(state);
		decryptOut.write((char*)state, BLKSIZE);			//decryption ��� ���
	}

	cipherOut.close();
	plaintextIn.close();
	decryptOut.close();
	return 0;
}
#include <cstdlib>
#include <cstring> // memcpy, memset
#include <string>
#include <iostream>

using namespace std;

#define ROL(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define ROR(v, c) (((v) >> (c)) | ((v) << (32 - (c))))

#if 1
// len usually does not include null terminator; o1 is the most significant dword, 07 the least
void __cdecl SHA256(const char *src, unsigned int len)
{
    unsigned int h0 = 1779033703;
    unsigned int h1 = -1150833019;
    unsigned int h2 = 1013904242;
    unsigned int h3 = -1521486534;
    unsigned int h4 = 1359893119;
    unsigned int h5 = -1694144372;
    unsigned int h6 = 528734635;
    unsigned int h7 = 1541459225;

    const int k[64] = {
        1116352408, 1899447441, -1245643825, -373957723,
        961987163, 1508970993, -1841331548, -1424204075,
        -670586216, 310598401, 607225278, 1426881987,
        1925078388, -2132889090, -1680079193, -1046744716,
        -459576895, -272742522, 264347078, 604807628,
        770255983, 1249150122, 1555081692, 1996064986,
        -1740746414, -1473132947, -1341970488, -1084653625,
        -958395405, -710438585, 113926993, 338241895,
        666307205, 773529912, 1294757372, 1396182291,
        1695183700, 1986661051, -2117940946, -1838011259,
        -1564481375, -1474664885, -1035236496, -949202525,
        -778901479, -694614492, -200395387, 275423344,
        430227734, 506948616, 659060556, 883997877,
        958139571, 1322822218, 1537002063, 1747873779,
        1955562222, 2024104815, -2067236844, -1933114872,
        -1866530822, -1538233109, -1090935817, -965641998 };

    unsigned int width = (len + 63) & 0xFFFFFFC0;
    if (!((len + 63) & 0xFFFFFFC0))
        width = 64;
    if ((len & 0x7F) > 0x38)
        width += 64;

    unsigned int *msg = new unsigned int[width << 2];
    memset(msg, 0, width);
    memcpy(msg, src, len);

	// append 1
    *((char *)msg + len) = 0x80;

    // append length in big endian
    *((char *)msg + width - 1) = 8 * len;
    *((char *)msg + width - 2) = (8 * len) >> 8;
    *((char *)msg + width - 3) = (8 * len) >> 16;
    *((char *)msg + width - 4) = (8 * len) >> 24;

    unsigned int w[64];
    unsigned char lsb; int other, s1, offset;
    unsigned int value, def;
    unsigned int t1, t2, a, b, c, d, e, f, g, h;

    unsigned int blocks = width >> 6;
    if (blocks)
    {
        int chunk = *(int *)((char *)msg + 2);
        do
        {
            unsigned int r = 0;
            do // w[0] -- w[15]
            {
                // must be in big endian
                lsb = *(char *)(chunk + 1);
                other = (*(char *)chunk |
                    (((*(char *)(chunk - 2) << 8) |
                        *(char *)(chunk - 1)) << 8)) << 8;
                chunk += 4;
                w[r++] = lsb | other;
            } while (r < 0x10);

            unsigned int *set = &w[14];
            r = 48;
            do // w[16] -- w[63]
            {
                value = *set; ++set;
                def = *(set - 14);
                s1 = (value >> 10) ^ ROL(value, 13) ^ ROL(value, 15);
                set[1] = *(set - 6) + *(set - 15) +
                    ((def >> 3) ^ ROR(def, 7) ^ ROL(*(set - 14), 14)) + s1;
                --r;
            } while (r);

            a = h0; b = h1; c = h2; d = h3; e = h4; f = h5; g = h6; h = h7;

            offset = 0;
            do // SHA-256 compression function
            {
                t1 = h + *(int *)((char *)k + offset) + *(unsigned int *)((char *)w + offset) +
                    (e & f ^ g & ~e) + (ROR(e, 6) ^ ROL(e, 7) ^ ROR(e, 11));
                t2 = (a & b ^ c & (a ^ b)) + (ROR(a, 2) ^ ROL(a, 10) ^ ROR(a, 13));
                h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;

                offset += 4;
            } while (offset < 0x100);

            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;

        } while (!(blocks--));
    }

    delete[] msg;
    //*o0 = h0; *o1 = h1; *o2 = h2; *o3 = h3; *o4 = h4; *o5 = h5; *o6 = h6; *o7 = h7;
    cout << h0 << h1 << h2 << h3 << h4 << h5 << h6 << h7 << "\n";
}
#endif

// TODO: USE g++ NOT gcc in osx else won't build
int main (int argc, char **argv)
{
	string str = argv[1];
	cout << "str = " << str << "\n";
	cout << "str.length()*8) = " << str.length()*8 << "\n";
	SHA256(argv[1], str.length()*8);
	return 0;
}

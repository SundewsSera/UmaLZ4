// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <windows.h>
#include <iostream>
#include <iomanip>

#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md5.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#include "lz4.h"

typedef unsigned int uint;
typedef uint64_t ulonglong;
typedef uint8_t byte;
typedef uint64_t undefined8;
typedef int64_t longlong;
typedef unsigned char _BYTE;

// 将十六进制字符串转换为字节数组
// 返回字节数组指针，outLen 输出字节长度
uint8_t* hexStringToBytes(const char* hexStr, size_t& outLen) {
    size_t len = std::strlen(hexStr);
    char* cleanStr = new char[len + 1];
    size_t cleanLen = 0;

    // 1. 过滤非十六进制字符
    for (size_t i = 0; i < len; ++i) {
        if (std::isxdigit(static_cast<unsigned char>(hexStr[i]))) {
            cleanStr[cleanLen++] = hexStr[i];
        }
    }

    if (cleanLen % 2 != 0)
        --cleanLen;  // 忽略最后一个孤立字符（防止 stoul 出错）

    // 2. 转换为字节
    size_t byteCount = cleanLen / 2;
    uint8_t* byteArray = new uint8_t[byteCount];
    for (size_t i = 0; i < byteCount; ++i) {
        char buf[3] = { cleanStr[2 * i], cleanStr[2 * i + 1], '\0' };
        byteArray[i] = static_cast<uint8_t>(std::strtoul(buf, nullptr, 16));
    }

    delete[] cleanStr;
    outLen = byteCount;
    return byteArray;
}

// 打印字节数组，每行 16 个字节
void printBytes(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (i > 0 && i % 16 == 0)
            std::cout << "\n";
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]) << " ";
    }
    std::cout << std::dec << "\n";
}

uint64_t read_be_uint64(const uint8_t* bytes, size_t offset) {
    return (static_cast<uint64_t>(bytes[offset + 0]) << 56) |
        (static_cast<uint64_t>(bytes[offset + 1]) << 48) |
        (static_cast<uint64_t>(bytes[offset + 2]) << 40) |
        (static_cast<uint64_t>(bytes[offset + 3]) << 32) |
        (static_cast<uint64_t>(bytes[offset + 4]) << 24) |
        (static_cast<uint64_t>(bytes[offset + 5]) << 16) |
        (static_cast<uint64_t>(bytes[offset + 6]) << 8) |
        (static_cast<uint64_t>(bytes[offset + 7]));
}

//神秘的随机数生成函数
undefined8 FUN_7ff905721070(ulonglong* param_1, byte* param_2, longlong param_3)

{
    ulonglong uVar1;
    byte bVar2;
    uint uVar3;

    if (param_3 != 0) {
        do {
            uVar1 = *param_1;
            *param_1 = uVar1 * 0x5851f42d4c957f2d + param_1[1];
            uVar3 = (uint)(uVar1 >> 0x2d) ^ (uint)(uVar1 >> 0x1b);
            bVar2 = (byte)(uVar1 >> 0x38);
            *param_2 = (char)uVar3 << (-(bVar2 >> 3) & 0x1f) | (byte)(uVar3 >> (bVar2 >> 3));
            param_3 = param_3 + -1;
            param_2 = param_2 + 1;
        } while (param_3 != 0);
    }
    return 0;
}

int FUN_7ff905721070_INTRO(void* p_rng, unsigned char* output, size_t output_len)
{
    return FUN_7ff905721070((ulonglong*)p_rng, (byte*)output, (longlong)output_len);
}

unsigned char xmmword_7FF905A29220[0x10] = {};
unsigned char xmmword_7FF905A29230[0x10] = {};
unsigned char xmmword_7FF905A29240[0x20] = {};
unsigned char xmmword_7FF905A29260[0x20] = {};


extern "C" __declspec(dllexport)
int LZ4_compress_default_ext(char* src, char* dst, int srcSize, int dstCapacity) 
{
    
    uint8_t* bytes = (uint8_t*)src;

    //printBytes(bytes, byteLen);

    uint64_t v12 = read_be_uint64(bytes, 0x60);

    //printf("v12 = 0x%p\n", v12);

    v12 = (v12 * 2) | 1;

    uint64_t v13 = read_be_uint64(bytes, 0x58);


    //printf("v12 = 0x%p\n", v12);

    //printf("v13 = 0x%p\n", v13);

    uint64_t v15 = ((v12 + v13) * 0x5851F42D4C957F2D) + v12;

    //printf("v15 = 0x%p\n", v15);

    uint8_t v8 = bytes[0x38];

    //printf("v8 = 0x%p\n", v8);

    int64_t v16 = v8 & 0xF;

    //printf("v16 = 0x%p\n", v16);

    if (v16)
    {
        do
        {
            v15 = v12 + 0x5851F42D4C957F2D * v15;
            --v16;

        } while (v16);
    }

    //printf("v15 = 0x%p\n", v15);

    mbedtls_ecdh_context v195;
    mbedtls_ecdh_init(&v195);
    mbedtls_ecp_group_load(&v195.grp, MBEDTLS_ECP_DP_CURVE25519);

    uint8_t v217[16];
    memcpy(v217, &v15, 0x08);
    memcpy(&v217[0x08], &v12, 0x08);
    //combine_u64_to_bytes_little_endian(v15, v12, v217);


    int answer = mbedtls_ecdh_gen_public(&v195.grp, &v195.d, &v195.Q, FUN_7ff905721070_INTRO, (void*)&v217);

    // 如果 Qp.Z 没有初始化或者为 0
    if (v195.Qp.Z.n == 0) {
        v195.Qp.Z.p = (mbedtls_mpi_uint*)calloc(1, sizeof(uint64_t));
        v195.Qp.Z.p[0] = 1;
        v195.Qp.Z.n = 1;
        v195.Qp.Z.s = 1;
    }
    else {
        // 否则就直接清零原有内存，并写入 1
        memset(v195.Qp.Z.p, 0, 8 * v195.Qp.Z.n);
        v195.Qp.Z.p[0] = 1;
        v195.Qp.Z.s = 1;
    }

    mbedtls_mpi_read_binary(&v195.Qp.X, &bytes[0x04], 0x20);
    mbedtls_mpi_write_binary(&v195.d, xmmword_7FF905A29260, 0x20uLL);

    mbedtls_mpi new_mpi;
    mbedtls_mpi_init(&new_mpi);

    answer = mbedtls_ecdh_compute_shared(&v195.grp, &new_mpi, &v195.Qp, &v195.d, FUN_7ff905721070_INTRO, (void*)&v217);

    uint8_t FirstKey[0x20];

    memcpy(FirstKey, new_mpi.p, 0x20);

    mbedtls_mpi_free(&new_mpi);

    memcpy(dst + 0x04, v195.Q.X.p, 0x20);

    mbedtls_ecdh_free(&v195);

    //Part1结束

    mbedtls_md5_context v196;
    mbedtls_md5_init(&v196);
    mbedtls_md5_starts(&v196);
    v196.total[0] = 0x30;
    v196.total[1] = 0x00;
    memcpy(v196.buffer, &bytes[0x38], 0x10);
    memcpy(&v196.buffer[0x10], &bytes[0x9A], 0x10);
    memcpy(&v196.buffer[0x20], &bytes[0x48], 0x10);

    unsigned char v200[16] = {};

    mbedtls_md5_finish_ret(&v196, v200);

    __int64 v113 = 0;
    uint8_t v201[16] = {};
    memcpy(v201, FirstKey, 0x10);

    uint8_t v10[0x20] = {};
    memcpy(v10, &bytes[0x24], 0x20);

    unsigned __int8 v114; // bl
    __int64 v115; // r11
    char v116; // r9
    char v117; // r8
    char v118; // bl
    unsigned __int8 v119; // bl
    __int64 v120; // r11
    char v121; // r9
    char v122; // r8
    char v123; // bl
    unsigned __int8 v124; // bl
    __int64 v125; // r11
    char v126; // r9
    char v127; // r8
    char v128; // bl
    unsigned __int8 v129; // bl
    __int64 v130; // r11
    char v131; // r9
    char v132; // r8
    __int64 v133; // rax
    char v134; // bl
    unsigned __int8 v135; // bl
    __int64 v136; // r11
    char v137; // r9
    char v138; // r8
    char v139; // bl
    unsigned __int8 v140; // bl
    __int64 v141; // r11
    char v142; // r9
    char v143; // r8
    char v144; // bl
    unsigned __int8 v145; // bl
    __int64 v146; // r11
    char v147; // r9
    char v148; // r8
    char v149; // bl
    char v150; // bl
    char v151; // r10
    char v152; // r9
    _BYTE* v153; // rdx
    char v154; // r8
    char v155; // bl

    do
    {
        v114 = *((_BYTE*)&v200 + v113);
        v115 = (*((_BYTE*)&v201 + v113) ^ v114) & 0xF;
        v116 = *((_BYTE*)FirstKey + v115) ^ v114;
        v117 = *((_BYTE*)&v201 + (v116 & 0xF)) ^ v114;
        *((_BYTE*)&v201 + (v116 & 0xF)) ^= *((_BYTE*)&v201 + v113) ^ v114;
        *((_BYTE*)&v201 + (v117 & 0xF)) ^= v116;
        v118 = v10[v117 & 0xF] ^ v114;
        *((_BYTE*)&v201 + (v118 & 0xF)) ^= v117;
        *((_BYTE*)&v201 + v115) ^= v118;
        v119 = *((_BYTE*)&v200 + v113 + 1);
        v120 = (*((_BYTE*)&v201 + v113 + 1) ^ v119) & 0xF;
        v121 = *((_BYTE*)FirstKey + v120) ^ v119;
        v122 = *((_BYTE*)&v201 + (v121 & 0xF)) ^ v119;
        *((_BYTE*)&v201 + (v121 & 0xF)) ^= *((_BYTE*)&v201 + v113 + 1) ^ v119;
        *((_BYTE*)&v201 + (v122 & 0xF)) ^= v121;
        v123 = v10[v122 & 0xF] ^ v119;
        *((_BYTE*)&v201 + (v123 & 0xF)) ^= v122;
        *((_BYTE*)&v201 + v120) ^= v123;
        v124 = *((_BYTE*)&v200 + v113 + 2);
        v125 = (*((_BYTE*)&v201 + v113 + 2) ^ v124) & 0xF;
        v126 = *((_BYTE*)FirstKey + v125) ^ v124;
        v127 = *((_BYTE*)&v201 + (v126 & 0xF)) ^ v124;
        *((_BYTE*)&v201 + (v126 & 0xF)) ^= *((_BYTE*)&v201 + v113 + 2) ^ v124;
        *((_BYTE*)&v201 + (v127 & 0xF)) ^= v126;
        v128 = v10[v127 & 0xF] ^ v124;
        *((_BYTE*)&v201 + (v128 & 0xF)) ^= v127;
        *((_BYTE*)&v201 + v125) ^= v128;
        v129 = *((_BYTE*)&v200 + v113 + 3);
        v130 = (*((_BYTE*)&v201 + v113 + 3) ^ v129) & 0xF;
        v131 = *((_BYTE*)FirstKey + v130) ^ v129;
        v132 = *((_BYTE*)&v201 + (v131 & 0xF)) ^ v129;
        v133 = v132 & 0xF;
        *((_BYTE*)&v201 + (v131 & 0xF)) ^= *((_BYTE*)&v201 + v113 + 3) ^ v129;
        *((_BYTE*)&v201 + v133) ^= v131;
        v134 = v10[v133] ^ v129;
        *((_BYTE*)&v201 + (v134 & 0xF)) ^= v132;
        *((_BYTE*)&v201 + v130) ^= v134;
        v135 = *((_BYTE*)&v200 + v113 + 4);
        v136 = (*((_BYTE*)&v201 + v113 + 4) ^ v135) & 0xF;
        v137 = *((_BYTE*)FirstKey + v136) ^ v135;
        v138 = *((_BYTE*)&v201 + (v137 & 0xF)) ^ v135;
        *((_BYTE*)&v201 + (v137 & 0xF)) ^= *((_BYTE*)&v201 + v113 + 4) ^ v135;
        *((_BYTE*)&v201 + (v138 & 0xF)) ^= v137;
        v139 = v10[v138 & 0xF] ^ v135;
        *((_BYTE*)&v201 + (v139 & 0xF)) ^= v138;
        *((_BYTE*)&v201 + v136) ^= v139;
        v140 = *((_BYTE*)&v200 + v113 + 5);
        v141 = (*((_BYTE*)&v201 + v113 + 5) ^ v140) & 0xF;
        v142 = *((_BYTE*)FirstKey + v141) ^ v140;
        v143 = *((_BYTE*)&v201 + (v142 & 0xF)) ^ v140;
        *((_BYTE*)&v201 + (v142 & 0xF)) ^= *((_BYTE*)&v201 + v113 + 5) ^ v140;
        *((_BYTE*)&v201 + (v143 & 0xF)) ^= v142;
        v144 = v10[v143 & 0xF] ^ v140;
        *((_BYTE*)&v201 + (v144 & 0xF)) ^= v143;
        *((_BYTE*)&v201 + v141) ^= v144;
        v145 = *((_BYTE*)&v200 + v113 + 6);
        v146 = (*((_BYTE*)&v201 + v113 + 6) ^ v145) & 0xF;
        v147 = *((_BYTE*)FirstKey + v146) ^ v145;
        v148 = *((_BYTE*)&v201 + (v147 & 0xF)) ^ v145;
        *((_BYTE*)&v201 + (v147 & 0xF)) ^= *((_BYTE*)&v201 + v113 + 6) ^ v145;
        *((_BYTE*)&v201 + (v148 & 0xF)) ^= v147;
        v149 = v10[v148 & 0xF] ^ v145;
        *((_BYTE*)&v201 + (v149 & 0xF)) ^= v148;
        *((_BYTE*)&v201 + v146) ^= v149;
        v150 = *((_BYTE*)&v200 + v113 + 7);
        v151 = *((_BYTE*)&v201 + v113 + 7) ^ v150;
        v152 = *((_BYTE*)FirstKey + (v151 & 0xF)) ^ v150;
        v153 = (unsigned char*)&v201 + (v152 & 0xF);
        v113 += 8LL;
        v154 = *v153 ^ v150;
        *v153 ^= v151;
        *((_BYTE*)&v201 + (v154 & 0xF)) ^= v152;
        v155 = v10[v154 & 0xF] ^ v150;
        *((_BYTE*)&v201 + (v155 & 0xF)) ^= v154;
        *((_BYTE*)&v201 + (v151 & 0xF)) ^= v155;
    } while (v113 < 16);

    //Part2结束

    mbedtls_md5_init(&v196);
    mbedtls_md5_starts(&v196);
    v196.total[0] = 0x30;
    v196.total[1] = 0x00;
    memcpy(v196.buffer, v201, 0x10);
    memcpy(&v196.buffer[0x10], FirstKey, 0x20);

    mbedtls_md5_update_ret(&v196, v200, 0x10);

    //Part3结束

    mbedtls_md5_update_ret(&v196, v10, 0x14);

    unsigned char v212[16] = {};
    mbedtls_md5_finish_ret(&v196, v212);

    //Part4结束
    mbedtls_aes_context v199;
    memset(&v199, 0, sizeof(mbedtls_aes_context));
    mbedtls_aes_setkey_enc(&v199, FirstKey, 0x100u);

    size_t v163 = 0;

    unsigned char v162[0x10] = {};
    memcpy(v162, &dst[0x04], 0x10);

    unsigned char v213[16] = {};

    unsigned char v204[0x24] = {};
    v204[0] = 1;
    v204[1] = 0;
    memcpy(&v204[0x02], &bytes[0x78], 0x10);
    memcpy(&v204[0x12], &bytes[0x88], 0x10);
    memcpy(&v204[0x22], &bytes[0x98], 0x02);

    mbedtls_aes_crypt_ctr(&v199, 36, &v163, v162, v213, v204, (unsigned char*)&dst[0x24]);
    mbedtls_aes_free(&v199);

    //Part5结束

    mbedtls_md5_init(&v196);
    mbedtls_md5_starts(&v196);
    v196.total[0] = 0x40;
    v196.total[1] = 0x00;
    memcpy(v196.buffer, &dst[0x04], 0x20);
    //memcpy(&v196.buffer[0x10], &dst[0x14], 0x10);
    memcpy(&v196.buffer[0x20], &bytes[0x38], 0x20);
    //memcpy(&v196.buffer[0x30], &bytes[0x48], 0x10);
    mbedtls_md5_process(&v196, v196.buffer);

    unsigned char v209[16] = {};
    mbedtls_md5_finish_ret(&v196, v209);
    mbedtls_md5_free(&v196);

    //Part6结束
    mbedtls_gcm_context v198;
    mbedtls_gcm_init(&v198);
    mbedtls_gcm_setkey(&v198, MBEDTLS_CIPHER_ID_AES, v212, 128);
    mbedtls_gcm_crypt_and_tag(&v198, 1, srcSize - 0xAA, v209, 16, &bytes[0x24], 52, &bytes[0xAA], (unsigned char*)& dst[0x58], 0x10, (unsigned char*)&dst[0x48]);
    mbedtls_gcm_free(&v198);

    int v180 = srcSize - 0xAA + 88; //去掉原来的头大小，加上之后的头大小
    int v181 = v180 - 4;

    memcpy(dst, &v181, 0x4);

    int result = v180; //返回压缩后的大小

    //最后记录了头部的一些数据，可能是用来解析返回的消息用的

    memcpy(xmmword_7FF905A29220, &bytes[0x38], 0x10);
    memcpy(xmmword_7FF905A29230, &bytes[0x9A], 0x10);
    memcpy(xmmword_7FF905A29240, &bytes[0x04], 0x20);


    printf("LZ4 Compression succeeded: %d bytes\n", result);

    return result;
}

extern "C" __declspec(dllexport)
int LZ4_decompress_safe_ext(char* src, char* dst, int compressedSize, int dstCapacity)
{
    uint8_t* bytes = (uint8_t*)src;

    mbedtls_ecdh_context v36;
    mbedtls_ecdh_init(&v36);
    mbedtls_ecp_group_load(&v36.grp, MBEDTLS_ECP_DP_CURVE25519);
    mbedtls_mpi_lset(&v36.Qp.Z, 1);

    unsigned __int64 v7 = 32;

    /*
    const char* input_1 = "5A EB F0 9D CC 92 BB B8 19 C8 91 35 6A 11 4A 3E 98 E6 2C C7 FA 9E 1F E0 A3 CD 06 53 7E A5 F3 88";
    size_t byte1Len = 0;
    uint8_t* bytes1 = hexStringToBytes((const char*)input_1, byte1Len);
    */

    mbedtls_mpi_read_binary(&v36.Qp.X, xmmword_7FF905A29240, 0x20);

    /*
    const char* input_2 = "4A B3 85 B3 97 4B 2B DF 1E 14 93 6F D5 86 C8 04 50 C1 1B 5D BD 81 B7 4C 0F A1 0A F8 53 3C EB B0";
    size_t byte2Len = 0;
    uint8_t* bytes2 = hexStringToBytes((const char*)input_2, byte2Len);
    */

    mbedtls_mpi_read_binary(&v36.d, xmmword_7FF905A29260, 0x20);

    mbedtls_mpi v28;
    mbedtls_mpi_init(&v28);

    mbedtls_ecdh_compute_shared(&v36.grp, &v28, &v36.Qp, &v36.d, 0, 0);

    mbedtls_ecdh_free(&v36);

    mbedtls_md5_context v37;
    mbedtls_md5_init(&v37);
    mbedtls_md5_starts(&v37);
    v37.total[0] = 0x40;
    v37.total[1] = 0x00;
    memcpy(v37.buffer, v28.p, 0x20);

    /*
    const char* input_3 = "35 18 07 08 4E 24 8D 27 4A 4C D4 94 18 A4 EC AB 53 02 6B 4A B1 E6 41 89 5B 0C F5 F8 CD 1F 9C 40";
    size_t byte3Len = 0;
    uint8_t* bytes3 = hexStringToBytes((const char*)input_3, byte3Len);
    */

    memcpy(&v37.buffer[0x20], xmmword_7FF905A29220, 0x10);
    memcpy(&v37.buffer[0x30], xmmword_7FF905A29230, 0x10);

    mbedtls_md5_process(&v37, v37.buffer);

    unsigned char v39[16] = {};
    mbedtls_md5_finish_ret(&v37, v39);

    mbedtls_md5_free(&v37);
    mbedtls_mpi_free(&v28);

    uint8_t* dst_lz4 = (uint8_t*)calloc(compressedSize + *(unsigned int*)bytes, 1);

    mbedtls_gcm_context v38;
    mbedtls_gcm_init(&v38);
    mbedtls_gcm_setkey(&v38, MBEDTLS_CIPHER_ID_AES, v39, 128);
    mbedtls_gcm_crypt_and_tag(&v38, 0, compressedSize - 36, &bytes[0x04], 16, xmmword_7FF905A29220, 32, &bytes[0x24], dst_lz4, 0x10, &bytes[0x14]);
    mbedtls_gcm_free(&v38);

    //uint8_t* dst = (uint8_t*)calloc(0x20E, 1);

    int decompressed_size = LZ4_decompress_safe((const char*)dst_lz4, (char*)dst, compressedSize - 36, *(unsigned int*)bytes);
    if (decompressed_size < 0) {
        printf("No LZ4 Compression\n");
        memcpy(dst, dst_lz4, compressedSize - 36);
        free(dst_lz4);
        return compressedSize - 36;
    }
    else {
        printf("LZ4 Decompression succeeded: %d bytes\n", decompressed_size);
    }
    free(dst_lz4);
    return decompressed_size;
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }


    //测试数据
    /*
    const char* input = "A6 00 00 00 5A EB F0 9D CC 92 BB B8 19 C8 91 35 6A 11 4A 3E 98 E6 2C C7 FA 9E 1F E0 A3 CD 06 53 7E A5 F3 88 DB A7 D4 C8 D2 8B 2E 4C 3F 86 E1 AE 96 DB 74 E7 C2 0D 34 41 35 18 07 08 4E 24 8D 27 4A 4C D4 94 18 A4 EC AB F5 1A 85 F7 35 C5 42 10 8F A7 9D 6B C5 7E 2D 89 F9 D5 EE 11 B2 FF CC 7B EA EA 88 7E 5C D8 09 DF 33 16 E7 7D FB C6 58 21 D0 1B 28 01 DE 20 99 E2 09 45 6E 54 90 C6 0E 31 AD 67 7B A0 7A 70 3C D8 A2 72 C7 9B 80 F9 44 0F BF 86 BA 1A C9 92 47 E7 32 62 53 02 6B 4A B1 E6 41 89 5B 0C F5 F8 CD 1F 9C 40 DE 00 10 B0 61 74 74 65 73 74 61 74 69 6F 6E 5F 74 79 70 65 01 A9 76 69 65 77 65 72 5F 69 64 CE 17 92 E0 A6 A6 64 65 76 69 63 65 03 A9 64 65 76 69 63 65 5F 69 64 D9 28 62 31 34 66 64 65 39 31 33 35 34 66 62 64 34 32 37 34 31 63 35 33 38 61 62 34 30 39 33 32 66 66 65 30 62 64 64 31 37 34 AB 64 65 76 69 63 65 5F 6E 61 6D 65 B8 47 4A 35 43 4E 36 34 20 28 48 61 73 65 65 20 43 6F 6D 70 75 74 65 72 29 B4 67 72 61 70 68 69 63 73 5F 64 65 76 69 63 65 5F 6E 61 6D 65 B7 4E 56 49 44 49 41 20 47 65 46 6F 72 63 65 20 47 54 58 20 31 30 36 30 AA 69 70 5F 61 64 64 72 65 73 73 AC 31 39 32 2E 31 36 38 2E 31 30 2E 32 B3 70 6C 61 74 66 6F 72 6D 5F 6F 73 5F 76 65 72 73 69 6F 6E BE 57 69 6E 64 6F 77 73 20 31 30 20 20 28 31 30 2E 30 2E 31 39 30 34 35 29 20 36 34 62 69 74 A7 63 61 72 72 69 65 72 A0 A8 6B 65 79 63 68 61 69 6E 00 A6 6C 6F 63 61 6C 65 A3 4A 50 4E AB 62 75 74 74 6F 6E 5F 69 6E 66 6F A0 AD 64 6D 6D 5F 76 69 65 77 65 72 5F 69 64 A0 B1 64 6D 6D 5F 6F 6E 65 74 69 6D 65 5F 74 6F 6B 65 6E A0 A8 73 74 65 61 6D 5F 69 64 C0 B9 73 74 65 61 6D 5F 73 65 73 73 69 6F 6E 5F 61 75 74 68 5F 74 69 63 6B 65 74 C0";

    size_t byteLen = 0;
    uint8_t* bytes = hexStringToBytes((const char*)input, byteLen);

    uint8_t* dst = (uint8_t*)calloc(0x1000, 1);
    LZ4_compress_default_ext((char*)bytes, (char*)dst, byteLen, 0x1000);
    free(dst);
    

    const char* input1 = "0E 02 00 00 16 1D 94 8C 3B 6C 6A 81 51 54 B5 B5 5E 78 4F 5E B1 77 B0 A5 40 34 3A BA 66 61 89 E5 C4 D9 6E 52 C7 BC F6 1B 50 D3 3E BA C9 2C 6A F7 0B 9A 83 DA C1 7B 33 F4 29 FE 4A A6 D5 41 E6 F4 06 2B 2E 7B 6D 53 6D F3 2F EE 32 7F C4 31 60 2D 00 11 49 4F 55 57 71 0C 7D BB F1 21 73 45 9A 56 72 08 BA 71 6C C4 72 80 1D 7B D1 FF 5A 40 B4 C8 F9 40 DE 2B 10 7B E0 10 90 4A 24 A3 34 B4 E8 E7 C0 4C 38 34 E1 CE 6A BF 7D 27 99 AF 38 BE 82 39 D9 AD FC CE 4F 3D BF 87 70 01 F1 92 8F 18 74 13 9D 58 9F 8B 1A 7D E0 E1 88 B2 96 42 55 CD EF 10 AD D7 1E E0 CF 5C A8 43 B7 A3 57 2C EB 00 88 5C 29 33 87 1B 23 F1 FD 34 92 8A B7 A0 5B 49 4E 93 2D 22 A0 68 B9 C5 D4 C1 8D 1E 5E 95 29 C4 0C BF 51 40 7F 78 D6 04 31 FF 94 04 F9 AF BD 2B 05 20 5A AF 07 AD 06 BC ED FD DA 41 AB 22 55 D8 05 34 EC 2A 4D 7D 68 0D 7C 5C E0 0A 1A 93 15 64 D9 68 B8 5F F7 54 13 0D D8 84 47 1A 93 D4 44 9F 59 B2 7E 98 ED 2A 01 CE 04 68 DD 44 14 48 09 6B D9 37 D8 85 32 D1 D2 D5 34 34 1E 32 06 79 31 62 54 6C 89 36 C4 F7 D3 D3 DA 52 67 A4 17 59 FB 53 DB 7A 9A E0 D5 B4 A1 CB 13 9C D5 1C 6E E7 AB 3B 4D 1E 55 62 B0 8F 71 07 67 CA 11 A3 04 F2 D8 7F 8E ED 77 31 5C EA 1E 62 7B 91 0D 0E 65 90 AD 92 95 AF 4C 06 5B CF 2F 60 77 D5 5E 23 FC 65 C2";

    size_t byte1Len = 0;
    uint8_t* bytes1 = hexStringToBytes((const char*)input1, byte1Len);

    uint8_t* dst1 = (uint8_t*)calloc(0x1000, 1);

    LZ4_decompress_safe_ext((char*)bytes1, (char*)dst1, byte1Len, 0x1000);
    */

    return TRUE;
}


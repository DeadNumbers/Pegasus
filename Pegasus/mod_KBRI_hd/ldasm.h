#ifndef _LDASM_
#define _LDASM_

//#include "defines.h"
#include <windows.h>

#define F_INVALID               0x01
#define F_PREFIX                0x02
#define F_REX                   0x04
#define F_MODRM                 0x08
#define F_SIB                   0x10
#define F_DISP                  0x20
#define F_IMM                   0x40
#define F_RELATIVE              0x80

#define uint8_t BYTE
#define uint32_t DWORD

typedef struct _ldasm_data {
        uint8_t         flags;
        uint8_t         rex;
        uint8_t         modrm;
        uint8_t         sib;
        uint8_t         opcd_offset;
        uint8_t         opcd_size;
        uint8_t         disp_offset;
        uint8_t         disp_size;
        uint8_t         imm_offset;
        uint8_t         imm_size;
} ldasm_data;

/*
 Description:
 Disassemble one instruction
 
 Arguments:
 code   - pointer to the code for disassemble
 ld             - pointer to structure ldasm_data
 is64   - set this flag for 64-bit code, and clear for 32-bit
 
 Return:
 length of instruction
 */
unsigned int ldasm(void *code, ldasm_data *ld, uint32_t is64);

#endif /* _LDASM_ */

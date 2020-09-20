#ifndef GLOBALS
#define GLOBALS

#define MAX_PROBE_JUMP_INSTR_BYTES  14

//cout << "" << endl;
#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>
#include <map>
#include <vector>
#include <sstream>
#include <algorithm>


// instruction map with an entry for each new instruction:
typedef struct { 
	ADDRINT orig_ins_addr;
	ADDRINT new_ins_addr;
	ADDRINT orig_targ_addr;
	bool hasNewTargAddr;
	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_category_enum_t category_enum;
	unsigned int size;
	int new_targ_entry;
	int iteration;
} instr_map_t;

// Tables of all candidate routines to be translated:
typedef struct { 
	ADDRINT rtn_addr; 
	USIZE rtn_size;
	int instr_map_entry;   
	bool isSafeForReplacedProbe;	
} translated_rtn_t;

typedef struct { 
	ADDRINT rtn_addr;
	ADDRINT loop_start;
	ADDRINT loop_finish;	
} translated_loop_t;

extern const unsigned int max_inst_len;
extern int UNROLL_NUM;
extern xed_state_t dstate;
extern ofstream outFile;
extern ADDRINT lowest_sec_addr;
extern ADDRINT highest_sec_addr;
extern char *tc;	
extern int tc_cursor;
extern instr_map_t *instr_map;
extern int num_of_instr_map_entries;
extern int max_ins_count;
extern int max_rtn_count;
extern translated_loop_t translated_loop[20000];

extern translated_rtn_t *translated_rtn;
extern int translated_loop_num;
extern int translated_rtn_num;
extern KNOB<BOOL>   KnobVerbose;

#endif // GLOBALS

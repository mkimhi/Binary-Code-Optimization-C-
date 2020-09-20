
/*########################################################################################################*/
// cd /nfs/iil/ptl/bt/ghaber1/pin/pin-2.10-45467-gcc.3.4.6-ia32_intel64-linux/source/tools/SimpleExamples
// make
//  ../../../pin -t obj-intel64/rtn-translation.so -- ~/workdir/tst
/*########################################################################################################*/
/*
run options:
1. <pindir>/pin –t ex3.so –prof -- ./bzip2 –k –f input.txt
2. <pindir>/pin –t ex3.so –inst -- ./bzip2 –k –f input.txt
*/


#include "proj_profiling.cpp"
#include "proj_dumps.cpp"
#include "proj_globals.h"
#include "proj_unroller.cpp"
#include "proj_branch_optimizer.cpp"


using namespace std;

ofstream outFile;




/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE,"pintool","verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE,"pintool","dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE,"pintool","no_tc_commit", "0", "Do not commit translated code");

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
std::ofstream* out = 0;

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;


// tc containing the new code:
char *tc;	
int tc_cursor = 0;

instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;

// total number of routines in the main executable module:
int max_rtn_count = 0;
translated_loop_t translated_loop[20000];
translated_rtn_t *translated_rtn;


int translated_rtn_num = 0;
int translated_loop_num = 0;
int UNROLL_NUM = 0;			//!!!to delete





/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID *v)
{
	// debug print of all images' instructions
	//dump_all_image_instrs(img);


    // Step 0: Check the image and the CPU:
	if (!IMG_IsMainExecutable(img))
		return;

	int rc = 0;
//******check if it needs to be larger	
	// step 1: Check size of executable sections and allocate required memory:	
	rc = allocate_and_init_memory(img);
	if (rc < 0)
		return;

	cout << "after memory allocation" << endl;

	// Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
	rc = find_candidate_rtns_for_translation(img);
	if (rc < 0)
		return;

	cout << "after identifying candidate routines" << endl;	 

	// step 2.1: reorder the loop array
	reorderer();

	cout << "after reordering" << endl;
	
	// step 2.2: unroll the loops
	rc = unroller(img);

	if (rc < 0)
		return;
	cout << "after unrolling" << endl;

	// Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
	rc = chain_all_direct_br_and_call_target_entries();
	if (rc < 0 )
		return;
	
	cout << "after calculate direct br targets" << endl;

	// Step 4: fix rip-based, direct branch and direct call displacements:
	rc = fix_instructions_displacements();
	if (rc < 0 )
{
		return;
}	
	cout << "after fix instructions displacements" << endl;


	// Step 5: write translated routines to new tc:
	rc = copy_instrs_to_tc();
	if (rc < 0 )
		return;

	cout << "after write all new instructions to memory tc" << endl;

   if (KnobDumpTranslatedCode) {
	   cerr << "Translation Cache dump:" << endl;
       dump_tc();  // dump the entire tc

	   cerr << endl << "instructions map dump:" << endl;
	   dump_entire_instr_map();     // dump all translated instructions in map_instr
   }


	// Step 6: Commit the translated routines:
	//Go over the candidate functions and replace the original ones by their new successfully translated ones:
	commit_translated_routines();	

	cout << "after commit translated routines" << endl;
   	//dump_entire_instr_map();
}



/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool translated routines of an Intel(R) 64 binary"
         << endl;
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}


//ex2
KNOB<BOOL>KnobProf(KNOB_MODE_WRITEONCE, "pintool", "prof", "0", "run in JIT mode");

//ex3
//KNOB<BOOL>KnobInst(KNOB_MODE_WRITEONCE, "pintool", "opt", "0", "Run in prob mode");


KNOB<int>KnobInst(KNOB_MODE_WRITEONCE, "pintool", "opt", "1", "Run in prob mode");

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin & symbol manager
    //out = new std::ofstream("xed-print.out");

	//we need to get from the user the number to unroll!!
	
	
	
    if( PIN_Init(argc,argv) )
        return Usage();

    PIN_InitSymbols();
	
	if(KnobProf.Value()){ //run ex2ish
		// Register Routine to be called to instrument rtn
		RTN_AddInstrumentFunction(Routine, 0);

		// Register Fini to be called when the application exits
		PIN_AddFiniFunction(Fini, 0);
    
		// Start the program, never returns
		PIN_StartProgram();
    
	}
	if (KnobInst.Value()<99999 && KnobInst.Value()>=0){
		UNROLL_NUM = KnobInst.Value();

		// Register ImageLoad
		IMG_AddInstrumentFunction(ImageLoad, 0);
		// Start the program, never returns
		PIN_StartProgramProbed();
	}
	else{
		printf("PLEASE ENTER RIGHT FLAG");
		PIN_StartProgram();
	}
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */


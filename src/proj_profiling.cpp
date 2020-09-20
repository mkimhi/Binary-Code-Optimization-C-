#ifndef PROF
#define PROF

#include "proj_globals.h"
#include "proj_dumps.cpp"


/* ============================================================= */
/* Service profiling routines                                    */
/* ============================================================= */

///holds relevant info for every loop
typedef struct loop 
{
	ADDRINT loop_end;
	ADDRINT loop_begin;
	UINT64 count_seen;
	UINT64 count_loop_inv;
	UINT64 last;
	UINT64 counted;
	UINT64 mean_taken;
	UINT64 diff_count;
	string rtn_name;
	ADDRINT rtn_add;
	UINT64* rtn_inv_count;
	ADDRINT diff;//
}  Loop_count;

map <RTN, UINT64> rtn_map;

map <ADDRINT, Loop_count *> my_map;

// This function is called before every instruction is executed
VOID docount(UINT64 * counter)
{
    (*counter)++;
}

//this function inserts the difference count
VOID diffFind (Loop_count * lc)
{
	UINT64 tmp = lc->count_seen - lc->counted;
	if (tmp != lc->last)
		(lc->diff_count)++;
	lc->counted = lc->count_seen;
	lc->last = tmp;
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, void *v)
{
        if (!RTN_Valid(rtn))
	{
            	return;
	}
	RTN_Open( rtn );	
	rtn_map[rtn]= 0;
	string curr_name = RTN_Name(rtn);
	ADDRINT curr_add = RTN_Address(rtn);	
	
	for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
	{
		//insert a counter to count routine invocations
		if( INS_IsRet(ins) )
		{
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rtn_map[rtn]), IARG_END);
		}
		//find a loop
		if ((INS_IsDirectBranchOrCall(ins)) && !(INS_IsCall(ins)) )
		{
			ADDRINT curr_ins = INS_Address(ins);
			ADDRINT tmp = INS_DirectBranchOrCallTargetAddress(ins);
			
			if (tmp > curr_ins)
				continue;

			if (my_map.find(curr_ins)==my_map.end()) //new loop
			{
				//creating new loop count
				Loop_count * lc = new Loop_count;
				lc->loop_end = curr_ins;
				lc->loop_begin = tmp;			
				lc->count_seen = 0;
				lc->count_loop_inv = 0;
				lc->mean_taken = 0;
				lc->diff_count = 0;
				lc->last = 0;
				lc->counted = 0;
				lc->rtn_name = curr_name;
				lc->rtn_add = curr_add;
				lc->rtn_inv_count = &(rtn_map[rtn]);
				lc->diff = (curr_ins - tmp);
				my_map[curr_ins] = lc;
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) docount, IARG_PTR, &(lc->count_seen),  IARG_END);
				if(INS_HasFallThrough(ins))
				{	
					INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) docount, IARG_PTR, &(lc->count_loop_inv), IARG_END);
					INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) diffFind, IARG_PTR, lc ,  IARG_END);
				}
			}
		}
	}
	RTN_Close( rtn );
}

//This function compares two uint64.
bool uint_cmp (Loop_count * first, Loop_count * second)
{

	return ((long unsigned int)(first->mean_taken) > (long unsigned int)(second->mean_taken));
} 

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(int n, void *v)
{
	outFile.open("loop-count.csv");	

	vector<Loop_count *>my_vec;
	
	for (map <ADDRINT, Loop_count *>::iterator itr = my_map.begin(); itr != my_map.end(); itr++)
	{
		if(itr->second->count_seen > 0)
		{
			if(itr->second->count_loop_inv == 0)
				itr->second->mean_taken = itr->second->count_seen;
			else
				itr->second->mean_taken = ((itr->second->count_seen)/(itr->second->count_loop_inv));
			my_vec.push_back(itr->second);
		}
		free(itr->second);		
	}
	std::sort(my_vec.begin(),my_vec.end(),uint_cmp);
	
	for (UINT64 i=0; i<my_vec.size();i++)
	{

		if (my_vec[i]->diff_count == 0)
			my_vec[i]->diff_count++;	
		outFile	<< "0x" << hex << my_vec[i]->loop_begin << ","
			<< "0x" << hex << my_vec[i]->diff << ","
			<< "0x" << hex << my_vec[i]->rtn_add << ","
			<< dec << my_vec[i]->mean_taken << "," 
			<< my_vec[i]->rtn_name << ","  
			<< dec << *(my_vec[i]->rtn_inv_count) << ","
			<< dec << my_vec[i]->count_seen << "," 
			<< my_vec[i]->count_loop_inv << "," 
			<< ((my_vec[i]->diff_count) - 1) << endl;
		free(my_vec[i]);
	}

}



#endif // PROF

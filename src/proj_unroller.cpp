#ifndef UNROLLER
#define UNROLLER


#include "proj_globals.h"
#include "proj_branch_optimizer.cpp"
#include "proj_dumps.cpp"
#include <vector>
#include <algorithm>

using namespace std;



/************************************/
/*    add_instruction_functions	    */
/************************************/
void add_mov(ADDRINT addr, xed_uint64_t offset, xed_reg_enum_t base_reg, xed_reg_enum_t reg, int iteration) 
{
	xed_encoder_instruction_t enc_instr;
	xed_encoder_request_t enc_req;
	xed_error_enum_t xed_error, xed_code;
	xed_decoded_inst_t xedd;
	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
	xed_uint8_t  ret_inst[ilen];
	xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 64, xed_reg(reg), xed_mem_bd(base_reg, xed_disp(offset, 32), 64));
	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	if ((!xed_convert_to_encoder_request(&enc_req, &enc_instr)))
		fprintf(stderr, "conversion to encode request failed\n");
	xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(ret_inst), ilen, &olen);
	if ((xed_error != XED_ERROR_NONE))
		fprintf(stderr, "xed encoding request of `mov` failed : XED error number(%d)\n", xed_error);
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);
	xed_code = xed_decode(&xedd, ret_inst, max_inst_len);
	if (xed_code != XED_ERROR_NONE) 
	{
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	int rc = add_new_instr_entry(&xedd, addr, olen, iteration);
	if (rc < 0) 
	{
		cerr << "ERROR: failed during instructon translation." << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	return;
}

void add_cmp(ADDRINT addr, int iteration, xed_reg_enum_t reg1, xed_reg_enum_t reg2) 
{
	xed_encoder_instruction_t enc_instr;
	xed_encoder_request_t enc_req;
	xed_error_enum_t xed_error, xed_code;
	xed_decoded_inst_t xedd;
	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
	xed_uint8_t  ret_inst[ilen];
	xed_inst2(&enc_instr, dstate, XED_ICLASS_CMP, 64, xed_reg(reg1), xed_reg(reg2));		//!!!!!!!!!!!!!!!check if it needs the opposite order
	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	if ((!xed_convert_to_encoder_request(&enc_req, &enc_instr)))
		fprintf(stderr, "conversion to encode request failed\n");
	xed_error = xed_encode(&enc_req, ret_inst, ilen, &olen);
	if ((xed_error != XED_ERROR_NONE))
		fprintf(stderr, "xed encoding request of `cmp` failed : XED error number(%d)\n", xed_error);
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);
	xed_code = xed_decode(&xedd, ret_inst, max_inst_len);
	if (xed_code != XED_ERROR_NONE) 
	{
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	int rc = add_new_instr_entry(&xedd, addr, olen, iteration);
	if (rc < 0) 
	{
		cerr << "ERROR: failed during instructon translation." << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	return;
}

void add_jump(ADDRINT addr, int iteration, ADDRINT j_target) 
{
	xed_encoder_instruction_t enc_instr;
	xed_encoder_request_t enc_req;
	xed_error_enum_t xed_error, xed_code;
	xed_decoded_inst_t xedd;
	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
	xed_uint8_t  ret_inst[ilen];
	xed_int32_t displacement = j_target - addr;
	xed_inst1(&enc_instr, dstate, XED_ICLASS_JNLE, 64, xed_relbr(displacement, 32));
	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	if ((!xed_convert_to_encoder_request(&enc_req, &enc_instr)))
		fprintf(stderr, "conversion to encode request failed\n");
	xed_error = xed_encode(&enc_req, ret_inst, ilen, &olen);
	if ((xed_error != XED_ERROR_NONE))
		fprintf(stderr, "xed encoding request of `jmp` failed : XED error number(%d)\n", xed_error);
	
	//fix displacement with olen          
	displacement = displacement - olen;
	xed_inst1(&enc_instr, dstate, XED_ICLASS_JNLE, 64, xed_relbr(displacement, 32));
	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	if ((!xed_convert_to_encoder_request(&enc_req, &enc_instr)))
		fprintf(stderr, "conversion to encode request failed\n");
	xed_error = xed_encode(&enc_req, ret_inst, ilen, &olen);
	if ((xed_error != XED_ERROR_NONE))
		fprintf(stderr, "xed encoding request of `jmp` failed : XED error number(%d)\n", xed_error);
	//the fix until here

	xed_decoded_inst_zero_set_mode(&xedd, &dstate);
	xed_code = xed_decode(&xedd, ret_inst, max_inst_len);
	//dump_instr_from_xedd(&xedd, addr);
	if (xed_code != XED_ERROR_NONE) 
	{
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	int rc = add_new_instr_entry(&xedd, addr, olen, iteration);
	if (rc < 0) 
	{
		cerr << "ERROR: failed during instructon translation." << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	return;
}



void add_jump_dum(ADDRINT addr, int iteration, ADDRINT j_target) 
{
	xed_encoder_instruction_t enc_instr;
	xed_encoder_request_t enc_req;
	xed_error_enum_t xed_error, xed_code;
	xed_decoded_inst_t xedd;
	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
	xed_uint8_t  ret_inst[ilen];
	xed_int32_t displacement = j_target - addr;
	xed_inst1(&enc_instr, dstate, XED_ICLASS_JNLE, 64, xed_relbr(displacement, 32));
	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	if ((!xed_convert_to_encoder_request(&enc_req, &enc_instr)))
		fprintf(stderr, "conversion to encode request failed\n");
	xed_error = xed_encode(&enc_req, ret_inst, ilen, &olen);
	if ((xed_error != XED_ERROR_NONE))
		fprintf(stderr, "xed encoding request of `jmp` failed : XED error number(%d)\n", xed_error);
	
	//fix displacement with olen          
	displacement = displacement - olen;
	xed_inst1(&enc_instr, dstate, XED_ICLASS_JLE, 64, xed_relbr(displacement, 32));
	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	if ((!xed_convert_to_encoder_request(&enc_req, &enc_instr)))
		fprintf(stderr, "conversion to encode request failed\n");
	xed_error = xed_encode(&enc_req, ret_inst, ilen, &olen);
	if ((xed_error != XED_ERROR_NONE))
		fprintf(stderr, "xed encoding request of `jmp` failed : XED error number(%d)\n", xed_error);
	//the fix until here

	xed_decoded_inst_zero_set_mode(&xedd, &dstate);
	xed_code = xed_decode(&xedd, ret_inst, max_inst_len);
	//dump_instr_from_xedd(&xedd, addr);
	if (xed_code != XED_ERROR_NONE) 
	{
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	int rc = add_new_instr_entry(&xedd, addr, olen, iteration);
	if (rc < 0) 
	{
		cerr << "ERROR: failed during instructon translation." << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	return;
}


void add_add(ADDRINT addr, xed_reg_enum_t reg, int iteration, int immidiate) 
{
	xed_encoder_instruction_t enc_instr;
	xed_encoder_request_t enc_req;
	xed_error_enum_t xed_error, xed_code;
	xed_decoded_inst_t xedd;
	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
	xed_uint8_t  ret_inst[ilen];
	xed_inst2(&enc_instr, dstate, XED_ICLASS_ADD, 64, xed_reg(reg), xed_imm0(immidiate, 32));
	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	if ((!xed_convert_to_encoder_request(&enc_req, &enc_instr))) 
		fprintf(stderr, "conversion to encode request failed\n");
	xed_error = xed_encode(&enc_req, ret_inst, ilen, &olen);
	if ((xed_error != XED_ERROR_NONE)) 
		fprintf(stderr, "xed encoding request of `add` failed : XED error number(%d)\n", xed_error);
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);
	xed_code = xed_decode(&xedd, ret_inst, max_inst_len);
	//dump_instr_from_xedd(&xedd, addr);
	if (xed_code != XED_ERROR_NONE) 
	{
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	int rc;
	rc = add_new_instr_entry(&xedd, addr, olen, iteration);
	if (rc < 0) 
	{
		cerr << "ERROR: failed during instructon translation." << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
	}
	return;
}

/*--------------------------------------------------------------------------------
								GET FREE REGS
this function finds two regs that are killed in their first appearence in the loop		
-----------------------------------------------------------------------------------*/
void reg_check(bool* regs, int i, const xed_operand_t* op, xed_reg_enum_t& reg1, xed_reg_enum_t& reg2, xed_decoded_inst_t* xedd, xed_operand_enum_t op_name)
{
	if (regs[i])
		return;
	regs[i] = true;
	if (xed_operand_written_only(op))
	{
		if (reg1 == XED_REG_INVALID)
		{
			reg1 = xed_decoded_inst_get_reg(xedd, op_name);
		}
		else
		{
			reg2 = xed_decoded_inst_get_reg(xedd, op_name);
		}
	}
}

bool get_free_regs(INS ins, ADDRINT loop_end, xed_reg_enum_t& reg1, xed_reg_enum_t& reg2)
{
	xed_decoded_inst_t xedd;
	xed_error_enum_t xed_code;
	unsigned int i;
	unsigned int noperands;
	xed_operand_enum_t op_name;
	xed_reg_enum_t tmp_reg;
	bool regs[4] = { 0 };
	while (INS_Address(ins) != loop_end)
	{
		xed_decoded_inst_zero_set_mode(&xedd, &dstate);
		xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(INS_Address(ins)), max_inst_len);
		if (xed_code != XED_ERROR_NONE) 
		{
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << INS_Address(ins) << endl;
			break;
		}
		const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
		noperands = xed_inst_noperands(xi);

		for (i = 0; i < noperands; i++)
		{
			const xed_operand_t* op = xed_inst_operand(xi, i);
			op_name = xed_operand_name(op);

			switch (op_name)
			{
			case XED_OPERAND_REG0:
			case XED_OPERAND_REG1:
			case XED_OPERAND_REG2:
			case XED_OPERAND_REG3:
			case XED_OPERAND_REG4:
			case XED_OPERAND_REG5:
			case XED_OPERAND_REG6:
			case XED_OPERAND_REG7:
			case XED_OPERAND_REG8:
			{
				tmp_reg = xed_decoded_inst_get_reg(&xedd, op_name);
				switch (tmp_reg)
				{
				case XED_REG_AX:
				case XED_REG_EAX:
				case XED_REG_RAX:
				{
					reg_check(regs, 0, op, reg1, reg2, &xedd, op_name);
					break;
				}
				case XED_REG_BX:
				case XED_REG_EBX:
				case XED_REG_RBX:
				{
					reg_check(regs, 1, op, reg1, reg2, &xedd, op_name);
					break;
				}
				case XED_REG_CX:
				case XED_REG_ECX:
				case XED_REG_RCX:
				{
					reg_check(regs, 2, op, reg1, reg2, &xedd, op_name);
					break;
				}
				case XED_REG_DX:
				case XED_REG_EDX:
				case XED_REG_RDX:
				{
					reg_check(regs, 3, op, reg1, reg2, &xedd, op_name);
					break;
				}
				default:
					continue;
				}

			}
			default:
				continue;
			}

			if (reg2 != XED_REG_INVALID)
				return true;
			if (regs[0] && regs[1] && regs[2] && regs[3])
				return false;
		}//end of for num of operands
		ins = INS_Next(ins);
	}

	//didn't find two registers that are being killed
	return false;
}

/*---------------------------------------
				LOOP UNROLL
this function makes the actual unrolling
-----------------------------------------*/
INS loop_unroll(INS ins, ADDRINT last_address)
{

	INS loop_begin = ins;
	ADDRINT first_address = INS_Address(loop_begin);
	xed_decoded_inst_t xedd;
	xed_error_enum_t xed_code;
	unsigned int i;
	xed_operand_enum_t op_name;
	int rc;

	// PART 1:  find 2 free registers we can use
	xed_reg_enum_t reg1 = XED_REG_INVALID;
	xed_reg_enum_t reg2 = XED_REG_INVALID;

	bool to_unroll = get_free_regs(loop_begin, last_address, reg1, reg2);
	while (INS_Address(ins) != last_address)
		ins = INS_Next(ins);
	
	INS loop_end = ins;

        //PART 2:   find counter and break-condition and get the adress of the cmp/whatever, put the data in the free registers
	int r1 = 0;
	int r2 = 0;
	xed_reg_enum_t base_reg1 = XED_REG_INVALID;
	xed_reg_enum_t base_reg2 = XED_REG_INVALID;
	xed_int64_t disp1 = 0;
	xed_int64_t disp2 = 0;
	ADDRINT cmp_address = first_address;//just to initialize
	bool before_cmp = true;
	bool mem1_rw = false;
	bool mem2_rw = false;
	unsigned int noperands;
	
	
	//r1/r2 is 0 init, if 1 have a register, if 2 have a memory address
	if (to_unroll){
		while (ins != loop_begin)
		{

			//for each operand
			xed_decoded_inst_zero_set_mode(&xedd, &dstate);
			xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(INS_Address(ins)), max_inst_len);
			const xed_simple_flag_t* rfi;
			if (xed_code != XED_ERROR_NONE)
			{
				cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << INS_Address(ins) << endl;
				break;
			}
			const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
			noperands = xed_inst_noperands(xi);
			if (mem1_rw && mem2_rw)
				break;

			//the compare instruction: get the data about mem adress and registers
			if (before_cmp)
				rfi = xed_decoded_inst_get_rflags_info(&xedd);
			if (xed_decoded_inst_uses_rflags(&xedd) == true && xed_simple_flag_get_must_write(rfi) && before_cmp)
			{
				before_cmp = false;
				cmp_address = INS_Address(ins);
				for (i = 0; i < noperands; i++)
				{
					const xed_operand_t* op = xed_inst_operand(xi, i);
					xed_operand_enum_t op_name = xed_operand_name(op);
					switch (op_name)
					{
					case XED_OPERAND_MEM0:
					case XED_OPERAND_MEM1:
					{
						if (r1 == 0)
						{
							base_reg1 = xed_decoded_inst_get_base_reg(&xedd, i);
							disp1 = xed_decoded_inst_get_memory_displacement(&xedd, i);
							r1 = 2;
						}
						else if (r2 == 0)
						{
							base_reg2 = xed_decoded_inst_get_base_reg(&xedd, i);
							disp2 = xed_decoded_inst_get_memory_displacement(&xedd, i);
							r2 = 2;
						}
						break;
					}
					case XED_OPERAND_REG0:
					case XED_OPERAND_REG1:
					case XED_OPERAND_REG2:
					case XED_OPERAND_REG3:
					case XED_OPERAND_REG4:
					case XED_OPERAND_REG5:
					case XED_OPERAND_REG6:
					case XED_OPERAND_REG7:
					case XED_OPERAND_REG8:
					{
						if (base_reg1 == XED_REG_INVALID)
						{
							base_reg1 = xed_decoded_inst_get_reg(&xedd, op_name);
							r1 = 1;
						}
						else
						{
							base_reg2 = xed_decoded_inst_get_reg(&xedd, op_name);
							r2 = 1;
						}
						break;
					}
					default:
						continue;
					}
				}
			}

			//we've found 2 adresses, now we check that it's still one read-write and one read the whole loop
			else if (r1 == 2 && r2 == 2)
				for (i = 0; i < noperands; i++)
				{

					/*
					1. check if the operand is mem
					2. check if it's one of our mems
					3. find what is it	(read-continue, readwrite-save it, write-break)
					*/
					const xed_operand_t* op = xed_inst_operand(xi, i);
					op_name = xed_operand_name(op);
					if ((op_name == XED_OPERAND_MEM0) || (op_name == XED_OPERAND_MEM1)) 
					{
						xed_reg_enum_t base = xed_decoded_inst_get_base_reg(&xedd, i);
						xed_uint_t disp = xed_decoded_inst_get_memory_displacement(&xedd, i);
						if ((base == base_reg1) && (disp == disp1))
						{
							if (xed_decoded_inst_mem_written(&xedd, i))
							{
								if (xed_decoded_inst_mem_read(&xedd, i))
									mem1_rw = true;
								else
								{
									mem1_rw = true;
									mem2_rw = true;
								}
							}
							else if ((base == base_reg2) && (disp == disp2) && (xed_decoded_inst_mem_written(&xedd, i)))
							{

								if (xed_decoded_inst_mem_read(&xedd, i))
									mem2_rw = true;
								else
								{
									mem1_rw = true;
									mem2_rw = true;
								}
							}
						}
					}

				}

			//one address but one register / 2 were registers
			else if (!before_cmp)
			{

				bool valid1 = false;
				bool valid2 = false;
				if (noperands == 0)
					for (i = noperands - 1; i < noperands; i--)
					{

						const xed_operand_t* op = xed_inst_operand(xi, i);
						xed_operand_enum_t op_name = xed_operand_name(op);
						if (xed_operand_written(op) && (xed_decoded_inst_get_reg(&xedd, op_name) == base_reg1) && (disp1 == 0))
							valid1 = true;
						continue;
						if (xed_operand_read(op) && valid1 == true)
						{//!!
							xed_reg_enum_t base = xed_decoded_inst_get_base_reg(&xedd, i);
							xed_uint_t disp = xed_decoded_inst_get_memory_displacement(&xedd, i);
							base_reg1 = base;
							disp1 = disp;
							r1 = 2;
							break;
						}
						if ((xed_operand_written(op)) && (xed_decoded_inst_get_reg(&xedd, op_name) == base_reg2) && (disp2 == 0))
							valid2 = true;
						continue;
						if (xed_operand_read(op) && valid2 == true)
						{//!!
							xed_reg_enum_t base = xed_decoded_inst_get_base_reg(&xedd, i);
							xed_uint_t disp = xed_decoded_inst_get_memory_displacement(&xedd, i);
							base_reg2 = base;
							disp2 = disp;
							r1 = 2;
							break;
						}
					}

			}
			//if (INS_Prev(ins) == )
			ins = INS_Prev(ins);
		}

	if (mem1_rw && mem2_rw)
		//not the loop we want
		to_unroll = false;
	else if (!mem1_rw && mem2_rw)
	{
		//swap the mems
		xed_reg_enum_t tmp_base_reg = base_reg1;
		base_reg1 = base_reg2;
		base_reg2 = tmp_base_reg;
		xed_int64_t tmp_disp = disp1;
		disp1 = disp2;
		disp2 = tmp_disp;
	}
}

	//if w==3, we do not unroll
	if (to_unroll)
	{
		//PART 3: add needed instructions
		//mov disp1(%base_reg1), reg1 (first ins, iter 0)	--get the counter
		add_mov(first_address, disp1, base_reg1, reg1, 0);

		//mov disp2(%base_reg2), reg2 (first ins, iter UNROLL_NUM+2)		--get the loop condition
		add_mov(first_address, disp2, base_reg2, reg2, UNROLL_NUM + 2);

		//addi UNROLL_NUM , reg1 (first ins, iter UNROLL_NUM+2)		--check if there are more than UNROLL_NUM iterations to do 
		add_add(first_address, reg1, UNROLL_NUM + 2, UNROLL_NUM);

		//cmp reg1, reg2 (first ins, iter UNROLL_NUM+2)		--compare them
		add_cmp(first_address, UNROLL_NUM + 2, reg1, reg2);		//!!!!!!!!!check if we need to switch the order

		//jg first ins (first ins, iter UNROLL_NUM+1)
		add_jump(first_address, UNROLL_NUM + 1, first_address);


		//PART 4:  unroll loop- without comp and jump, (beside of last iter)
		for (int i = 1; i < UNROLL_NUM + 1; i++){

			//this is every loop unrolling //(INS_Address(INS_Next(ins)) !=0)
			for (ins = loop_begin; (INS_Prev(ins) != loop_end) &&(INS_Valid(ins)) ; ins = INS_Next(ins))
			{//THE F LOOP													
				if ((ins == loop_end || INS_Address(ins) == cmp_address) && (i != UNROLL_NUM))
					continue;
				ADDRINT addr = INS_Address(ins);
				xed_decoded_inst_zero_set_mode(&xedd, &dstate);
				xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);

				if (xed_code != XED_ERROR_NONE)
				{
					cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					break;
				}
				if (ins != loop_end)
					rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), i);
				else
					rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), 0);				
				if (rc < 0)
				{
					cerr << "ERROR: failed during instructon translation." << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					break;
				}
			}
		}

	}

	//PART 5:   copy loop(iter UNROLL_NUM+1)			(for the reminder and for loops without the conditions we want)
	for (ins = loop_begin; (INS_Prev(ins) != loop_end) &&(INS_Valid(ins)); ins = INS_Next(ins)) 
	{
		ADDRINT addr = INS_Address(ins);
		xed_decoded_inst_t xedd;
		xed_error_enum_t xed_code;
		xed_decoded_inst_zero_set_mode(&xedd, &dstate);
		xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
		if (xed_code != XED_ERROR_NONE)
		{
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
			translated_rtn[translated_rtn_num].instr_map_entry = -1;
			break;
		}

		rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), UNROLL_NUM + 1);
		if (rc < 0)
		{
			cerr << "ERROR: failed during instructon translation." << endl;
			translated_rtn[translated_rtn_num].instr_map_entry = -1;
			break;
		}
	}

	return ins;
}

/*****************************************/
/*             unroller                  */
/*****************************************/
/*
the algorithm is:
0)find the counter(read, read-write) and the end of loop(read only) (check in the whole loop)
1)find two registers we can change (a registers that first appears with write only).
/ other way: use the counter and the end of loop with addi and subi.
2)addi, compare, jump to after unroll.
3)unroll.
4)copy the loop.


it uses the func above
*/


int unroller(IMG img)
{
	int rc, i, first_loop_ind, last_loop_ind;
	int translated = 0;
	rc = 0;
	bool jumped2loop= false;
	while (translated < translated_rtn_num)
	{
		translated_rtn[translated].instr_map_entry = num_of_instr_map_entries;
		xed_decoded_inst_t xedd;
		xed_error_enum_t xed_code;
		ADDRINT rtn_address = translated_rtn[translated].rtn_addr;
		RTN rtn = RTN_FindByAddress(rtn_address);
		RTN_Open(rtn);
		INS ins = RTN_InsHead(rtn);
		first_loop_ind = -1;
		last_loop_ind = -1;
		i = 0;
		
		while (last_loop_ind == -1)
		{

			if ((translated_loop[i].rtn_addr == rtn_address) && (first_loop_ind == -1))
				first_loop_ind = i;
			if ((translated_loop[i].rtn_addr != rtn_address) && (first_loop_ind != -1))
				last_loop_ind = i-1;
			i++;

		}
		//copy the lines before the loop

		for (; INS_Address(ins) < translated_loop[first_loop_ind].loop_start; ins = INS_Next(ins))
		{

			//find the loop adresses
			ADDRINT addr = INS_Address(ins);
			xed_decoded_inst_zero_set_mode(&xedd, &dstate);
			xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
			if (xed_code != XED_ERROR_NONE)
			{
				cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
				translated_rtn[translated_rtn_num].instr_map_entry = -1;
				break;
			}
			jumped2loop = false;
			for (int j = first_loop_ind; j <= last_loop_ind; j++)
			{
				if ((INS_IsDirectBranchOrCall(ins)) && ((INS_DirectBranchOrCallTargetAddress(ins) > translated_loop[j].loop_start) && (INS_DirectBranchOrCallTargetAddress(ins) <= translated_loop[j].loop_finish)))
				{
					if (jumped2loop==false){	
						jumped2loop = true;
						rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), UNROLL_NUM);
					}

				}
 			}
				if (jumped2loop == false){
					rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), 0);
				}			

			if (rc < 0)
			{
				cerr << "ERROR: failed during instructon translation." << endl;
				translated_rtn[translated_rtn_num].instr_map_entry = -1;
				break;
			}
		}

		for (i = first_loop_ind; i <= last_loop_ind; i++)
		{
			ins = loop_unroll(ins, translated_loop[i].loop_finish);//the actual unrolling

			//copy the lines after the loop as is, don't need a change for now
			for (; INS_Valid(ins) && (INS_Address(ins) < translated_loop[i+1].loop_start) ; ins = INS_Next(ins))
			{
				ADDRINT addr = INS_Address(ins);
				xed_decoded_inst_zero_set_mode(&xedd, &dstate);
				xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
				if (xed_code != XED_ERROR_NONE)
				{
					cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					break;
				}
				jumped2loop = false;
				for (int j = first_loop_ind; j <= last_loop_ind; j++)
				{
					if ((INS_IsDirectBranchOrCall(ins)) && ((INS_DirectBranchOrCallTargetAddress(ins) > translated_loop[j].loop_start) && (INS_DirectBranchOrCallTargetAddress(ins) <= translated_loop[j].loop_finish)))
					{
						if (jumped2loop==false){	
							jumped2loop = true;
							rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), UNROLL_NUM);
						}
					}
 				}
				
				if (jumped2loop == false){
					rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins), 0);
				}
				if (rc < 0)
				{
					cerr << "ERROR: failed during instructon translation." << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					break;
				}
			}
		}
		RTN_Close(rtn);
		translated++;
	}
	return 0;
}

bool loop_cmp (translated_loop_t first, translated_loop_t second)
{
	return ((first.loop_start) < (second.loop_start));
}

void reorderer()
{
	int i;
	int j = 0;
	vector<translated_loop_t> my_vec;
	//copy the array into the vector
	for (i = 0; i < translated_loop_num; i++)
		my_vec.push_back((translated_loop[i]));
	//sort the vector
	std::sort(my_vec.begin(),my_vec.end(),loop_cmp);
	//copy the sorted vector to the array
	for (i = 0; (unsigned)i < my_vec.size(); i++)
	{
		translated_loop[i] = my_vec[i]; 
	}
	translated_loop_num = j;
}


#endif // UNROLLER

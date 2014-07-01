#include "Hook.h"

const BYTE Hook::ADD_ESP_8[3] = {0x83, 0xC4, 0x8};
const BYTE Hook::MOV_EAX_EBP[3] = {0x8b, 0x45, 0xE8};
const BYTE Hook::SUB_ESP_NUMOFARGS_BYTES[2] = {0x2B, 0x25};
const BYTE Hook::ADD_ESP_NUMOFARGS_BYTES[2] = {0x03, 0x25};

//Namespace for implementation details.
//detail::hook_pre() and detail::hook_post() cannot be placed inside the Hook class since they're __declspec(naked)
namespace detail {

	/*
		Naked: The stack frame is already constructed by hooked function
		Noinline: So we can get the address of the function and call it
		Volatile: Prevent the optimizer from removing the function
	*/
	__declspec(naked, noinline) volatile void hook_pre(DWORD callback, DWORD arg_offset) {
		__asm {
			//save registers
			pushad;

			//Remember offset for the first argument
			mov		eax, dword ptr ss:[ebp-0x08]
			mov		[eax], ebp;
			add		[eax], 0x08;

			/*	Save actual return address on stack, not really needed for
				hook_pre but needs to have the same side effects as hook_post
				which needs this
			*/
			push	dword ptr ss:[ebp + 0x04];

			//Call callback function
			call	dword ptr ss:[ebp-0x0C];

			//Set esp to point back to our return point
			add esp, 0x4;

			//Restore all registers from stack
			popad;

			ret;
		}
	}

	__declspec(naked, noinline) volatile void hook_post(DWORD callback, DWORD arg_offset) {
		_asm {
			//Save eax before we mess with anything
			push eax;

			//Remember offset for the first argument
			mov		eax, dword ptr ss:[ebp-0x08]
			mov		[eax], ebp;
			add		[eax], 0x08;

			//Save actual return address on stack
			push dword ptr ss:[ebp + 0x04];

			//Move callback pointer to eax
			mov eax, dword ptr ss:[ebp - 0x0C];
			//Set new return point
			mov dword ptr ss:[ebp + 0x04], eax;

			//Set esp to point back to our return point
			add esp, 0x4;

			//Restore old eax
			pop eax;

			ret;
		}
	}
}


BYTE* Hook::getFuncInstructions(const HANDLE& hProcess, DWORD lpFunction, DWORD& numOfInstructions, BYTE eof_inst) {
	BYTE inst;
	DWORD size = 0;
	while(true) {
		//Read byte
		ReadProcessMemory(hProcess, (const void*)(lpFunction+size), &inst, sizeof(BYTE), NULL);
		//Break if we hit the termination instruction
		if(inst == eof_inst) {
			break;
		}

		//Increment offset
		size += sizeof(BYTE);
	}

	BYTE* code = new BYTE[size];
	//Read code and return pointer
	ReadProcessMemory(hProcess, (const void*)lpFunction, code, size, &numOfInstructions);
	return code;
}

void Hook::hook_function(LPCSTR lpModule, LPCSTR lpFuncName, DWORD lpFunction) {
	//Get address of function to hook
	dwAddr = (DWORD) GetProcAddress(GetModuleHandleA(lpModule), lpFuncName);
	
	//Arrays that form the jumps
	BYTE jmp[5] = {
		JMP,
		0x00, 0x00, 0x00, 0x00, //address
	};

	//Calculate the opcode for the jumps (to - from - 5)
	DWORD dwCalc = ((DWORD) lpFunction - dwAddr - (sizeof(DWORD)+1));

	//Copy jump address to byte array
	std::memcpy(&jmp[1], &dwCalc, sizeof(DWORD));

	//Optain process and process id of this process
	HANDLE currentProcess = GetCurrentProcess();
	DWORD currentProcessId = GetProcessId(currentProcess);

	//Buffer for the original code to override
	BYTE oldCode[sizeof(DWORD)+1];

	//Open the process for reading
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, currentProcessId);

	//Get instruction of the callback function
	DWORD sizeof_callback;
	BYTE* callback_instructions = getFuncInstructions(hProcess, (DWORD)lpFunction, sizeof_callback, RET);

	//Read code from hookee that is going to be moved to our hooker func
	ReadProcessMemory(hProcess, (const void*) dwAddr, oldCode, sizeof(DWORD)+1, NULL);

	DWORD writeAddr = dwAddr;
	//Write jump from hookee to hooker func
	WriteProcessMemory(currentProcess, (void*)writeAddr, jmp, sizeof(DWORD)+1, NULL);

	writeAddr = (DWORD)lpFunction;

	//Calculate the jump opcode for the jump back to hooked function
	DWORD dwCalc_back = -dwCalc - (sizeof(DWORD)+1) - (sizeof(DWORD)+1) - sizeof_callback;

	//Write old code into new function
	WriteProcessMemory(currentProcess, (void*)writeAddr, oldCode, sizeof(DWORD)+1, NULL);

	writeAddr += sizeof(DWORD)+1;
	//Write old callback function data at the new position
	WriteProcessMemory(currentProcess, (void*)writeAddr, callback_instructions, sizeof_callback, NULL);

	writeAddr += sizeof_callback;

	BYTE jmp_back[5] = {
		JMP,
		0x00, 0x00, 0x00, 0x00, //address
	};

	//Write opcode into buffer
	memcpy(&jmp_back[1], &dwCalc_back, sizeof(DWORD));

	//Write the jump back to the original function
	WriteProcessMemory(currentProcess, (void*)writeAddr, jmp_back, sizeof(DWORD)+1, NULL);

	//Clean up
	CloseHandle(hProcess);
}

/*
	Hvor blev EBP af? Bliver den popped?
*/

Hook::_callback Hook::create_callback_wrapper(void (*hook)()) {
	/*
	Create callback function like so:

	1.	push eax						1						0
	2.	push (DWORD)&arg_offset			1 + sizeof(DWORD) = 5	1
	3.	push (DWORD)hook				1 + sizeof(DWORD) = 5	6
	4.	call detail::hook_(pre/post)	1 + sizeof(DWORD) = 5	11
	5.	mov eax, [ebp-0x18]				3						16
	6.	mov orig_ret_addr, eax			1 + sizeof(DWORD) = 5	19
	7.	add esp, 0x08					3						24
	8.	pop eax							1						27
	9.	ret								1						28
	RET is never actually reached, but is an end-of-function-marker for getFuncInstructions */

	const DWORD size = 1 + (1+sizeof(DWORD)) + (1+sizeof(DWORD)) + (1+sizeof(DWORD)) + 3 + (1+sizeof(DWORD)) + 1 + 3 + 1;
	BYTE* callback_wrapper = new BYTE[size];

	//1. push eax
	callback_wrapper[0] = Hook::PUSH_EAX;

	//2. push (DWORD)&arg_offset
	callback_wrapper[1] = Hook::PUSH;
	DWORD addr = (DWORD)&arg_offset;
	std::memcpy(&callback_wrapper[2], &addr, sizeof(DWORD));

	//3. push (DWORD)hook
	callback_wrapper[6] = Hook::PUSH;
	std::memcpy(&callback_wrapper[7], &hook, sizeof(DWORD));

	//4. call detail::hook
	callback_wrapper[11] = Hook::CALL;
	
	if(current_call_order == PRE_CALL) {
		addr = (DWORD)&detail::hook_pre - (DWORD)callback_wrapper - size + 8;
	}
	else {
		addr = (DWORD)&detail::hook_post - (DWORD)callback_wrapper - size + 8;
	}
	std::memcpy(&callback_wrapper[12], &addr, sizeof(DWORD));

	//5. mov eax, [ebp-0x18]
	std::memcpy(&callback_wrapper[16], MOV_EAX_EBP, sizeof(MOV_EAX_EBP));

	//6. mov orig_ret_addr, eax
	addr = (DWORD)&orig_ret_addr;
	callback_wrapper[19] = PARTIAL_MOV;
	std::memcpy(&callback_wrapper[20], &addr, sizeof(DWORD));

	//8. add esp, 0x08
	std::memcpy(&callback_wrapper[24], ADD_ESP_8, sizeof(ADD_ESP_8));

	//7. pop eax
	callback_wrapper[27] = POP_EAX;

	//9. Ret
	callback_wrapper[28] = Hook::RET;

	//Set permissions to memory area so we can execute our code
	DWORD OldProtect;
	VirtualProtect(callback_wrapper, size, PAGE_EXECUTE_READWRITE, &OldProtect);

	return (_callback)callback_wrapper;
}

__declspec(noinline) Hook::_callback Hook::create_post_callback_wrapper(void (*hook)()) {

	/*
		1. sub		esp, numOfArgs_bytes	(So we don't remove the arguments from the stack when we push old eip when we call the hook)
		2. call		hook;					(Using absoloute call through a pointer)
		3. add		esp, numOfArgs_bytes	(Restore old state of esp)
		4. push		orig_ret_addr
		5. ret
	*/

	const DWORD size = (2 + sizeof(DWORD)) + (2 + sizeof(DWORD)) + (2 + sizeof(DWORD)) + (2 + sizeof(DWORD)) + 1;
	BYTE* func = new BYTE[size];
	DWORD* hook_ptr = new DWORD;
	*hook_ptr = (DWORD)hook;

	DWORD addr;

	//1. sub esp, numOfArgs_bytes
	std::memcpy(&func[0], SUB_ESP_NUMOFARGS_BYTES, sizeof(SUB_ESP_NUMOFARGS_BYTES));
	addr = (DWORD)&numOfArgs_bytes;
	std::memcpy(&func[2], &addr, sizeof(DWORD));

	//2. call hook;
	func[6] = 0xFF; //Absolute indirect call
	func[7] = 0x15;
	addr = (DWORD)hook_ptr;
	std::memcpy(&func[8], &addr, sizeof(DWORD));

	//3. add esp, numOfArgs_bytes
	std::memcpy(&func[12], ADD_ESP_NUMOFARGS_BYTES, sizeof(ADD_ESP_NUMOFARGS_BYTES));
	addr = (DWORD)&numOfArgs_bytes;
	std::memcpy(&func[14], &addr, sizeof(DWORD));

	//4. push orig_ret_addr
	func[18] = 0xFF; //Push value of absolute address on stack
	func[19] = 0x35;
	addr = (DWORD)&orig_ret_addr;
	std::memcpy(&func[20], &addr, sizeof(DWORD));

	//5. ret
	func[24] = RET;

	//Allow execution of the newly created asm
	DWORD OldProtect;
	VirtualProtect(func, size, PAGE_EXECUTE_READWRITE, &OldProtect);

	return (_callback)func;
}

//Add hook on function "func" in dll "module"
void Hook::setHook(const char* func, const char* module, const std::size_t numOfArgs, const call_order call_order, void (*hook)()) {
	this->numOfArgs_bytes = numOfArgs*4;
	this->current_call_order = call_order;

	_callback callback;
	if(call_order == PRE_CALL) {
		callback = create_callback_wrapper(hook);
	}
	else {
		_callback middle_func = create_post_callback_wrapper(hook);
		callback = create_callback_wrapper(middle_func);
	}
	this->hook = callback;

	//Hook func with the newly created func as callback
	hook_function(module, func, (DWORD)this->hook);
}

void Hook::unsetHook() {
	//Optain process and process id of this process
	HANDLE currentProcess = GetCurrentProcess();
	DWORD currentProcessId = GetProcessId(currentProcess);

	//Buffer for the original code to override
	BYTE oldCode[sizeof(DWORD)+1];

	//Open the process for reading
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, currentProcessId);

	//Read legit moved code that was overriden for the jump
	ReadProcessMemory(hProcess, (void*)this->hook, oldCode, sizeof(oldCode), NULL);
	
	//Write legit moved code back into the hooked function instead of jump
	WriteProcessMemory(currentProcess, (void*)dwAddr, oldCode, sizeof(oldCode), NULL);

	CloseHandle(hProcess);

	//Clear variables
	dwAddr = NULL;
	current_call_order = NULL;
	numOfArgs_bytes = 0;
	arg_offset = 0;
	hook = nullptr;
}
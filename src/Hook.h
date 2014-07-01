#include <Windows.h>
#include <iostream>		

#ifndef _MSC_VER
static_assert(false, "This library is only compatible with Microsoft Visual C++")
#endif

class Hook
{
public:
	typedef int call_order;
	typedef void (*_callback)();
	static const call_order POST_CALL = 0;
	static const call_order PRE_CALL = 1;

private:
	DWORD orig_ret_addr;
	std::size_t numOfArgs_bytes;
	void (*hook)();
	call_order current_call_order;
	DWORD dwAddr; //Address of hooked function
	DWORD arg_offset;

	static const BYTE JMP = 0xE9;
	static const BYTE RET = 0xC3;
	static const BYTE PUSH = 0x68;
	static const BYTE CALL = 0xE8;
	static const BYTE ADD_ESP_8[3];
	static const BYTE MOV_EAX_EBP[3];
	static const BYTE SUB_ESP_NUMOFARGS_BYTES[2];
	static const BYTE ADD_ESP_NUMOFARGS_BYTES[2];
	static const BYTE PARTIAL_MOV = 0xA3;
	static const BYTE PUSH_EAX = 0x50;
	static const BYTE POP_EAX = 0x58;
	
	BYTE* getFuncInstructions(const HANDLE& hProcess, DWORD lpFunction, DWORD& numOfInstructions, BYTE eof_inst);
	void hook_function(LPCSTR lpModule, LPCSTR lpFuncName, DWORD lpFunction);
	_callback create_callback_wrapper(void (*hook)());
	_callback create_post_callback_wrapper(void (*hook)());

public:

	/*
		Get the n'th argument (from the left).
		Note:
			- Do NOT make n a const int. Leave it as non-const!
				The compiler breaks the code if it's const
	*/
	template<typename T>
	__declspec(noinline) volatile T getArg(int n) {
		//Ugly! But the alternative would be inline asm, which would be an overkill here
		return *(T*)(arg_offset+(n*4));
	}

	template<typename T>
	__declspec(noinline) volatile void setArg(int n, T arg) {
		*(T*)(arg_offset+(n*4)) = arg;
	}

	template<typename T>
	__declspec(noinline) volatile void setReturnValue(T val) {
		__asm {
			mov eax, val
		}
	}

	//Add hook on function "func" in dll "module"
	void setHook(const char* func, const char* module, const std::size_t numOfArgs, const call_order call_order, void (*hook)());

	void unsetHook();
};
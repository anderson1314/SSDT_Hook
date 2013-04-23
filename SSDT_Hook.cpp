#include<ntddk.h>

typedef NTSTATUS (* NTOPENTHREAD)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PCLIENT_ID ClientId
	);

typedef NTSTATUS (* NTOPENPROCESS)(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId
	);


extern "C" extern NTSTATUS ObOpenObjectByPointer (
    __in PVOID Object,                                            
    __in ULONG HandleAttributes,                           
    __in_opt PACCESS_STATE PassedAccessState,  
    __in ACCESS_MASK DesiredAccess,                   
    __in_opt POBJECT_TYPE ObjectType,                   
    __in KPROCESSOR_MODE AccessMode,               
    __out PHANDLE Handle                                        
    );

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR Base;
	PULONG Count;
	ULONG Limit;
	PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
extern "C" extern PKSERVICE_TABLE_DESCRIPTOR    KeServiceDescriptorTable;//KeServiceDescriptorTableΪ��������

#define NEW_SYSCALL
//#define DBG_ZWJ 

/////////////////////////////////////
VOID Hook1();
VOID Hook2();
VOID Unhook();
VOID OnUnload(IN PDRIVER_OBJECT DriverObject);


#ifdef NEW_SYSCALL  //for add new system call
INT ProcessIndex[]={10,78,124,278,306,381,395,482,500,514,548,562,574,582,638};
#else
INT ProcessIndex[]={10,78,124,278,306,381,395,482,500,514,562,574,582,638};  //Remove ObOpenObjectByPointer Call index
INT IndexOfOpenByPoint= 548;
#endif

NTOPENPROCESS OldProcess;
NTOPENPROCESS MeProcess;

#ifdef NEW_SYSCALL  //for add new system call
//Save Old ServiceTable 
PULONG OldServiceTableBase;
PUCHAR OldArgumentTable;
ULONG OldLimit;

PULONG NewServiceTable;  //New ServiceTable  ,size 0x11d* 4
PUCHAR NewArgumentTable; //New ArgumentTable ,size 0x11d
#endif


//////////////////////////////////////
ULONG JmpAddress;//��ת��NtOpenProcess��ĵ�ַ
ULONG OldServiceAddress;//ԭ��NtOpenProcess�ķ����ַ

PULONG TempBuff;

#define MaxFuncLength  656 

ULONG MeNtOpenProcess;
INT RealFuncLength;
ULONG MeHookAddress;
ULONG OrgAddr;


#if 0
NTSTATUS MyNtOpenProcess(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PCLIENT_ID ClientId) 
	{
		ACCESS_MASK oDA;
		OBJECT_ATTRIBUTES oOA;
		CLIENT_ID oCID;
		NTSTATUS statusF, statusT;

		oDA = DesiredAccess;
		oOA = *ObjectAttributes;
		oCID = *ClientId;
		#ifdef DBG_ZWJ
		__asm{
			int 3
		}
		#endif
		OldProcess=(NTOPENTHREAD)OldServiceAddress;

		//statusF = OldProcess(ProcessHandle, oDA, &oOA, &oCID);
		//statusT = ((NTOPENPROCESS)MeNtOpenProcess)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		
		//statusF = OldProcess(ProcessHandle, oDA, &oOA, &oCID);
		statusT = OldProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	
		return statusT;
	}

#endif

//////////////////////////////////////
#if 0
__declspec(naked) NTSTATUS __stdcall MyNtOpenProcess(PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId) 
{

	NTSTATUS statusF, statusT;
#ifdef DBG_ZWJ
	DbgPrint("NtOpenProcess() called \n");
	__asm{
		int 3
	}
#endif	
	//(*oProcessHandle) = (*ProcessHandle);
	//oDA = DesiredAccess;
	//(*oOA) = (*ObjectAttributes);
	//(*oCID) = (*ClientId);
	RtlZeroMemory(TempBuff,16);
	*TempBuff =(ULONG)ProcessHandle;
	*((ULONG*)((ULONG)TempBuff+4))=(ULONG)DesiredAccess;
	*((ULONG*)((ULONG)TempBuff+8))=(ULONG)ObjectAttributes;
	*((ULONG*)((ULONG)TempBuff+12))=(ULONG)ClientId;

#ifdef DBG_ZWJ
	__asm{
		int 3
	}
#endif
	OldProcess=(NTOPENTHREAD)OldServiceAddress;
	//MeProcess=(NTOPENPROCESS)MeNtOpenProcess;
	//statusF = OldProcess(ProcessHandle, oDA, &oOA, &oCID);
	//statusT = ((NTOPENPROCESS)MeNtOpenProcess)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	//return statusT;
	__asm{
		call OldProcess
		mov  statusF,eax
//		push [TempBuff+12]
//		push [TempBuff+8]
//		push [TempBuff+4]
//		push [TempBuff]
//		call  MeProcess

#if 0
		
		//push    0C4h
		//push    804daaa8h  //��ʮ���ֽ�
		//jmp		[JmpAddress]

#endif

#if 0
			push    0C4h
			push    804daaa8h  //��ʮ���ֽ�
			push    eax
			mov		eax,PUCNtOpenProcess
			add		eax,11
			mov		eax,[eax]
			//int 3
			add		eax,PUCNtOpenProcess
			add		eax,0fh
			mov     Temp,eax
			pop		eax
			//int 3
			call	Temp
			//int 3
			jmp     [JmpAddress]  
#endif		
     
	}
	statusT = ((NTOPENPROCESS)MeNtOpenProcess)((PHANDLE)(*TempBuff),(ACCESS_MASK) (*((ULONG*)((ULONG)TempBuff+4))),(POBJECT_ATTRIBUTES) (*((ULONG*)((ULONG)TempBuff+8))),(PCLIENT_ID)(*((ULONG*)((ULONG)TempBuff+12))));
	DbgPrint("NtOpenProcess() called end \n");
	//return statusT;
}
#endif


//                 ���º�����CALL��Local��ַת����ȷ							
//==================================================================
//Index��			ָ��ĳ������Ҫת����תCall���ڵ�ַƫ������
//CodeBaseAddress��	�����׵�ַ
//==================================================================

VOID ModifyCallLocalAddress(INT Index[],INT ArraySize,PUCHAR CodeBaseAddress,LONG Diff)
{
	#ifdef DBG_ZWJ
	__asm{
	int 3
	}
	#endif
	for(int i=0; i<ArraySize ; i++ )
	{
		*((ULONG*)(CodeBaseAddress+Index[i]+1))=(*((LONG*)(CodeBaseAddress+Index[i]+1))+Diff);
		//*((ULONG*)(CodeBaseAddress+Index[i]+5))=(*((LONG*)(CodeBaseAddress+Index[i]+5))+Diff);
	}

#ifndef NEW_SYSCALL
	#ifdef DBG_ZWJ
	DbgPrint("IndexOfOpenByPoint [0x%8X] => *IndexOfOpenByPoint  0x%8X  \n",((ULONG)CodeBaseAddress+IndexOfOpenByPoint),*((ULONG*)(CodeBaseAddress+IndexOfOpenByPoint+1)));
	#endif
	*((ULONG*)(CodeBaseAddress+IndexOfOpenByPoint+1))=(ULONG)ObOpenObjectByPointer - ((ULONG)CodeBaseAddress+IndexOfOpenByPoint+5);
	#ifdef DBG_ZWJ
	DbgPrint("Change IndexOfOpenByPoint [0x%8X] => *IndexOfOpenByPoint  0x%8X  \n",((ULONG)CodeBaseAddress+IndexOfOpenByPoint),*((ULONG*)(CodeBaseAddress+IndexOfOpenByPoint+1)));
	#endif
#endif
}

//                  �����������ʵ�ʳ��Ȳ�Copy��ָ��λ��							
//==================================================================
//StartAddress��	�����׵�ַ
//FuncMaxLength���������ܵ����Size������ʵ��Size, 4��8��������
//ReturnByte��ԭ����returnʱƽ���ջ��byte��
//NewFuncStartAddress�����ص��º�����ַ
//==================================================================
VOID SaveNtOpenProcessCode(ULONG StartAddress,ULONG FuncMaxLength,ULONG ReturnByte,ULONG * MyFuncStartAddress,INT *RealLength)
{
	LONG Diff;
	RealFuncLength=0;

	PUCHAR NewFuncStartAddress=(PUCHAR)ExAllocatePool(NonPagedPool,FuncMaxLength);
	TempBuff=(PULONG)ExAllocatePool(NonPagedPool,16);

	//oProcessHandle = (PHANDLE)TempBuff;
	//(PVOID*)oDA = DesiredAccess;
	//oOA = (POBJECT_ATTRIBUTES)((ULONG)TempBuff+8);
	//oCID = (PCLIENT_ID)((ULONG)TempBuff+12);

	#ifdef DBG_ZWJ
	DbgPrint("NewFuncStartAddress 0x%8X \n",(ULONG)NewFuncStartAddress);
	#endif
	RtlFillMemory(NewFuncStartAddress,FuncMaxLength,0xCC);
	
	//������������ֵ
	Diff=StartAddress-(ULONG)NewFuncStartAddress;
	#ifdef DBG_ZWJ
	DbgPrint("Diff 0x%08X \n",Diff);
	#endif

	for(int i=0 ;i < FuncMaxLength ; i ++)
	{
		#ifdef DBG_ZWJ
		DbgPrint("Search ...:%d  0x%02X \n",i,*(UCHAR*)(StartAddress+i));
		#endif
		if(*(UCHAR*)(StartAddress+i) == 0xC2)
		{
			#ifdef DBG_ZWJ
			DbgPrint("StartAddress+i+1 =  0x%4X \n",*(USHORT *)(StartAddress+i+1));
			#endif
			if( *(USHORT *)(StartAddress+i+1)==ReturnByte)
			{
				MeHookAddress=StartAddress+i;   //for inline hook address
				//OrgAddr=*((PULONG)StartAddress+i-4);
				*RealLength = i + 3;
				break;
			}
		}
	}
	#ifdef DBG_ZWJ
	DbgPrint("MeHookAddress:%d \n",MeHookAddress );
	DbgPrint("RealFuncLength:%d \n",*RealLength );
	#endif
	
	RtlCopyMemory(NewFuncStartAddress,(VOID *)StartAddress,*RealLength);
	
	#ifdef DBG_ZWJ
	DbgPrint("NewFuncStartAddress+11 org:0x%08X \n",*((ULONG*)(NewFuncStartAddress+11)) );
	#endif
	//*((ULONG*)(PUCNtOpenProcess+11))=(*((LONG*)(PUCNtOpenProcess+11))+Diff);

	ModifyCallLocalAddress(ProcessIndex,sizeof(ProcessIndex)/sizeof(INT),NewFuncStartAddress,Diff);

	#ifdef DBG_ZWJ
	DbgPrint("NewFuncStartAddress+11 chg:0x%08X \n",*((ULONG*)(NewFuncStartAddress+11)) );
	#endif
	//*((UCHAR*)(PUCNtOpenProcess+15))=0xE9;
	//*((ULONG*)(PUCNtOpenProcess+16))=0x805c22a5;

	#ifdef DBG_ZWJ
	for (int i=0; i<FuncMaxLength; i++ )
	{
		DbgPrint("0x%d:0x%02X \n",i,NewFuncStartAddress[i] );
	}
	#endif

	* MyFuncStartAddress=(ULONG)NewFuncStartAddress;
	#ifdef DBG_ZWJ
	DbgPrint("MyFuncStartAddress:0x%08X \n",* MyFuncStartAddress );
	
	__asm{
		int 3
	}
	#endif
}


extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = OnUnload;
	#ifdef DBG_ZWJ
	DbgPrint("Unhooker load \n");
	#endif
	Hook1();
	Hook2();
	#ifdef DBG_ZWJ
	__asm int 3
	#endif
	return STATUS_SUCCESS;
}
/////////////////////////////////////////////////////
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{	
	#ifdef DBG_ZWJ
	DbgPrint("Unhooker unload! \n");
	#endif
	Unhook();
}
/////////////////////////////////////////////////////
VOID Hook1()
{
	ULONG  Address;

#ifdef NEW_SYSCALL  //for add new system call
	OldServiceTableBase=KeServiceDescriptorTable->Base;
	OldLimit=KeServiceDescriptorTable->Limit;
	OldArgumentTable=KeServiceDescriptorTable->Number;

	NewServiceTable=(PULONG)ExAllocatePool(NonPagedPool,1140);//Size =4*0x11D =474
	NewArgumentTable=(PUCHAR)ExAllocatePool(NonPagedPool,288); //Size =0x11D=285 ==>288
	RtlZeroMemory(NewServiceTable,1140);
	RtlZeroMemory(NewArgumentTable,288);
	RtlCopyMemory(NewServiceTable,(VOID*)OldServiceTableBase,1136);
	RtlCopyMemory(NewArgumentTable,(VOID*)OldArgumentTable,284);

	
	#ifdef DBG_ZWJ
	DbgPrint("AdOldServiceTableBase:0x%08X ,OldLimit:0x%08X ,OldArgumentTable:0x%08X \n",OldServiceTableBase,OldLimit,OldArgumentTable);
	DbgPrint("Address:0x%08X \n",Address);
	#endif
#endif 

	Address = (ULONG)KeServiceDescriptorTable->Base + 0x7A * 4;//0x7AΪNtOpenProcess����ID
	OldServiceAddress = *(ULONG*)Address;//����ԭ��NtOpenProcess�ĵ�ַ
	#ifdef DBG_ZWJ
	DbgPrint("OldServiceAddress:0x08X% \n",OldServiceAddress);
	#endif

	SaveNtOpenProcessCode(OldServiceAddress,MaxFuncLength,0x0010,&MeNtOpenProcess,&RealFuncLength);
	#ifdef DBG_ZWJ
	DbgPrint("MeNtOpenProcess:0x%08X RealFuncLength: %d \n",MeNtOpenProcess,RealFuncLength);
	#endif
	//JmpAddress = (ULONG)NtOpenProcess + 10; //��ת��NtOpenProcess����ͷ��10�ĵط�����������ǰ��д��JMP��ʧЧ��
	#ifdef DBG_ZWJ
	//DbgPrint("JmpAddress:0x%08X",JmpAddress);
	#endif
}

VOID Hook2()
{
		__asm{//ȥ���ڴ汣��
		    cli
			push eax
			mov  eax,cr0
			and  eax,not 10000h
			mov  cr0,eax
			pop eax
	}

#ifdef NEW_SYSCALL  //for add new system call
	//*((ULONG*)Address) = MeNtOpenProcess;//HOOK SSDT
	//*((ULONG*)Address) = (ULONG)MyNtOpenProcess;//HOOK SSDT
	*((PULONG)((ULONG)NewServiceTable + 0x11c * 4))=MeNtOpenProcess;
	*((PULONG)((ULONG)NewServiceTable + 0x11D * 4))=0x11D;

	*((PUCHAR)((ULONG)NewArgumentTable + 0x11c))=0x10;

	KeServiceDescriptorTable->Base=NewServiceTable;
	KeServiceDescriptorTable->Number=NewArgumentTable;
	KeServiceDescriptorTable->Limit=0x11D;
#endif  	

#if 0
	//add esp, 8   <= 83 C4 08
	*((PCHAR)MeHookAddress-5)=0xCC;
	*((PCHAR)MeHookAddress-4)=0xCC;
	*((PCHAR)MeHookAddress-3)=0x83;
	*((PCHAR)MeHookAddress-2)=0xC4;
	*((PCHAR)MeHookAddress-1)=0x08;
#endif
	*((PCHAR)MeHookAddress)=0xE9;
	*((PULONG)(MeHookAddress+1))=MeNtOpenProcess-(MeHookAddress +5);

	__asm{//�ָ��ڴ汣��  
			push eax
		    mov  eax,cr0
			or   eax,10000h
			mov  cr0,eax
			pop eax
			sti
	}
}
//////////////////////////////////////////////////////
VOID Unhook()
{
	ULONG  Address;
	Address = (ULONG)KeServiceDescriptorTable->Base + 0x7A * 4;//����SSDT

	__asm{//ȥ���ڴ汣��
			cli
			push eax
			mov  eax,cr0
			and  eax,not 10000h
			mov  cr0,eax
			pop eax
	}

#ifdef NEW_SYSCALL  //for add new system call
	//*((ULONG*)Address) = (ULONG)OldServiceAddress;//��ԭSSDT
	KeServiceDescriptorTable->Base=OldServiceTableBase;
	KeServiceDescriptorTable->Number=OldArgumentTable;
	KeServiceDescriptorTable->Limit=OldLimit;
#endif  

#if 0
	//b8300000c0
	*((PCHAR)MeHookAddress-5)=0xB8;
	*((PCHAR)MeHookAddress-4)=0x30;
	*((PCHAR)MeHookAddress-3)=0x0;
	*((PCHAR)MeHookAddress-2)=0x0;
	*((PCHAR)MeHookAddress-1)=0xC0;
#endif
	//e8326af7ff
	//*((PCHAR)MeHookAddress)=0xe8;
	//*((PULONG)(MeHookAddress+1))=OrgAddr;
	*((PCHAR)MeHookAddress  )=0xc2;
	*((PCHAR)MeHookAddress+1)=0x10;
	*((PCHAR)MeHookAddress+2)=0x00;
	*((PCHAR)MeHookAddress+3)=0xcc;
	*((PCHAR)MeHookAddress+4)=0xcc;

	//ExFreePool(&MeNtOpenProcess);

	__asm{//�ָ��ڴ汣��  
			push eax
			mov  eax,cr0
			or   eax,10000h
			mov  cr0,eax
			pop eax
			sti
	}
	#ifdef DBG_ZWJ
	DbgPrint("Unhook \n");
	#endif
}

#if 0
// OrgRel	ԭ�����ת��ַ
// CurAbs	��ǰ������Ե�ַ
// MyAbs	�滻������Ե�ַ
// CodeLen	��ת����ռ�ݵĳ���
// ����ֵ	���滻�������Ե�ַ
LONG GetRelAddr(LONG OrgRel, ULONG CurAbs, ULONG MyAbs) //, ULONG CodeLen)
{
	ULONG TrgAbs;
	TrgAbs = CurAbs + OrgRel; // + CodeLen; //Ŀ�ĵ�ַ
	return TrgAbs - MyAbs;
}

// ����ԭ�����������Ĵ��루���޸ĵ���ȷ����ָ�����
// pCode ����������������ĵ�ַ
// TrgAddr Ҫ����ĺ����ĵ�ַ
// BufferLength ��������ռ�õĴ�С
VOID BufferCode(PUCHAR pCode, ULONG TrgAddr, ULONG BufferLength)
{
	PUCHAR cPtr, pOpcode;
	ULONG cAbs, i;
	LONG oRel, cRel;
    ULONG Length;
	memset(pCode, 0x90, BufferLength);
	for (i = 0; i < BufferLength; i+= Length)
	{
	
		cAbs = TrgAddr + i;
		pCode[i] = *(PUCHAR)cAbs;
		Length = SizeOfCode((PUCHAR)cAbs, &pOpcode);//Ӌ�㮔ǰָ���L��
		if(Length)
		{//��Ϊ0�򿼹���ָ� ���ȣ�Length
			memcpy(pCode + i, (PVOID)(cAbs), Length);
		}//���������ָ�����´���������λ
		//if (!Length) break;
		switch (*(PUCHAR)cAbs)
		{
		case 0x0F: //JXX NEAR X
			if ((*(PUCHAR)(cAbs + 1) >= 0x80)&&(*(PUCHAR)(cAbs + 1) <= 0x8F))
			{
				oRel = *(PLONG)(cAbs + 2);
				if ((oRel + cAbs + 6 > TrgAddr + BufferLength)||
					(oRel + cAbs + 6 < TrgAddr)) //�ж���ת�Ƿ��ڹ��̷�Χ��
				{
					pCode[i + 1] = *(PUCHAR)(cAbs + 1);
					cRel = GetRelAddr(oRel, cAbs, (ULONG)pCode + i);
					memcpy(pCode + i + 2, &cRel, sizeof(LONG));
					//DbgPrint("JXX: 0x%08X -> 0x%08X", cAbs, (ULONG)pCode + i);
					//i += sizeof(LONG) + 1;
				}
			}
			break;
		case 0xE8: //CALL
			oRel = *(PLONG)(cAbs + 1);				
			if ((oRel + cAbs + 5 > TrgAddr + BufferLength)||
				(oRel + cAbs + 5 < TrgAddr)) //�ж���ת�Ƿ��ڹ��̷�Χ��
			{
				cRel = GetRelAddr(oRel, cAbs, (ULONG)
					+ i);
				memcpy(pCode + i + 1, &cRel, sizeof(LONG));
				//DbgPrint("CALL: 0x%08X -> 0x%08X", cAbs, (ULONG)pCode + i);
				
			}
			break;
		case 0x80: //CMP BYTE PTR X
			if (*(PUCHAR)(cAbs + 1) == 0x7D)
			{
				memcpy(pCode + i + 1, (PVOID)(cAbs + 1), 3);
				//i += 3; 
				continue;
			}
			break;
		case 0xC2: //RET X
			if (*(PUSHORT)(cAbs +1) == 0x10)
			{
				memcpy(pCode + i + 1, (PVOID)(cAbs + 1), sizeof(USHORT));
				//i += sizeof(USHORT);
			}
			break;
			/*case 0xE9: //JMP
			oRel = *(PLONG)(cAbs + 1);
			if (oRel + cAbs > TrgAddr + BufferLength)
			{
			cRel = GetRelAddr(oRel, cAbs, (ULONG)pCode + i);
			memcpy(pCode + i + 1, &cRel, sizeof(LONG));
			i += 4;
			}*/
		//default:	
		}
/*����Ĵ�����������
		if ((*(PUCHAR)cAbs == 0x39)||(*(PUCHAR)cAbs == 0x89)||(*(PUCHAR)cAbs == 0x8D))
		{
			memcpy(pCode + i + 1, (PVOID)(cAbs + 1), sizeof(USHORT));
			i += sizeof(USHORT);
			continue;
		}*/
		
		//DbgPrint("addr:%08X//n:%02X//Length!%08X\n",(ULONG)cAbs,*(PUCHAR)cAbs,Length);
		/*if ((*(PUCHAR)cAbs >= 0x70)&&(*(PUCHAR)cAbs <= 0x7F)&&(*(PUCHAR)(cAbs - 1) != 0xFF))
		{
		oRel = (LONG)(*(PCHAR)(cAbs + 1));
		cRel = GetRelAddr(oRel, cAbs, (ULONG)pCode + i);
		memcpy(pCode + i + 1, &cRel, 1);
		i++; continue;
		}*/
	}
}

#endif
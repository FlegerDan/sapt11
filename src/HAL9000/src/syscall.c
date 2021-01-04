#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread_internal.h"
#include "cpumu.h"
#include "vm_reservation_space.h"
#include "bitmap.h"
#include "lock_common.h"
#include "io.h"
#include "vmm.h"


extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8]; // il obtine

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId); // afiseaza Id-ul de apel al sistemului

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;
        //GdtIsSegmentPrivileged();
        
        //SyscallThreadExit
        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
           
        // STUDENT TODO: implement the rest of the syscalls
        case SyscallIdFileWrite:
            status = SyscallFileWrite((UM_HANDLE)pSyscallParameters[0], (PVOID)pSyscallParameters[1], (QWORD)pSyscallParameters[2], (QWORD*)pSyscallParameters[3]);
            break;
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)pSyscallParameters[0]);
            break;
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)pSyscallParameters[0]);
            break;
        case SyscallIdProcessGetNumberOfPages:
            status = SyscallProcessGetNumberOfPages((DWORD*)pSyscallParameters[0], (DWORD*)pSyscallParameters[1]);
            break;
        case SyscallIdReadMemory:
            status = SyscallReadMemory((PBYTE)pSyscallParameters[0], (PBYTE)pSyscallParameters[1]);
        case SyscallIdFileRead:
            break;
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit( // functie responsabila pentru flaguri la registrii
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry); // acces la kernel
    /*
    This function is
responsible for switching to the kernel stack, for saving the user register state, for calling
the C SyscallHandler() function.*/
    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}


// STUDENT TODO: implement the rest of the syscalls
STATUS
SyscallThreadExit(
    IN      STATUS                  ExitStatus
)
{
    ThreadExit(ExitStatus);
    return ExitStatus;
}
STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    ProcessTerminate(NULL);
    return ExitStatus;
}
STATUS
SyscallVirtualAlloc(
    IN_OPT      PVOID                   BaseAddress,
    IN          QWORD                   Size,
    IN          VMM_ALLOC_TYPE          AllocType,
    IN          PAGE_RIGHTS             PageRights,
    IN_OPT      UM_HANDLE               FileHandle,
    IN_OPT      QWORD                   Key,
    OUT         PVOID* AllocatedAddress
)
{
    PPROCESS proces = GetCurrentProcess();
    *AllocatedAddress = VmmAllocRegionEx(BaseAddress,
        Size,
        AllocType,
        PageRights,
        TRUE,
        NULL,
        proces->VaSpace,
        proces->PagingData,
        NULL
    );
    
}

STATUS
SyscallFileWrite(
    IN  UM_HANDLE               FileHandle,
    PVOID                       Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    STATUS status = STATUS_SUCCESS;

    if (FileHandle == UM_FILE_HANDLE_STDOUT) {

        status = MmuIsBufferValid(Buffer, SHADOW_STACK_SIZE, PAGE_RIGHTS_WRITE, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            return status;
        }
        *BytesWritten = BytesToWrite;

        LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);
    }


    return status;
}


STATUS
SyscallProcessGetNumberOfPages(
    OUT     DWORD* PagesCommitted,
    OUT     DWORD* PagesReserved
)
{
    
    VmGetNumberOfPagesCommitted(VmmRetrieveReservationSpaceForSystemProcess(), &PagesCommitted);
    VmGetNumberOfPagesReserved(VmmRetrieveReservationSpaceForSystemProcess(), &PagesReserved);
}
STATUS
SyscallReadMemory(
    IN_READS(1)     PBYTE   Address,
    OUT             PBYTE   ValueRead
)
{

    PML4 cr3;
    cr3.Raw =(QWORD) __readcr3();;
    BOOLEAN Accessed;
    BOOLEAN Dirty;
    STATUS status = STATUS_SUCCESS;
    ASSERT(NULL != Address);
    status = MmuIsBufferValid(Address, SHADOW_STACK_SIZE, PAGE_RIGHTS_WRITE, GetCurrentProcess());
    if (status != STATUS_SUCCESS)
    {
        PHYSICAL_ADDRESS test = VmmGetPhysicalAddressEx(cr3, Address, &Accessed, &Dirty);
        ASSERT(NULL != test);
        ValueRead = *((PBYTE) test);
    }
   
}


STATUS
SwapOut(
    QWORD PAGE_SIZE
)
{
    char b;
    PBYTE pAddress;

    SyscallVirtualAlloc(NULL, 8 * PAGE_SIZE, VMM_ALLOC_TYPE_COMMIT | VMM_ALLOC_TYPE_RESERVE, PAGE_RIGHTS_READWRITE, UM_INVALID_HANDLE_VALUE, 0, &pAddress);

    memset(pAddress, 0x91, 8 * PAGE_SIZE);

    SwapOut(pAddress);

    for (DWORD i = 0; i < 8 * PAGE_SIZE; ++i)
    {
        LOG("Value at offset %u is 0x%x\n", i, pAddress[i]);
    }

    // swap out the stack
    SwapOut(&b);

    // Lets have some fun
    SwapOut(NULL);
}
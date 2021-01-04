#include "HAL9000.h"
#include "thread_internal.h"
#include "mutex.h"

#define MUTEX_MAX_RECURSIVITY_DEPTH         MAX_BYTE

typedef struct _MUTEX_SYSTEM_DATA
{
    LOCK                AllMutexesLock;

    _Guarded_by_(AllMutexesLock)
     LIST_ENTRY          AllMutexesList;
} MUTEX_SYSTEM_DATA, * PMUTEX_SYSTEM_DATA;

static MUTEX_SYSTEM_DATA m_mutexSystemData;

void
_No_competing_thread_
MutexSystemPreinit(
    void
)
{
    memzero(&m_mutexSystemData, sizeof(MUTEX_SYSTEM_DATA));

    InitializeListHead(&m_mutexSystemData.AllMutexesList);
    LockInit(&m_mutexSystemData.AllMutexesLock);

}
_No_competing_thread_
void
MutexInit(
    OUT         PMUTEX      Mutex,
    IN          BOOLEAN     Recursive
    )
{
    ASSERT( NULL != Mutex );

    memzero(Mutex, sizeof(MUTEX));

    LockInit(&Mutex->MutexLock);

    InitializeListHead(&Mutex->WaitingList);
    InitializeListHead(&Mutex->AllList);
    INTR_STATE oldIntrState;
    LockAcquire(&m_mutexSystemData.AllMutexesLock, &oldIntrState);
    InsertTailList(&m_mutexSystemData.AllMutexesList, &Mutex->AllList);
    LockRelease(&m_mutexSystemData.AllMutexesLock, oldIntrState);

    Mutex->MaxRecursivityDepth = Recursive ? MUTEX_MAX_RECURSIVITY_DEPTH : 1;
}
STATUS
MutexExecuteForEachMutexEntry(
    IN      PFUNC_ListFunction  Function,
    IN_OPT  PVOID               Context
)
{
    STATUS status;
    INTR_STATE oldState;

    if (NULL == Function)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    status = STATUS_SUCCESS;

    LockAcquire(&m_mutexSystemData.AllMutexesLock, &oldState);
    status = ForEachElementExecute(&m_mutexSystemData.AllMutexesList,
        Function,
        Context,
        FALSE
    );
    LockRelease(&m_mutexSystemData.AllMutexesLock, oldState);

    return status;
}
ACQUIRES_EXCL_AND_REENTRANT_LOCK(*Mutex)
REQUIRES_NOT_HELD_LOCK(*Mutex)
void
MutexAcquire(
    INOUT       PMUTEX      Mutex
    )
{
    INTR_STATE dummyState;
    INTR_STATE oldState;
    PTHREAD pCurrentThread = GetCurrentThread();

    ASSERT( NULL != Mutex);
    ASSERT( NULL != pCurrentThread );

    if (pCurrentThread == Mutex->Holder)
    {
        ASSERT( Mutex->CurrentRecursivityDepth < Mutex->MaxRecursivityDepth );

        Mutex->CurrentRecursivityDepth++;
        return;
    }

    oldState = CpuIntrDisable();

    LockAcquire(&Mutex->MutexLock, &dummyState );
    if (NULL == Mutex->Holder)
    {
        Mutex->Holder = pCurrentThread;
        Mutex->CurrentRecursivityDepth = 1;
    }

    while (Mutex->Holder != pCurrentThread)
    {
        InsertTailList(&Mutex->WaitingList, &pCurrentThread->ReadyList);
        ThreadTakeBlockLock();
        LockRelease(&Mutex->MutexLock, dummyState);
        ThreadBlock();
        LockAcquire(&Mutex->MutexLock, &dummyState );
    }

    _Analysis_assume_lock_acquired_(*Mutex);

    LockRelease(&Mutex->MutexLock, dummyState);

    CpuIntrSetState(oldState);
}

RELEASES_EXCL_AND_REENTRANT_LOCK(*Mutex)
REQUIRES_EXCL_LOCK(*Mutex)
void
MutexRelease(
    INOUT       PMUTEX      Mutex
    )
{
    INTR_STATE oldState;
    PLIST_ENTRY pEntry;

    ASSERT(NULL != Mutex);
    ASSERT(GetCurrentThread() == Mutex->Holder);

    if (Mutex->CurrentRecursivityDepth > 1)
    {
        Mutex->CurrentRecursivityDepth--;
        return;
    }

    pEntry = NULL;

    LockAcquire(&Mutex->MutexLock, &oldState);

    pEntry = RemoveHeadList(&Mutex->WaitingList);
    if (pEntry != &Mutex->WaitingList)
    {
        PTHREAD pThread = CONTAINING_RECORD(pEntry, THREAD, ReadyList);

        // wakeup first thread
        Mutex->Holder = pThread;
        Mutex->CurrentRecursivityDepth = 1;
        ThreadUnblock(pThread);
    }
    else
    {
        Mutex->Holder = NULL;
    }

    _Analysis_assume_lock_released_(*Mutex);

    LockRelease(&Mutex->MutexLock, oldState);
}
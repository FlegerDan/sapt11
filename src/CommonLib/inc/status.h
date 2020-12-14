#pragma once

// every error status code has the MSB set to 1
#define FAIL_MASK                                       (1<<31)
#define WARNING_MASK                                    (1<<30)
#define INFO_MASK                                       (1<<29)

// nothing over (1<<27) should be used
#define GENERAL_MASK                                    (1<<27)
#define INTRO_MASK                                      (1<<26)
#define VMX_MASK                                        (1<<25)
#define CPU_MASK                                        (1<<24)
#define COMM_MASK                                       (1<<23)
#define TIMER_MASK                                      (1<<22)
#define HEAP_MASK                                       (1<<21)
#define MEMORY_MASK                                     (1<<20)
#define STORAGE_MASK                                    (1<<19)
#define DISK_MASK                                       (1<<18)
#define APIC_MASK                                       (1<<17)
#define DEVICE_MASK                                     (1<<16)
#define RESERVED_MASK                                   (1<<16)
// nothing under (1<<16) should be used

// general errors
#define STATUS_UNSUPPORTED                              (FAIL_MASK | GENERAL_MASK | 0x0001UL)
#define STATUS_INTERNAL_ERROR                           (FAIL_MASK | GENERAL_MASK | 0x0002UL)
#define STATUS_UNSUCCESSFUL                             (FAIL_MASK | GENERAL_MASK | 0x0003UL)
#define STATUS_ELEMENT_NOT_FOUND                        (FAIL_MASK | GENERAL_MASK | 0x0004UL)
#define STATUS_ELEMENT_FOUND                            (FAIL_MASK | GENERAL_MASK | 0x0005UL)
#define STATUS_LIST_EMPTY                               (FAIL_MASK | GENERAL_MASK | 0x0006UL)
#define STATUS_ALREADY_INITIALIZED                      (FAIL_MASK | GENERAL_MASK | 0x0007UL)
#define STATUS_ALREADY_INITIALIZED_HINT                 (WARNING_MASK | GENERAL_MASK | 0x0008UL )
#define STATUS_INCOMPATIBLE_INTERFACE                   (FAIL_MASK | GENERAL_MASK | 0x0009UL )
#define STATUS_INVALID_PARAMETER1                       (FAIL_MASK | GENERAL_MASK | 0x0011UL)
#define STATUS_INVALID_PARAMETER2                       (FAIL_MASK | GENERAL_MASK | 0x0012UL)
#define STATUS_INVALID_PARAMETER3                       (FAIL_MASK | GENERAL_MASK | 0x0013UL)
#define STATUS_INVALID_PARAMETER4                       (FAIL_MASK | GENERAL_MASK | 0x0014UL)
#define STATUS_INVALID_PARAMETER5                       (FAIL_MASK | GENERAL_MASK | 0x0015UL)
#define STATUS_INVALID_PARAMETER6                       (FAIL_MASK | GENERAL_MASK | 0x0016UL)
#define STATUS_INVALID_PARAMETER7                       (FAIL_MASK | GENERAL_MASK | 0x0017UL)
#define STATUS_INVALID_PARAMETER8                       (FAIL_MASK | GENERAL_MASK | 0x0018UL)
#define STATUS_INVALID_FILE_NAME                        (FAIL_MASK | GENERAL_MASK | 0x0019UL)
#define STATUS_FILE_NOT_FOUND                           (FAIL_MASK | GENERAL_MASK | 0x001AUL)
#define STATUS_FILE_TYPE_INVALID                        (FAIL_MASK | GENERAL_MASK | 0x001BUL)
#define STATUS_TIME_INVALID                             (FAIL_MASK | GENERAL_MASK | 0x001CUL)
#define STATUS_PATH_NOT_VALID                           (FAIL_MASK | GENERAL_MASK | 0x001DUL)
#define STATUS_FILE_ALREADY_EXISTS                      (FAIL_MASK | GENERAL_MASK | 0x001EUL)
#define STATUS_FILE_NOT_DIRECTORY                       (FAIL_MASK | GENERAL_MASK | 0x001FUL)
#define STATUS_NO_MORE_OBJECTS                          (FAIL_MASK | GENERAL_MASK | 0x0020UL)
#define STATUS_PARSE_FAILED                             (FAIL_MASK | GENERAL_MASK | 0x0021UL)
#define STATUS_JOB_INTERRUPTED                          (FAIL_MASK | GENERAL_MASK | 0x0022UL)
#define STATUS_INVALID_MZ_IMAGE                         (FAIL_MASK | GENERAL_MASK | 0x0023UL)
#define STATUS_INVALID_IMAGE_SIZE                       (FAIL_MASK | GENERAL_MASK | 0x0024UL)
#define STATUS_INVALID_PE_IMAGE                         (FAIL_MASK | GENERAL_MASK | 0x0025UL)
#define STATUS_IMAGE_NOT_64_BIT                         (FAIL_MASK | GENERAL_MASK | 0x0026UL)
#define STATUS_IMAGE_SUBSYSTEM_NOT_NATIVE               (FAIL_MASK | GENERAL_MASK | 0x0027UL)
#define STATUS_IMAGE_NOT_FULLY_LOADED                   (FAIL_MASK | GENERAL_MASK | 0x0028UL)
#define STATUS_IMAGE_HAS_RELOCATIONS                    (FAIL_MASK | GENERAL_MASK | 0x0029UL)
#define STATUS_NOT_IMPLEMENTED                          (FAIL_MASK | GENERAL_MASK | 0x002AUL)
#define STATUS_INVALID_FUNCTION                         (FAIL_MASK | GENERAL_MASK | 0x002BUL)
#define STATUS_INVALID_BUFFER                           (FAIL_MASK | GENERAL_MASK | 0x002CUL)
#define STATUS_NOT_INITIALIZED                          (FAIL_MASK | GENERAL_MASK | 0x002DUL)
#define STATUS_NO_HANDLING_REQUIRED                     (INFO_MASK | GENERAL_MASK | 0x002EUL)
#define STATUS_CONFLICTING_OPTIONS                      (FAIL_MASK | GENERAL_MASK | 0x002FUL)
#define STATUS_ASSERTION_FAILURE                        (FAIL_MASK | GENERAL_MASK | 0x0030UL)
#define STATUS_NO_DATA_AVAILABLE                        (FAIL_MASK | GENERAL_MASK | 0x0031UL)
#define STATUS_LIMIT_REACHED                            (FAIL_MASK | GENERAL_MASK | 0x0032UL)

// introspection errors
#define STATUS_INTRO_INVALID_SYSCALL_HANDLER            (FAIL_MASK | INTRO_MASK | 0x0001UL )
#define STATUS_INTRO_KERNEL_BASE_NOT_FOUND              (FAIL_MASK | INTRO_MASK | 0x0002UL )
#define STATUS_INTRO_KERNEL_INVALID_IMAGE               (FAIL_MASK | INTRO_MASK | 0x0003UL )
#define STATUS_INTRO_EXPORT_NOT_FOUND                   (FAIL_MASK | INTRO_MASK | 0x0004UL )
#define STATUS_INTRO_MODULE_LIST_NOT_FOUND              (FAIL_MASK | INTRO_MASK | 0x0005UL )
#define STATUS_INTRO_PCR_NOT_AVAILABLE                  (FAIL_MASK | INTRO_MASK | 0x0006UL )
#define STATUS_INTRO_KERNEL_ADDRESS_INVALID             (FAIL_MASK | INTRO_MASK | 0x0007UL )
#define STATUS_INTRO_VARIABLES_NOT_DEFINED              (WARNING_MASK | INTRO_MASK | 0x0008UL )
#define STATUS_INTRO_INTROSPECTION_NOT_SUPPORTED        (FAIL_MASK | INTRO_MASK | 0x0009UL )
#define STATUS_INTRO_PROCESS_NOT_VALID                  (FAIL_MASK | INTRO_MASK | 0x000AUL )
#define STATUS_INTRO_PATTERN_NOT_FOUND                  (FAIL_MASK | INTRO_MASK | 0x000BUL )
#define STATUS_INTRO_INTROSPECTION_NOT_INITIALIZED      (FAIL_MASK | INTRO_MASK | 0x000CUL )
#define STATUS_INTRO_DEBUGGER_DATA_NOT_FOUND            (FAIL_MASK | INTRO_MASK | 0x000DUL )

// vmx related issues
#define STATUS_VMX_WRITE_FAILED                         (FAIL_MASK | VMX_MASK | 0x0001UL )
#define STATUS_VMX_READ_FAILED                          (FAIL_MASK | VMX_MASK | 0x0002UL )
#define STATUS_VMX_INVEPT_FAILED                        (FAIL_MASK | VMX_MASK | 0x0003UL )
#define STATUS_VMX_EPT_MAPPING_FAILED                   (FAIL_MASK | VMX_MASK | 0x0004UL )
#define STATUS_VMX_EXIT_NOT_IMPLEMENTED                 (FAIL_MASK | VMX_MASK | 0x0005UL )
#define STATUS_VMX_FEATURE_NOT_SUPPORTED                (FAIL_MASK | VMX_MASK | 0x0006UL )
#define STATUS_VMX_UNEXPECTED_VMCALL                    (FAIL_MASK | VMX_MASK | 0x0007UL )
#define STATUS_VMX_GUEST_MEMORY_CANNOT_BE_MAPPED        (FAIL_MASK | VMX_MASK | 0x0008UL )

// cpu related errors
#define STATUS_CPU_UNSUPPORTED_FEATURE                  (FAIL_MASK | CPU_MASK | 0x0001UL)
#define STATUS_CPU_MONITOR_NOT_SUPPORTED                (FAIL_MASK | CPU_MASK | 0x0002UL)
#define STATUS_CPU_MONITOR_FILTER_SIZE_TOO_SMALL        (FAIL_MASK | CPU_MASK | 0x0003UL)
#define STATUS_CPU_MONITOR_FILTER_SIZE_TOO_LARGE        (FAIL_MASK | CPU_MASK | 0x0004UL)
#define STATUS_CPU_NO_MATCHES                           (WARNING_MASK | CPU_MASK | 0x0005UL)

// communication related errors
#define STATUS_COMM_SERIAL_ALREADY_INITIALIZED          (WARNING_MASK | COMM_MASK | 0x0001UL)
#define STATUS_COMM_SERIAL_NO_PORTS_AVAILABLE           (WARNING_MASK | COMM_MASK | 0x0002UL)
#define STATUS_COMM_SERIAL_NOT_INITIALIZED              (FAIL_MASK | COMM_MASK | 0x0003UL)
#define STATUS_COMM_VMCALL_UNSUPPORTED_COMMAND          (FAIL_MASK | COMM_MASK | 0x0004UL)

// timer related errors
#define STATUS_TIMER_INVALID_FREQUENCY                  (FAIL_MASK | TIMER_MASK | 0x0001UL)

// heap related errors
#define STATUS_HEAP_TOO_SMALL                           (FAIL_MASK | HEAP_MASK | 0x0001UL)
#define STATUS_HEAP_ALREADY_INITIALIZED                 (FAIL_MASK | HEAP_MASK | 0x0002UL)
#define STATUS_HEAP_NO_MORE_MEMORY                      (FAIL_MASK | HEAP_MASK | 0x0003UL)
#define STATUS_HEAP_INSUFFICIENT_RESOURCES              (FAIL_MASK | HEAP_MASK | 0x0004UL)

// memory related errors
#define STATUS_INVALID_POINTER                          (FAIL_MASK | MEMORY_MASK | 0x0001UL)
#define STATUS_BUFFER_TOO_SMALL                         (FAIL_MASK | MEMORY_MASK | 0x0002UL)
#define STATUS_INSUFFICIENT_MEMORY                      (FAIL_MASK | MEMORY_MASK | 0x0003UL)
#define STATUS_MEMORY_CANNOT_BE_MAPPED                  (FAIL_MASK | MEMORY_MASK | 0x0004UL)
#define STATUS_PHYSICAL_MEMORY_TOO_SMALL                (FAIL_MASK | MEMORY_MASK | 0x0005UL)
#define STATUS_MEMORY_IS_NOT_RESERVED                   (FAIL_MASK | MEMORY_MASK | 0x0006UL)
#define STATUS_PHYSICAL_MEMORY_NOT_AVAILABLE            (FAIL_MASK | MEMORY_MASK | 0x0007UL)
#define STATUS_PAT_LAYOUT_NOT_COMPATIBLE                (FAIL_MASK | MEMORY_MASK | 0x0008UL)
#define STATUS_MEMORY_CANNOT_BE_RESERVED                (FAIL_MASK | MEMORY_MASK | 0x0009UL)
#define STATUS_MEMORY_ACCESS_DENIED                     (FAIL_MASK | MEMORY_MASK | 0x000AUL)
#define STATUS_MEMORY_CANNOT_BE_COMMITED                (FAIL_MASK | MEMORY_MASK | 0x000BUL)
#define STATUS_MEMORY_CONFLICTING_ACCESS_RIGHTS         (FAIL_MASK | MEMORY_MASK | 0x000CUL)
#define STATUS_MEMORY_CONFLICTING_CACHEABILITY          (FAIL_MASK | MEMORY_MASK | 0x000DUL)
#define STATUS_BUFFER_TOO_LARGE                         (FAIL_MASK | MEMORY_MASK | 0x000EUL)
#define STATUS_MEMORY_ALREADY_RESERVED                  (FAIL_MASK | MEMORY_MASK | 0x000FUL)
#define STATUS_MEMORY_IS_NOT_COMMITED                   (FAIL_MASK | MEMORY_MASK | 0x0010UL)
#define STATUS_MEMORY_PREVENTS_USERMODE_ACCESS          (FAIL_MASK | MEMORY_MASK | 0x0011UL)
#define STATUS_MEMORY_INSUFFICIENT_ACCESS_RIGHTS        (FAIL_MASK | MEMORY_MASK | 0x0012UL)

// disk related errors
#define STATUS_DISK_MBR_NOT_PRESENT                     (FAIL_MASK | DISK_MASK | 0x0001UL)
#define STATUS_DISK_FULL                                (FAIL_MASK | DISK_MASK | 0x0002UL)

// APIC errors
#define STATUS_APIC_NOT_MAPPED                          (FAIL_MASK | APIC_MASK | 0x0001UL)
#define STATUS_APIC_NOT_INITIALIZED                     (FAIL_MASK | APIC_MASK | 0x0002UL)
#define STATUS_APIC_NOT_ENABLED                         (FAIL_MASK | APIC_MASK | 0x0003UL)

// device error
#define STATUS_DEVICE_DOES_NOT_EXIST                    (FAIL_MASK | DEVICE_MASK | 0x0001UL)
#define STATUS_DEVICE_NO_MORE_DEVICES                   (FAIL_MASK | DEVICE_MASK | 0x0002UL)
#define STATUS_DEVICE_NOT_SUPPORTED                     (FAIL_MASK | DEVICE_MASK | 0x0003UL)
#define STATUS_DEVICE_NOT_INITIALIZED                   (FAIL_MASK | DEVICE_MASK | 0x0004UL)
#define STATUS_DEVICE_SECTOR_OFFSET_EXCEEDED            (FAIL_MASK | DEVICE_MASK | 0x0005UL)
#define STATUS_DEVICE_SECTOR_COUNT_EXCEEDED             (FAIL_MASK | DEVICE_MASK | 0x0006UL)
#define STATUS_DEVICE_COULD_NOT_BE_CREATED              (FAIL_MASK | DEVICE_MASK | 0x0007UL)
#define STATUS_DEVICE_DRIVER_COULD_NOT_BE_CREATED       (FAIL_MASK | DEVICE_MASK | 0x0008UL)
#define STATUS_DEVICE_INVALID_OPERATION                 (FAIL_MASK | DEVICE_MASK | 0x0009UL)
#define STATUS_DEVICE_DATA_ALIGNMENT_ERROR              (FAIL_MASK | DEVICE_MASK | 0x000AUL)
#define STATUS_DEVICE_NO_FILESYSTEM_MOUNTED             (FAIL_MASK | DEVICE_MASK | 0x000BUL)
#define STATUS_DEVICE_FILESYSTEM_UNSUPPORTED            (FAIL_MASK | DEVICE_MASK | 0x000CUL)
#define STATUS_DEVICE_CLUSTER_INVALID                   (FAIL_MASK | DEVICE_MASK | 0x000DUL)
#define STATUS_DEVICE_ALIGNMENT_NO_SATISFIED            (FAIL_MASK | DEVICE_MASK | 0x000EUL)
#define STATUS_DEVICE_DMA_NOT_SUPPORTED                 (FAIL_MASK | DEVICE_MASK | 0x000FUL)
#define STATUS_DEVICE_DMA_PHYSICAL_ADDRESS_TOO_HIGH     (FAIL_MASK | DEVICE_MASK | 0x0010UL)
#define STATUS_DEVICE_DMA_PHYSICAL_SPAN_TOO_LARGE       (FAIL_MASK | DEVICE_MASK | 0x0011UL)
#define STATUS_DEVICE_INTERRUPT_NOT_AVAILABLE           (FAIL_MASK | DEVICE_MASK | 0x0012UL)
#define STATUS_DEVICE_DMA_SPAN_CROSSES_BOUNDARY         (FAIL_MASK | DEVICE_MASK | 0x0013UL)
#define STATUS_DEVICE_DOES_NOT_EXIST_HINT               (WARNING_MASK | DEVICE_MASK | 0x0014UL)
#define STATUS_DEVICE_NOT_READY                         (FAIL_MASK | DEVICE_MASK | 0x0015UL)
#define STATUS_DEVICE_DISABLED                          (FAIL_MASK | DEVICE_MASK | 0x0016UL)
#define STATUS_DEVICE_NOT_CONNECTED                     (FAIL_MASK | DEVICE_MASK | 0x0017UL)
#define STATUS_DEVICE_INTERRUPT_NOT_CONFIGURED          (FAIL_MASK | DEVICE_MASK | 0x0018UL)
#define STATUS_DEVICE_CAPABILITIES_NOT_SUPPORTED        (FAIL_MASK | DEVICE_MASK | 0x0019UL)
#define STATUS_DEVICE_CAPABILITY_DOES_NOT_EXIST         (FAIL_MASK | DEVICE_MASK | 0x001AUL)
#define STATUS_DEVICE_INTERRUPT_TYPE_NOT_SUPPORTED      (FAIL_MASK | DEVICE_MASK | 0x001BUL)
#define STATUS_DEVICE_INTERRUPT_PRIORITY_NOT_AVAILABLE  (FAIL_MASK | DEVICE_MASK | 0x001CUL)
#define STATUS_DEVICE_SPACE_RANGE_EXCEEDED              (FAIL_MASK | DEVICE_MASK | 0x001DUL)
#define STATUS_DEVICE_TYPE_INVALID                      (FAIL_MASK | DEVICE_MASK | 0x001EUL)
#define STATUS_DEVICE_BUSY                              (FAIL_MASK | DEVICE_MASK | 0x001FUL)

// success status
#define STATUS_SUCCESS                                  0UL

// check if a status was successful
#define SUCCEEDED(x)                                    ( 0 == ( (x) & FAIL_MASK ) )

typedef _Return_type_success_(SUCCEEDED(return)) DWORD  STATUS;
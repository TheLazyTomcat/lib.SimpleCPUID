{-------------------------------------------------------------------------------

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.

-------------------------------------------------------------------------------}
{===============================================================================

  SimpleCPUID

    Small library designed to provide some basic parsed information (mainly CPU
    features) obtained by the CPUID instruction on x86(-64) processors.
    Should be compatible with any Windows and Unix system.

  ©František Milt 2016-12-16

  Version 0.9

  Dependencies:
    AuxTypes - github.com/ncs-sniper/Lib.AuxTypes
    BitOps   - github.com/ncs-sniper/Lib.BitOps

  Sources:
    https://en.wikipedia.org/wiki/CPUID
    http://sandpile.org/x86/cpuid.htm
    Intel® 64 and IA-32 Architectures Software Developer’s Manual (September 2016)
    AMD CPUID Specification; Publication #25481 Revision 2.34 (September 2010)

===============================================================================}
unit SimpleCPUID;

{$IF Defined(CPUX86_64) or Defined(CPUX64)}
  {$DEFINE x64}
{$ELSEIF Defined(CPU386)}
  {$DEFINE x86}
{$ELSE}
  {$MESSAGE FATAL 'Unsupported CPU.'}
{$IFEND}

{$IF Defined(WINDOWS) or Defined(MSWINDOWS))}
  {$DEFINE Windows}
{$ELSE}
  {$IFNDEF UNIX}
    {$MESSAGE FATAL 'Unsupported operating system.'}
  {$ENDIF}
{$IFEND}

{$IFDEF FPC}
  {$MODE Delphi}
  {$ASMMODE Intel}
{$ENDIF}

{$IFDEF PurePascal}
  {$MESSAGE WARN 'This unit cannot be compiled without ASM.'}
{$ENDIF}

{$message 'implement retrieval of all leafs/subleafs'}

interface

uses
  AuxTypes;

{==============================================================================}
{   Main CPUID routines                                                        }
{==============================================================================}

Function CPUIDSupported: LongBool; register; assembler;

procedure CPUID(Leaf, SubLeaf: UInt32; Result: Pointer); register; overload; assembler;
procedure CPUID(Leaf: UInt32; Result: Pointer); overload;

{==============================================================================}
{------------------------------------------------------------------------------}
{                                 TSimpleCPUID                                 }
{------------------------------------------------------------------------------}
{==============================================================================}

type
  TCPUIDResult = packed record
    EAX,EBX,ECX,EDX:  UInt32;
  end;
  PCPUIDResult = ^TCPUIDResult;

  TCPUIDLeaf = record
    ID:       UInt32;
    Data:     TCPUIDResult;
    SubLeafs: array of TCPUIDResult;
  end;
  PCPUIDLeaf = ^TCPUIDLeaf;

  TCPUIDLeafs = array of TCPUIDLeaf;

//--  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --

  TCPUIDManufacturerID = (mnOthers,mnAMD,mnCentaur,mnCyrix,mnIntel,mnTransmeta,
                          mnNationalSemiconductor,mnNexGen,mnRise,mnSiS,mnUMC,
                          mnVIA,mnVortex);

//--  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --

  TCPUIDInfo_AdditionalInfo = record
    BrandID:                Byte;
    CacheLineFlushSize:     Word; // In bytes (raw data is in qwords)
    LogicalProcessorCount:  Byte; // HTT (see features) must be on, otherwise reserved
    LocalAPICID:            Byte;
  end;

//--  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --

  TCPUIDInfo_Features = record
  {leaf 1, ECX register}
    SSE3,           // [00] SSE3 Extensions
    PCLMULQDQ,      // [01] Carryless Multiplication
    DTES64,         // [02] 64-bit Debug Store Area
    MONITOR,        // [03] MONITOR and MWAIT Instructions
    DS_CPL,         // [04] CPL Qualified Debug Store
    VMX,            // [05] Virtual Machine Extensions
    SMX,            // [06] Safer Mode Extensions
    EIST,           // [07] Enhanced Intel SpeedStep® Technology
    TM2,            // [08] Thermal Monitor 2
    SSSE3,          // [09] SSSE3 Extensions
    CNXT_ID,        // [10] L1 Context ID
    SDBG,           // [11]	Silicon Debug interface
    FMA,            // [12] Fused Multiply Add
    CMPXCHG16B,     // [13] CMPXCHG16B Instruction
    xTPR,           // [14] Update Control (Can disable sending task priority messages)
    PDCM,           // [15] Perform & Debug Capability MSR
    PCID,           // [17] Process-context Identifiers
    DCA,            // [18] Direct Cache Access
    SSE4_1,         // [19] SSE4.1 Instructions
    SSE4_2,         // [20] SSE4.2 Instructions
    x2APIC,         // [21] x2APIC Support
    MOVBE,          // [22] MOVBE Instruction
    POPCNT,         // [23] POPCNT Instruction
    TSC_Deadline,   // [24] APIC supports one-shot operation using a TSC deadline value
    AES,            // [25] AES Instruction Set
    XSAVE,          // [26] XSAVE, XRESTOR, XSETBV, XGETBV Instructions
    OSXSAVE,        // [27] XSAVE enabled by OS
    AVX,            // [28] Advanced Vector Extensions
    F16C,           // [29] F16C (half-precision) FP Support
    RDRAND,         // [30] RDRAND (on-chip random number generator) Support
    HYPERVISOR,     // [31] Running on a hypervisor (always 0 on a real CPU)
  {leaf 1, EDX register}
    FPU,            // [00] x87 FPU on Chip
    VME,            // [01] Virtual-8086 Mode Enhancement
    DE,             // [02] Debugging Extensions
    PSE,            // [03] Page Size Extensions
    TSC,            // [04] Time Stamp Counter
    MSR,            // [05] RDMSR and WRMSR Support
    PAE,            // [06] Physical Address Extensions
    MCE,            // [07] Machine Check Exception
    CX8,            // [08] CMPXCHG8B Instruction
    APIC,           // [09] APIC on Chip
    SEP,            // [11] SYSENTER and SYSEXIT Instructions
    MTRR,           // [12] Memory Type Range Registers
    PGE,            // [13] PTE Global Bit
    MCA,            // [14] Machine Check Architecture
    CMOV,           // [15] Conditional Move/Compare Instruction
    PAT,            // [16] Page Attribute Table
    PSE_36,         // [17] Page Size Extension
    PSN,            // [18] Processor Serial Number
    CLFSH,          // [19] CLFLUSH Instruction
    DS,             // [21] Debug Store
    ACPI,           // [22] Thermal Monitor and Clock Control
    MMX,            // [23] MMX Technology
    FXSR,           // [24] FXSAVE/FXRSTOR Instructions
    SSE,            // [25] SSE Extensions
    SSE2,           // [26] SSE2 Extensions
    SS,             // [27] Self Snoop
    HTT,            // [28] Multi-threading
    TM,             // [29] Thermal Monitor
    IA64,           // [30] IA64 processor emulating x86
    PBE,            // [31] Pending Break Enable
  {leaf 7:0, EBX register}
    FSGSBASE,       // [00] RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE Support
    TSC_ADJUST,     // [01] IA32_TSC_ADJUST MSR Support
    SGX,            // [02] Intel Software Guard Extensions (Intel SGX Extensions)
    BMI1,           // [03] Bit Manipulation Instruction Set 1
    HLE,            // [04] Transactional Synchronization Extensions
    AVX2,           // [05] Advanced Vector Extensions 2
    FPDP,           // [06] x87 FPU Data Pointer updated only on x87 exceptions
    SMEP,           // [07] Supervisor-Mode Execution Prevention
    BMI2,           // [08] Bit Manipulation Instruction Set 2
    ERMS,           // [09] Enhanced REP MOVSB/STOSB
    INVPCID,        // [10] INVPCID Instruction
    RTM,            // [11] Transactional Synchronization Extensions
    PQM,            // [12] Platform Quality of Service Monitoring
    FPCSDS,         // [13] FPU CS and FPU DS deprecated
    MPX,            // [14] Intel MPX (Memory Protection Extensions)
    PQE,            // [15] Platform Quality of Service Enforcement
    AVX512F,        // [16] AVX-512 Foundation
    AVX512DQ,       // [17] AVX-512 Doubleword and Quadword Instructions
    RDSEED,         // [18] RDSEED instruction
    ADX,            // [19] Intel ADX (Multi-Precision Add-Carry Instruction Extensions)
    SMAP,           // [20] Supervisor Mode Access Prevention
    AVX512IFMA,     // [21] AVX-512 Integer Fused Multiply-Add Instructions
    PCOMMIT,        // [22] PCOMMIT Instruction
    CLFLUSHOPT,     // [23] CLFLUSHOPT Instruction
    CLWB,           // [24] CLWB Instruction
    PT,             // [25] Intel Processor Trace
    AVX512PF,       // [26] AVX-512 Prefetch Instructions
    AVX512ER,       // [27] AVX-512 Exponential and Reciprocal Instructions
    AVX512CD,       // [28] AVX-512 Conflict Detection Instructions
    SHA,            // [29] Intel SHA extensions
    AVX512BW,       // [30] AVX-512 Byte and Word Instructions
    AVX512VL,       // [31] AVX-512 Vector Length Extensions
  {leaf 7:0, ECX register}
    PREFETCHWT1,    // [00] PREFETCHWT1 Instruction
    AVX512VBMI,     // [01] AVX-512 Vector Bit Manipulation Instructions
    UMIP,           // [02] User-mode Instruction Prevention
    PKU,            // [03] Memory Protection Keys for User-mode pages
    OSPKE,          // [04] PKU enabled by OS
    CET,            // [07] ??? (http://sandpile.org/x86/cpuid.htm)
    VA57:  Boolean; // [16] 5-level paging, CR4.VA57
    MAWAU: Byte;    // [17..21] The value of MAWAU (User MPX (Memory Protection Extensions) address-width adjust)
                    //          used by the BNDLDX and BNDSTX instructions in 64-bit mode.
    RDPID,          // [22] Read Processor ID
    SGX_LC,         // [30] SGX Launch Configuration
  {leaf 7:0, EDX register}
    AVX512QVNNIW,   // [02] AVX-512 Neural Network Instructions
    AVX512QFMA:     // [03] AVX-512 Multiply Accumulation Single precision
      Boolean;
  end;

//--  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --

  TCPUIDInfo_ExtendedFeatures = record
  {leaf $80000001, ECX register}
    AHF64,          // [00] LAHF/SAHF available in 64-bit mode
    CMP,            // [01] Hyperthreading not valid (HTT=1 indicates HTT(0) or CMP(1))
    SVM,            // [02] Secure Virtual Machine
    EAS,            // [03] Extended APIC space
    CR8D,           // [04] CR8 in 32-bit mode
    LZCNT,          // [05] Advanced bit manipulation (lzcnt and popcnt)
    ABM,            // [05] Equal to LZCNT
    SSE4A,          // [06] SSE4a Support
    MSSE,           // [07] Misaligned SSE mode
    _3DNowP,        // [08] PREFETCH and PREFETCHW Instructions
    OSVW,           // [09] OS Visible Workaround
    IBS,            // [10] Instruction Based Sampling
    XOP,            // [11] XOP instruction set
    SKINIT,         // [12] SKINIT/STGI instructions
    WDT,            // [13] Watchdog timer
    LWP,            // [15] Light Weight Profiling
    FMA4,           // [16] 4 operands fused multiply-add
    TCE,            // [17] Translation Cache Extension
    NODEID,         // [19] NodeID MSR
    TBM,            // [21] Trailing Bit Manipulation
    TOPX,           // [22] Topology Extensions
    PCX_CORE,       // [23] Core performance counter extensions
    PCX_NB,         // [24] NB performance counter extensions
    DBX,            // [26] Data breakpoint extensions
    PERFTSC,        // [27] Performance TSC
    PCX_L2I,        // [28] L2I performance counter extensions
    MON,            // [29] MONITORX/MWAITX Instructions
  {leaf $80000001, EDX register}
    FPU,            // [00] Onboard x87 FPU
    VME,            // [01] Virtual mode extensions (VIF)
    DE,             // [02] Debugging extensions (CR4 bit 3)
    PSE,            // [03] Page Size Extension
    TSC,            // [04] Time Stamp Counter
    MSR,            // [05] Model-specific registers
    PAE,            // [06] Physical Address Extension
    MCE,            // [07] Machine Check Exception
    CX8,            // [08] CMPXCHG8 (compare-and-swap) Instruction
   {
   	If the APIC has been disabled, then the APIC feature flag will read as 0.
   }
    APIC,           // [09] Onboard Advanced Programmable Interrupt Controller
   {
    The AMD K6 processor, model 6, uses bit 10 to indicate SEP. Beginning with
    model 7, bit 11 is used instead.
    Intel processors only report SEP when CPUID is executed in PM64.
   }    
    SEP,            // [11] SYSCALL and SYSRET Instructions
    MTRR,           // [12] Memory Type Range Registers
    PGE,            // [13] Page Global Enable bit in CR4
    MCA,            // [14] Machine check architecture
    CMOV,           // [15] Conditional move and FCMOV instructions
    PAT,            // [16] Page Attribute Table
  (*FCMOV,*)        // [16] ??? (http://sandpile.org/x86/cpuid.htm)
    PSE36,          // [17] 36-bit page size extension
  {
    AMD K7 processors prior to CPUID=0662h may report 0 even if they are MP-capable.
  }
    MP,             // [19] Multiprocessor Capable
    NX,             // [20] Execute Disable Bit available
    MMXExt,         // [22] Extended MMX (AMD specific, MMX-SSE and SSE-MEM)
    MMX,            // [23]	MMX Instructions
    FXSR,           // [24] FXSAVE, FXRSTOR instructions, CR4 bit 9
  (*MMXExt,*)       // [24] Extended MMX (Cyrix specific)
    FFXSR,          // [25] FXSAVE/FXRSTOR optimizations
    PG1G,           // [26] 1-GByte pages are available
    TSCP,           // [27] RDTSCP and IA32_TSC_AUX are available
    LM,             // [29] AMD64/EM64T, Long Mode
    _3DNowExt,      // [30] Extended 3DNow!
    _3DNow:         // [31] 3DNow!
      Boolean;
  end;

//--  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --  --

  TCPUIDInfo = record
    // leaf 0x00000000
    ManufacturerID:             TCPUIDManufacturerID;
    ManufacturerIDString:       String;
    // leaf 0x00000001
    ProcessorType:              Byte;
    ProcessorFamily:            Byte;
    ProcessorModel:             Byte;
    ProcessorStepping:          Byte;
    AdditionalInfo:             TCPUIDInfo_AdditionalInfo;
    // leaf 0x00000001 and 0x00000007
    ProcessorFeatures:          TCPUIDInfo_Features;
    // leaf 0x80000001
    ExtendedProcessorFeatures:  TCPUIDInfo_ExtendedFeatures;
    // leaf 0x80000002 - 0x80000004
    BrandString:                String;
  end;

{==============================================================================}
{   TSimpleCPUID - declaration                                                 }
{==============================================================================}

  TSimpleCPUID = class(TObject)
  private
    fSupported:  Boolean;
    fLeafs:      TCPUIDLeafs;
    fInfo:       TCPUIDInfo;
    Function GetLeafCount: Integer;
    Function GetLeaf(Index: Integer): TCPUIDLeaf;
  protected
    procedure InitStdLeafs; virtual;
    procedure ProcessLeaf_0000_0000; virtual;
    procedure ProcessLeaf_0000_0001; virtual;
    procedure ProcessLeaf_0000_0002; virtual;
    procedure ProcessLeaf_0000_0004; virtual;
    procedure ProcessLeaf_0000_0007; virtual;
    procedure InitExtLeafs; virtual;
    procedure ProcessLeaf_8000_0001; virtual;
    procedure ProcessLeaf_8000_0002_to_8000_0004; virtual;
  public
    constructor Create(Initialize: Boolean = True);
    destructor Destroy; override;
    procedure Initialize; virtual;
    procedure Finalize; virtual;
    Function IndexOf(LeafID: UInt32): Integer; virtual;
    property Info: TCPUIDInfo read fInfo;
    property Leafs[Index: Integer]: TCPUIDLeaf read GetLeaf; default;
  published
    property Supported: Boolean read fSupported;
    property Count: Integer read GetLeafCount;
  end;

{==============================================================================}
{------------------------------------------------------------------------------}
{                                TSimpleCPUIDEx                                }
{------------------------------------------------------------------------------}
{==============================================================================}

{==============================================================================}
{   TSimpleCPUIDEx - declaration                                               }
{==============================================================================}

  TSimpleCPUIDEx = class(TSimpleCPUID)
  private
    fProcessorID: Integer;
  protected
    class Function SetThreadAffinity(ProcessorMask: PtrUInt): PtrUInt; virtual;
  public
    class Function ProcessorAvailable(ProcessorID: Integer): Boolean; virtual;
    constructor Create(ProcessorID: Integer = 0; Initialize: Boolean = True);
    procedure Initialize; override;
  published
    property ProcessorID: Integer read fProcessorID write fProcessorID;
  end;

implementation

uses
  {$IFDEF Windows}Windows{$ELSE}unixtype, pthreads{$ENDIF}, SysUtils, BitOps;

{==============================================================================}
{   Auxiliary routines and declarations                                        }
{==============================================================================}

{$IFNDEF Windows}
Function pthread_getaffinity_np(thread: pthread_t; cpusetsize: size_t; cpuset: Pointer): LongInt; cdecl; external;
Function pthread_setaffinity_np(thread: pthread_t; cpusetsize: size_t; cpuset: Pointer): LongInt; cdecl; external;
Function sched_getaffinity(pid: pid_t; cpusetsize: size_t; mask: Pointer): LongInt; cdecl; external;
Function getpid: pid_t; cdecl; external;

//------------------------------------------------------------------------------

procedure RaiseError(ResultValue: Integer; FuncName: String);
begin
If ResultValue <> 0 then
  raise Exception.CreateFmt('%s failed with error %d.',[FuncName,ResultValue]);
end;
{$ENDIF}

{==============================================================================}
{   Main CPUID routines (ASM)                                                  }
{==============================================================================}

Function CPUIDSupported: LongBool;
const
  EFLAGS_BitMask_ID = UInt32($00200000);
asm
{- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  Result is returned in EAX register (all modes).

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -}
{$IFDEF x64}
  // save initial RFLAGS register value
  PUSHFQ

  // save RFLAGS register value again for further use
  PUSHFQ
  // invert ID bit in RFLAGS value stored on stack (bit #21)
  XOR   qword ptr [RSP],  EFLAGS_BitMask_ID
  // load RFLAGS register from stack (with inverted ID bit)
  POPFQ

  // save RFLAGS register to stack (if ID bit can be changed, it is saved
  // as inverted, otherwise it has its initial value)
  PUSHFQ
  // load saved RFLAGS value to EAX
  POP   RAX
  // get whichever bit has changed in comparison with initial RFLAGS value
  XOR   RAX, qword ptr [RSP]
  // check if ID bit has changed (if not => CPUID instruction not supported)
  AND   RAX, EFLAGS_BitMask_ID

  // restore initial RFLAGS value
  POPFQ
{$ELSE}
  // save initial EFLAGS register value
  PUSHFD

  // save EFLAGS register value again for further use
  PUSHFD
  // invert ID bit in EFLAGS value stored on stack (bit #21)
  XOR   dword ptr [ESP],  EFLAGS_BitMask_ID
  // load EFLAGS register from stack (with inverted ID bit)
  POPFD

  // save EFLAGS register to stack (if ID bit can be changed, it is saved
  // as inverted, otherwise it has its initial value)
  PUSHFD
  // load saved EFLAGS value to EAX
  POP   EAX
  // get whichever bit has changed in comparison with initial EFLAGS value
  XOR   EAX, dword ptr [ESP]
  // check if ID bit has changed (if not => CPUID instruction not supported)
  AND   EAX, EFLAGS_BitMask_ID

  // restore initial EFLAGS value
  POPFD
{$ENDIF}
end;

//------------------------------------------------------------------------------

procedure CPUID(Leaf, SubLeaf: UInt32; Result: Pointer);
asm
{$IFDEF x64}
{- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  Register content on enter:

  Win64  Lin64

   ECX    EDI   Leaf of the CPUID info (parameter for CPUID instruction)
   EDX    ESI   SubLeaf of the CPUID info (valid only for some leafs)   
    R8    RDX   Address of memory space (at least 16 bytes long) to which
                resulting data (registers EAX, EBX, ECX and EDX, in that order)
                will be copied

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -}

  // save non-volatile registers
  PUSH  RBX

{$IFDEF Windows}
  // Code for Windows 64bit

  // move leaf and subleaf id to a proper register
  MOV   EAX,  ECX
  MOV   ECX,  EDX

{$ELSE}
  // Code for Linux 64bit

  // copy address of memory storage, so it is available for further use
  MOV   R8,   RDX

  // move leaf and subleaf id to a proper register
  MOV   EAX,  EDI
  MOV   ECX,  ESI

{$ENDIF}

  // get the info
  CPUID

  // copy resulting registers to a provided memory
  MOV   [R8],       EAX
  MOV   [R8 + 4],   EBX
  MOV   [R8 + 8],   ECX
  MOV   [R8 + 12],  EDX

  // restore non-volatile registers
  POP   RBX
{$ELSE x64}
{- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  Win32, Lin32

  Register content on enter:

    EAX - Leaf of the CPUID info (parameter for CPUID instruction)
    EDX - SubLeaf of the CPUID info (valid only for some leafs)
    ECX - Address of memory space (at least 16 bytes long) to which resulting
          data (registers EAX, EBX, ECX and EDX, in that order) will be copied

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -}

  // save non-volatile registers
  PUSH  EDI
  PUSH  EBX

  // copy address of memory storage, so it is available for further use
  MOV   EDI,  ECX

  // move subleaf number to ECX register where it is expected
  MOV   ECX,  EDX

  // get the info (EAX register already contains the leaf number)
  CPUID

  // copy resulting registers to a provided memory
  MOV   [EDI],      EAX
  MOV   [EDI + 4],  EBX
  MOV   [EDI + 8],  ECX
  MOV   [EDI + 12], EDX

  // restore non-volatile registers
  POP   EBX
  POP   EDI
{$ENDIF x64}
end;

//   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---

procedure CPUID(Leaf: UInt32; Result: Pointer);
begin
CPUID(Leaf,0,Result);
end;

{==============================================================================}
{------------------------------------------------------------------------------}
{                                 TSimpleCPUID                                 }
{------------------------------------------------------------------------------}
{==============================================================================}

type
  TManufacturersItem = record
    IDStr:  String;
    ID:     TCPUIDManufacturerID;
  end;

const
  Manufacturers: array[0..13] of TManufacturersItem = (
    (IDStr: 'AMDisbetter!'; ID: mnAMD),
    (IDStr: 'AuthenticAMD'; ID: mnAMD),
    (IDStr: 'CentaurHauls'; ID: mnCentaur),
    (IDStr: 'CyrixInstead'; ID: mnCyrix),
    (IDStr: 'GenuineIntel'; ID: mnIntel),
    (IDStr: 'TransmetaCPU'; ID: mnTransmeta),
    (IDStr: 'GenuineTMx86'; ID: mnTransmeta),
    (IDStr: 'Geode by NSC'; ID: mnNationalSemiconductor),
    (IDStr: 'NexGenDriven'; ID: mnNexGen),
    (IDStr: 'RiseRiseRise'; ID: mnRise),
    (IDStr: 'SiS SiS SiS '; ID: mnSiS),
    (IDStr: 'UMC UMC UMC '; ID: mnUMC),
    (IDStr: 'VIA VIA VIA '; ID: mnVIA),
    (IDStr: 'Vortex86 SoC'; ID: mnVortex));

{==============================================================================}
{   TSimpleCPUID - implementation                                              }
{==============================================================================}

{------------------------------------------------------------------------------}
{   TSimpleCPUID - private methods                                             }
{------------------------------------------------------------------------------}

Function TSimpleCPUID.GetLeafCount: Integer;
begin
Result := Length(fLeafs);
end;

//------------------------------------------------------------------------------

Function TSimpleCPUID.GetLeaf(Index: Integer): TCPUIDLeaf;
begin
If (Index >= Low(fLeafs)) and (Index <= High(fLeafs)) then
  Result := fLeafs[Index]
else
  raise Exception.CreateFmt('TSimpleCPUID.GetLeaf: Index (%d) out of bounds.',[Index]);
end;

{------------------------------------------------------------------------------}
{   TSimpleCPUID - protected methods                                           }
{------------------------------------------------------------------------------}

procedure TSimpleCPUID.InitStdLeafs;
var
  Temp: TCPUIDResult;
  i:    Integer;
begin
// get leaf count
CPUID(0,Addr(Temp));
SetLength(fLeafs,Temp.EAX + 1);
// load all standard leafs
For i := Low(fLeafs) to High(fLeafs) do
  begin
    fLeafs[i].ID := UInt32(i);
    CPUID(fLeafs[i].ID,Addr(fLeafs[i].Data));
  end;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.ProcessLeaf_0000_0000;
var
  Index:  Integer;
  Str:    AnsiString;
  i:      Integer;
begin
Index := IndexOf($00000000);
If Index >= 0 then
  begin
    SetLength(Str,12);
    Move(fLeafs[Index].Data.EBX,Pointer(PAnsiChar(Str))^,4);
    Move(fLeafs[Index].Data.EDX,{%H-}Pointer({%H-}PtrUInt(PAnsiChar(Str)) + 4)^,4);
    Move(fLeafs[Index].Data.ECX,{%H-}Pointer({%H-}PtrUInt(PAnsiChar(Str)) + 8)^,4);
    fInfo.ManufacturerIDString := String(Str);
    fInfo.ManufacturerID := mnOthers;
    For i := Low(Manufacturers) to High(Manufacturers) do
      If AnsiSameStr(Manufacturers[i].IDStr,fInfo.ManufacturerIDString) then
        fInfo.ManufacturerID := Manufacturers[i].ID;
  end;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.ProcessLeaf_0000_0001;
var
  Index:  Integer;
begin
Index := IndexOf($00000001);
If Index >= 0 then
  begin
    // processor type
    fInfo.ProcessorType := GetBits(fLeafs[Index].Data.EAX,12,13);
    // processor family
    If GetBits(fLeafs[Index].Data.EAX,8,11) <> $F then
      fInfo.ProcessorFamily := GetBits(fLeafs[Index].Data.EAX,8,11)
    else
      fInfo.ProcessorFamily := GetBits(fLeafs[Index].Data.EAX,8,11) +
                                    GetBits(fLeafs[Index].Data.EAX,20,27);
    // processor model
    If GetBits(fLeafs[Index].Data.EAX,8,11) in [$6,$F] then
      fInfo.ProcessorModel := (GetBits(fLeafs[Index].Data.EAX,16,19) shr 4) or
                                    GetBits(fLeafs[Index].Data.EAX,4,7)
    else
      fInfo.ProcessorModel := GetBits(fLeafs[Index].Data.EAX,4,7);
    // processor stepping
    fInfo.ProcessorStepping := GetBits(fLeafs[Index].Data.EAX,0,3);
    // additional info
    fInfo.AdditionalInfo.BrandID               := GetBits(fLeafs[Index].Data.EBX,0,7);
    fInfo.AdditionalInfo.CacheLineFlushSize    := GetBits(fLeafs[Index].Data.EBX,8,15) * 8;
    fInfo.AdditionalInfo.LogicalProcessorCount := GetBits(fLeafs[Index].Data.EBX,16,23);
    fInfo.AdditionalInfo.LocalAPICID           := GetBits(fLeafs[Index].Data.EBX,24,31);
    // processor features
    with fInfo.ProcessorFeatures do
      begin
      {ECX register}
        SSE3         := BT(fLeafs[Index].Data.ECX,0);
        PCLMULQDQ    := BT(fLeafs[Index].Data.ECX,1);
        DTES64       := BT(fLeafs[Index].Data.ECX,2);
        MONITOR      := BT(fLeafs[Index].Data.ECX,3);
        DS_CPL       := BT(fLeafs[Index].Data.ECX,4);
        VMX          := BT(fLeafs[Index].Data.ECX,5);
        SMX          := BT(fLeafs[Index].Data.ECX,6);
        EIST         := BT(fLeafs[Index].Data.ECX,7);
        TM2          := BT(fLeafs[Index].Data.ECX,8);
        SSSE3        := BT(fLeafs[Index].Data.ECX,9);
        CNXT_ID      := BT(fLeafs[Index].Data.ECX,10);
        SDBG         := BT(fLeafs[Index].Data.ECX,11);
        FMA          := BT(fLeafs[Index].Data.ECX,12);
        CMPXCHG16B   := BT(fLeafs[Index].Data.ECX,13);
        xTPR         := BT(fLeafs[Index].Data.ECX,14);
        PDCM         := BT(fLeafs[Index].Data.ECX,15);
        PCID         := BT(fLeafs[Index].Data.ECX,17);
        DCA          := BT(fLeafs[Index].Data.ECX,18);
        SSE4_1       := BT(fLeafs[Index].Data.ECX,19);
        SSE4_2       := BT(fLeafs[Index].Data.ECX,20);
        x2APIC       := BT(fLeafs[Index].Data.ECX,21);
        MOVBE        := BT(fLeafs[Index].Data.ECX,22);
        POPCNT       := BT(fLeafs[Index].Data.ECX,23);
        TSC_Deadline := BT(fLeafs[Index].Data.ECX,24);
        AES          := BT(fLeafs[Index].Data.ECX,25);
        XSAVE        := BT(fLeafs[Index].Data.ECX,26);
        OSXSAVE      := BT(fLeafs[Index].Data.ECX,27);
        AVX          := BT(fLeafs[Index].Data.ECX,28);
        F16C         := BT(fLeafs[Index].Data.ECX,29);
        RDRAND       := BT(fLeafs[Index].Data.ECX,30);
        HYPERVISOR   := BT(fLeafs[Index].Data.ECX,31);
      {EDX register}
        FPU          := BT(fLeafs[Index].Data.EDX,0);
        VME          := BT(fLeafs[Index].Data.EDX,1);
        DE           := BT(fLeafs[Index].Data.EDX,2);
        PSE          := BT(fLeafs[Index].Data.EDX,3);
        TSC          := BT(fLeafs[Index].Data.EDX,4);
        MSR          := BT(fLeafs[Index].Data.EDX,5);
        PAE          := BT(fLeafs[Index].Data.EDX,6);
        MCE          := BT(fLeafs[Index].Data.EDX,7);
        CX8          := BT(fLeafs[Index].Data.EDX,8);
        APIC         := BT(fLeafs[Index].Data.EDX,9);
        SEP          := BT(fLeafs[Index].Data.EDX,11);
        MTRR         := BT(fLeafs[Index].Data.EDX,12);
        PGE          := BT(fLeafs[Index].Data.EDX,13);
        MCA          := BT(fLeafs[Index].Data.EDX,14);
        CMOV         := BT(fLeafs[Index].Data.EDX,15);
        PAT          := BT(fLeafs[Index].Data.EDX,16);
        PSE_36       := BT(fLeafs[Index].Data.EDX,17);
        PSN          := BT(fLeafs[Index].Data.EDX,18);
        CLFSH        := BT(fLeafs[Index].Data.EDX,19);
        DS           := BT(fLeafs[Index].Data.EDX,21);
        ACPI         := BT(fLeafs[Index].Data.EDX,22);
        MMX          := BT(fLeafs[Index].Data.EDX,23);
        FXSR         := BT(fLeafs[Index].Data.EDX,24);
        SSE          := BT(fLeafs[Index].Data.EDX,25);
        SSE2         := BT(fLeafs[Index].Data.EDX,26);
        SS           := BT(fLeafs[Index].Data.EDX,27);
        HTT          := BT(fLeafs[Index].Data.EDX,28);
        TM           := BT(fLeafs[Index].Data.EDX,29);
        IA64         := BT(fLeafs[Index].Data.EDX,30);
        PBE          := BT(fLeafs[Index].Data.EDX,31);
      end;
  end;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.ProcessLeaf_0000_0002;
var
  Index:  Integer;
  i:      Integer;
begin
// this whole function must be run on the same processor, otherwise results will be wrong
Index := IndexOf($00000002);
If Index >= 0 then
  If Byte(fLeafs[Index].Data.EAX) > 0 then
    begin
      SetLength(fLeafs[Index].SubLeafs,Byte(fLeafs[Index].Data.EAX));
      fLeafs[Index].SubLeafs[0] := fLeafs[Index].Data;
      For i := 1 to High(fLeafs[Index].SubLeafs) do
        CPUID(2,Addr(fLeafs[Index].SubLeafs[i]));
    end;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.ProcessLeaf_0000_0004;
var
  Index:  Integer;
  Temp:   TCPUIDResult;
begin
Index := IndexOf($00000004);
If Index >= 0 then
  begin
    Temp := fLeafs[Index].Data;
    while ((Temp.EAX and $1F) <> 0) and (Length(fLeafs[Index].SubLeafs) <= 128) do
      begin
        SetLength(fLeafs[Index].SubLeafs,Length(fLeafs[Index].SubLeafs) + 1);
        fLeafs[Index].SubLeafs[High(fLeafs[Index].SubLeafs)] := Temp;
        CPUID(4,Length(fLeafs[Index].SubLeafs),@Temp);
      end;
  end;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.ProcessLeaf_0000_0007;
var
  Index:  Integer;
  i:      Integer;
begin
Index := IndexOf($00000007);
If Index >= 0 then
  begin
    // get all subleafs
    SetLength(fLeafs[Index].SubLeafs,fLeafs[Index].Data.EAX + 1);
    For i := Low(fLeafs[Index].SubLeafs) to High(fLeafs[Index].SubLeafs) do
      CPUID(7,UInt32(i),Addr(fLeafs[Index].SubLeafs[i]));
    // processor features
    with fInfo.ProcessorFeatures do
      begin
      {EBX register}
        FSGSBASE     := BT(fLeafs[Index].Data.EBX,0);
        TSC_ADJUST   := BT(fLeafs[Index].Data.EBX,1);
        SGX          := BT(fLeafs[Index].Data.EBX,2);
        BMI1         := BT(fLeafs[Index].Data.EBX,3);
        HLE          := BT(fLeafs[Index].Data.EBX,4);
        AVX2         := BT(fLeafs[Index].Data.EBX,5);
        FPDP         := BT(fLeafs[Index].Data.EBX,6);
        SMEP         := BT(fLeafs[Index].Data.EBX,7);
        BMI2         := BT(fLeafs[Index].Data.EBX,8);
        ERMS         := BT(fLeafs[Index].Data.EBX,9);
        INVPCID      := BT(fLeafs[Index].Data.EBX,10);
        RTM          := BT(fLeafs[Index].Data.EBX,11);
        PQM          := BT(fLeafs[Index].Data.EBX,12);
        FPCSDS       := BT(fLeafs[Index].Data.EBX,13);
        MPX          := BT(fLeafs[Index].Data.EBX,14);
        PQE          := BT(fLeafs[Index].Data.EBX,15);
        AVX512F      := BT(fLeafs[Index].Data.EBX,16);
        AVX512DQ     := BT(fLeafs[Index].Data.EBX,17);
        RDSEED       := BT(fLeafs[Index].Data.EBX,18);
        ADX          := BT(fLeafs[Index].Data.EBX,19);
        SMAP         := BT(fLeafs[Index].Data.EBX,20);
        AVX512IFMA   := BT(fLeafs[Index].Data.EBX,21);
        PCOMMIT      := BT(fLeafs[Index].Data.EBX,22);
        CLFLUSHOPT   := BT(fLeafs[Index].Data.EBX,23);
        CLWB         := BT(fLeafs[Index].Data.EBX,24);
        PT           := BT(fLeafs[Index].Data.EBX,25);
        AVX512PF     := BT(fLeafs[Index].Data.EBX,26);
        AVX512ER     := BT(fLeafs[Index].Data.EBX,27);
        AVX512CD     := BT(fLeafs[Index].Data.EBX,28);
        SHA          := BT(fLeafs[Index].Data.EBX,29);
        AVX512BW     := BT(fLeafs[Index].Data.EBX,30);
        AVX512VL     := BT(fLeafs[Index].Data.EBX,31);
      {ECX register}
        PREFETCHWT1  := BT(fLeafs[Index].Data.ECX,0);
        AVX512VBMI   := BT(fLeafs[Index].Data.ECX,1);
        UMIP         := BT(fLeafs[Index].Data.ECX,2);
        PKU          := BT(fLeafs[Index].Data.ECX,3);
        OSPKE        := BT(fLeafs[Index].Data.ECX,4);
        CET          := BT(fLeafs[Index].Data.ECX,7);
        VA57         := BT(fLeafs[Index].Data.ECX,16);
        MAWAU        := Byte(GetBits(fLeafs[Index].Data.ECX,17,21));
        RDPID        := BT(fLeafs[Index].Data.ECX,22);
        SGX_LC       := BT(fLeafs[Index].Data.ECX,30);
      {EDX register}
        AVX512QVNNIW := BT(fLeafs[Index].Data.EDX,2);
        AVX512QFMA   := BT(fLeafs[Index].Data.EDX,3);
      end;
  end;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.InitExtLeafs;
var
  Temp: TCPUIDResult;
  Cnt:  Integer;
  i:    Integer;
begin
// get leaf count
CPUID($80000000,Addr(Temp));
If (Temp.EAX and $80000000) <> 0 then
  begin
    Cnt := Length(fLeafs);
    SetLength(fLeafs,Length(fLeafs) + Integer(Temp.EAX and not $80000000) + 1);
    // load all extended leafs
    For i := Cnt to High(fLeafs) do
      begin
        fLeafs[i].ID := UInt32(i - Cnt) or $80000000;
        CPUID(fLeafs[i].ID,Addr(fLeafs[i].Data));
      end;
  end;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.ProcessLeaf_8000_0001;
var
  Index:  Integer;
begin
Index := IndexOf($80000001);
If Index >= 0 then
  begin
    // extended processor features
    with fInfo.ExtendedProcessorFeatures do
      begin
      {ECX register}
        AHF64     := BT(fLeafs[Index].Data.ECX,0);
        CMP       := BT(fLeafs[Index].Data.ECX,1);
        SVM       := BT(fLeafs[Index].Data.ECX,2);
        EAS       := BT(fLeafs[Index].Data.ECX,3);
        CR8D      := BT(fLeafs[Index].Data.ECX,4);
        LZCNT     := BT(fLeafs[Index].Data.ECX,5);
        ABM       := BT(fLeafs[Index].Data.ECX,5);
        SSE4A     := BT(fLeafs[Index].Data.ECX,6);
        MSSE      := BT(fLeafs[Index].Data.ECX,7);
        _3DNowP   := BT(fLeafs[Index].Data.ECX,8);
        OSVW      := BT(fLeafs[Index].Data.ECX,9);
        IBS       := BT(fLeafs[Index].Data.ECX,10);
        XOP       := BT(fLeafs[Index].Data.ECX,11);
        SKINIT    := BT(fLeafs[Index].Data.ECX,12);
        WDT       := BT(fLeafs[Index].Data.ECX,13);
        LWP       := BT(fLeafs[Index].Data.ECX,15);
        FMA4      := BT(fLeafs[Index].Data.ECX,16);
        TCE       := BT(fLeafs[Index].Data.ECX,17);
        NODEID    := BT(fLeafs[Index].Data.ECX,19);
        TBM       := BT(fLeafs[Index].Data.ECX,21);
        TOPX      := BT(fLeafs[Index].Data.ECX,22);
        PCX_CORE  := BT(fLeafs[Index].Data.ECX,23);
        PCX_NB    := BT(fLeafs[Index].Data.ECX,24);
        DBX       := BT(fLeafs[Index].Data.ECX,26);
        PERFTSC   := BT(fLeafs[Index].Data.ECX,27);
        PCX_L2I   := BT(fLeafs[Index].Data.ECX,28);
        MON       := BT(fLeafs[Index].Data.ECX,29);
      {EDX register}
        FPU       := BT(fLeafs[Index].Data.EDX,0);
        VME       := BT(fLeafs[Index].Data.EDX,1);
        DE        := BT(fLeafs[Index].Data.EDX,2);
        PSE       := BT(fLeafs[Index].Data.EDX,3);
        TSC       := BT(fLeafs[Index].Data.EDX,4);
        MSR       := BT(fLeafs[Index].Data.EDX,5);
        PAE       := BT(fLeafs[Index].Data.EDX,6);
        MCE       := BT(fLeafs[Index].Data.EDX,7);
        CX8       := BT(fLeafs[Index].Data.EDX,8);
        APIC      := BT(fLeafs[Index].Data.EDX,9);
        SEP       := BT(fLeafs[Index].Data.EDX,11);
        MTRR      := BT(fLeafs[Index].Data.EDX,12);
        PGE       := BT(fLeafs[Index].Data.EDX,13);
        MCA       := BT(fLeafs[Index].Data.EDX,14);
        CMOV      := BT(fLeafs[Index].Data.EDX,15);
        PAT       := BT(fLeafs[Index].Data.EDX,16);
        PSE36     := BT(fLeafs[Index].Data.EDX,17);
        MP        := BT(fLeafs[Index].Data.EDX,19);
        NX        := BT(fLeafs[Index].Data.EDX,20);
        MMXExt    := BT(fLeafs[Index].Data.EDX,22);
        MMX       := BT(fLeafs[Index].Data.EDX,23);
        FXSR      := BT(fLeafs[Index].Data.EDX,24);
        FFXSR     := BT(fLeafs[Index].Data.EDX,25);
        PG1G      := BT(fLeafs[Index].Data.EDX,26);
        TSCP      := BT(fLeafs[Index].Data.EDX,27);
        LM        := BT(fLeafs[Index].Data.EDX,29);
        _3DNowExt := BT(fLeafs[Index].Data.EDX,30);
        _3DNow    := BT(fLeafs[Index].Data.EDX,31);
      end;
  end;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.ProcessLeaf_8000_0002_to_8000_0004;
var
  Str:    AnsiString;
  i:      Integer;
  Index:  Integer;
begin
// get brand string
SetLength(Str,48);
For i := 0 to 2 do
  begin
    Index := IndexOf($80000002 + UInt32(i));
    If Index >= 0 then
      begin
        Move(fLeafs[Index].Data.EAX,{%H-}Pointer({%H-}PtrUInt(PAnsiChar(Str)) + PtrUInt(i * 16))^,4);
        Move(fLeafs[Index].Data.EBX,{%H-}Pointer({%H-}PtrUInt(PAnsiChar(Str)) + PtrUInt(i * 16) + 4)^,4);
        Move(fLeafs[Index].Data.ECX,{%H-}Pointer({%H-}PtrUInt(PAnsiChar(Str)) + PtrUInt(i * 16) + 8)^,4);
        Move(fLeafs[Index].Data.EDX,{%H-}Pointer({%H-}PtrUInt(PAnsiChar(Str)) + PtrUInt(i * 16) + 12)^,4);
      end
    else
      begin
        fInfo.BrandString := '';
        Exit;
      end;
  end;
SetLength(Str,StrLen(PAnsiChar(Str)));
fInfo.BrandString := Trim(String(Str));
end;

{------------------------------------------------------------------------------}
{   TSimpleCPUID - public methods                                              }
{------------------------------------------------------------------------------}

constructor TSimpleCPUID.Create(Initialize: Boolean = True);
begin
inherited Create;
If Initialize then Self.Initialize;
end;

//------------------------------------------------------------------------------

destructor TSimpleCPUID.Destroy;
begin
Finalize;
inherited;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.Initialize;
begin
SetLength(fLeafs,0);
fSupported := SimpleCPUID.CPUIDSupported;
If fSupported then
  begin
    InitStdLeafs;
    ProcessLeaf_0000_0000;
    ProcessLeaf_0000_0001;
    ProcessLeaf_0000_0002;
    ProcessLeaf_0000_0004;
    ProcessLeaf_0000_0007;
    InitExtLeafs;
    ProcessLeaf_8000_0001;
    ProcessLeaf_8000_0002_to_8000_0004;
  end;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUID.Finalize;
begin
SetLength(fLeafs,0);
end;

//------------------------------------------------------------------------------

Function TSimpleCPUID.IndexOf(LeafID: UInt32): Integer;
var
  i:  Integer;
begin
Result := -1;
For i := Low(fLeafs) to High(fLeafs) do
  If fLeafs[i].ID = LeafID then
    begin
      Result := i;
      Break;
    end;
end;


{==============================================================================}
{------------------------------------------------------------------------------}
{                                TSimpleCPUIDEx                                }
{------------------------------------------------------------------------------}
{==============================================================================}

{==============================================================================}
{   TSimpleCPUIDEx - implementation                                            }
{==============================================================================}

{------------------------------------------------------------------------------}
{   TSimpleCPUIDEx - protected methods                                         }
{------------------------------------------------------------------------------}

class Function TSimpleCPUIDEx.SetThreadAffinity(ProcessorMask: PtrUInt): PtrUInt;
begin
{$IFDEF Windows}
Result := SetThreadAffinityMask(GetCurrentThread,ProcessorMask);
{$ELSE}
RaiseError(pthread_getaffinity_np(pthread_self,SizeOf(Result),@Result),'pthread_getaffinity_np');
RaiseError(pthread_setaffinity_np(pthread_self,SizeOf(ProcessorMask),@ProcessorMask),'pthread_setaffinity_np');
{$ENDIF}
end;

{------------------------------------------------------------------------------}
{   TSimpleCPUIDEx - public methods                                            }
{------------------------------------------------------------------------------}

class Function TSimpleCPUIDEx.ProcessorAvailable(ProcessorID: Integer): Boolean;
var
  ProcessAffinityMask:  PtrUInt;
{$IFDEF Windows}
  SystemAffinityMask:   PtrUInt;
begin
If (ProcessorID >= 0) and (ProcessorID < (SizeOf(PtrUInt) * 8)) then
  begin
    If GetProcessAffinityMask(GetCurrentProcess,{%H-}ProcessAffinityMask,{%H-}SystemAffinityMask) then
      Result := BT(ProcessAffinityMask,ProcessorID)
    else
      raise Exception.CreateFmt('GetProcessAffinityMask failed with error 0x%.8x.',[GetLastError]);
  end
else Result := False;
end;
{$ELSE}
begin
If (ProcessorID >= 0) and (ProcessorID < (SizeOf(PtrUInt) * 8)) then
  begin
    RaiseError(sched_getaffinity(getpid,SizeOf(ProcessAffinityMask),@ProcessAffinityMask),'sched_getaffinity');
    Result := BT(ProcessAffinityMask,ProcessorID);
  end
else Result := False;
end;
{$ENDIF}

//------------------------------------------------------------------------------

constructor TSimpleCPUIDEx.Create(ProcessorID: Integer = 0; Initialize: Boolean = True);
begin
inherited Create(False);
fProcessorID := ProcessorID;
If Initialize then Self.Initialize;
end;

//------------------------------------------------------------------------------

procedure TSimpleCPUIDEx.Initialize;
var
  ProcessorMask:  PtrUInt;
begin
If ProcessorAvailable(fProcessorID) then
  begin
    ProcessorMask := 0;
    BitSetTo(ProcessorMask,fProcessorID,True);
    ProcessorMask := SetThreadAffinity(ProcessorMask);
    try
      inherited Initialize;
    finally
      SetThreadAffinity(ProcessorMask);
    end;
  end
else raise Exception.CreateFmt('TSimpleCPUIDEx.Initialize: Logical processor #%d not available.',[fProcessorID]);
end;

end.


#include "Funcs.hpp"

UNICODE_STRING DriverName;
UNICODE_STRING SymbolicLinkName;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

#define read_ctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x5734, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define base_addy_ctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x5735, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define cr3_van_ctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x5736, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)




NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status = {};
    ULONG BytesReturned = {};
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    ULONG IoControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG InputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;

    if (IoControlCode == read_ctl) {
        if (InputBufferLength == sizeof(_r)) {
            pr Request = (pr)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleReadRequest(Request);
            BytesReturned = sizeof(_r);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
            BytesReturned = 0;
        }
    }
    else if (IoControlCode == base_addy_ctl) {
        if (InputBufferLength == sizeof(_b)) {
            pb Request = (pb)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleBaseAddressRequest(Request);
            BytesReturned = sizeof(_b);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
            BytesReturned = 0;
        }
    }

    else if (IoControlCode == cr3_van_ctl) {
        if (InputBufferLength == sizeof(_gr)) {
            pgr Request = (pgr)(Irp->AssociatedIrp.SystemBuffer);
            Status = find_pml4_base(Request);
            BytesReturned = sizeof(_gr);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
            BytesReturned = 0;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Irp->IoStatus.Status;
}

NTSTATUS DispatchHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;
    default:
        break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    NTSTATUS Status = {};

    Status = IoDeleteSymbolicLink(&SymbolicLinkName);

    if (!NT_SUCCESS(Status))
        return;

    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS InitializeDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;

    RtlInitUnicodeString(&DriverName, L"\\Device\\SLIGHTSPASTED");
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\SLIGHTSPASTED");

    Status = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymbolicLinkName, &DriverName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = &UnsupportedDispatch;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = &DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControlHandler;
    DriverObject->DriverUnload = &UnloadDriver;

    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return IoCreateDriver(NULL, &InitializeDriver);
}
/** @file
  This is DCS platform information application

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 
Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Guid/GlobalVariable.h>
#include <Library/PasswordLib.h>
#include <Library/GraphLib.h>
#include <DcsConfig.h>

#ifdef _M_X64
#define ARCH_NAME "X64"
#else
#define ARCH_NAME "IA32"
#endif
CHAR8 Temp[1024];
CHAR8 StrBuffer[1024];
UINTN gXmlTabs = 0;

UINTN
XmlOutTab() {
	UINTN len;
	UINTN i = gXmlTabs;
	CHAR8*   pos = (CHAR8*)StrBuffer;
	INTN     remains = sizeof(StrBuffer) - 1;
	while (i > 0 && remains > 0) {
		*pos = ' ';
		remains--;
		i--;
		pos++;
	}
	len = sizeof(StrBuffer) - remains - 1;
	return len;
}

UINTN
XmlTag(
	IN EFI_FILE            *infoFileTxt,
	IN CONST CHAR8         *tag,
	IN BOOLEAN             closeTag,
	IN CONST CHAR8         *value,
	...
	) {
	VA_LIST  args;
	UINTN    len = XmlOutTab();
	CHAR8*   pos = (CHAR8*)StrBuffer + len;
	CHAR8*   attrFormat = NULL;
	INTN     remains = sizeof(StrBuffer) - 1 - len;
	if (infoFileTxt == NULL) return 0;
	VA_START(args, value);
	len = AsciiSPrint(pos, remains, "<%a", tag);
	remains -= len;
	pos += len;
	if ((attrFormat = VA_ARG(args, CHAR8 *)) != NULL) {
		len = AsciiVSPrint(pos, remains, attrFormat, args);
		remains -= len;
		pos += len;
	}
	VA_END(args);
	if (closeTag) {
		if (value == NULL) {
			len = AsciiSPrint(pos, remains, "/>\n");
			remains -= len;
			pos += len;
		}
		else {
			len = AsciiSPrint(pos, remains, ">%a</%a>\n", value, tag);
			remains -= len;
			pos += len;
		}
	}	else {
		if (value == NULL) {
			len = AsciiSPrint(pos, remains, ">");
			remains -= len;
			pos += len;
		}
		else {
			len = AsciiSPrint(pos, remains, ">%a", value, tag);
			remains -= len;
			pos += len;
		}
	}
	len = sizeof(StrBuffer) - remains - 1;
	infoFileTxt->Write(infoFileTxt, &len, StrBuffer);
	return len;
}

UINTN
XmlStartTag(
	IN EFI_FILE            *infoFileTxt,
	IN CONST CHAR8         *tag) 
{
	UINTN    len = XmlOutTab();
	CHAR8*   pos = (CHAR8*)StrBuffer + len;
	INTN     remains = sizeof(StrBuffer) - 1 - len;
	gXmlTabs += remains > 0 ? 1 : 0;
	len = AsciiSPrint(pos, remains, "<%a>\n", tag);
	remains -= len;
	pos += len;
	len = sizeof(StrBuffer) - remains - 1;
	infoFileTxt->Write(infoFileTxt, &len, StrBuffer);

	return len;
}

UINTN
XmlEndTag(
	IN EFI_FILE            *infoFileTxt,
	IN CONST CHAR8         *tag
	)
{
	UINTN    len;
	CHAR8*   pos;
	INTN     remains;
	gXmlTabs -= gXmlTabs > 0 ? 1 : 0;
	len = XmlOutTab();
	pos = (CHAR8*)StrBuffer + len;
	remains = sizeof(StrBuffer) - 1 - len;

	if (infoFileTxt == NULL) return 0;
	len = AsciiSPrint(pos, remains, "</%a>\n", tag);
	remains -= len;
	pos += len;
	len = sizeof(StrBuffer) - remains - 1;
	infoFileTxt->Write(infoFileTxt, &len, StrBuffer);
	return len;
}


UINTN
XmlEndTagPrint(
	IN EFI_FILE            *infoFileTxt,
	IN CONST CHAR8         *tag,
	IN CONST CHAR8         *formatValue,
	...
	)
{
	VA_LIST  args;
	UINTN    len = 0;
	CHAR8*   pos = (CHAR8*)StrBuffer + len;
	INTN     remains = sizeof(StrBuffer) - 1 - len;
	if (infoFileTxt == NULL) return 0;
	VA_START(args, formatValue);
	if (formatValue != NULL) {
		len = AsciiVSPrint(pos, remains, formatValue, args);
		remains -= len;
		pos += len;
	}
	VA_END(args);
	len = AsciiSPrint(pos, remains, "</%a>\n", tag);
	remains -= len;
	pos += len;
	len = sizeof(StrBuffer) - remains -1;
	infoFileTxt->Write(infoFileTxt, &len, StrBuffer);
	return len;
}

EFI_FILE            *fInfo;

VOID
InfoEFI() {
	XmlStartTag(fInfo, "EFI");
	XmlTag(fInfo, "Version", FALSE, NULL, NULL);
	XmlEndTagPrint(fInfo, "Version", "%d.%d", gST->Hdr.Revision >> 16, gST->Hdr.Revision & 0xFFFF);
	XmlTag(fInfo, "Vendor", FALSE, NULL, NULL);
	XmlEndTagPrint(fInfo, "Vendor", "%s", gST->FirmwareVendor);
	XmlTag(fInfo, "Revision", FALSE, NULL, NULL);
	XmlEndTagPrint(fInfo, "Revision", "0x0%x", gST->FirmwareRevision);
	XmlTag(fInfo, "Architecture", TRUE, ARCH_NAME, NULL);
	XmlEndTag(fInfo, "EFI");
}

VOID
InfoSystem() {
	EFI_STATUS res;
	res = SMBIOSGetSerials();
	if (!EFI_ERROR(res)) {
		//		XmlTag(info, "System",FALSE, NULL, NULL);
		XmlStartTag(fInfo, "System");
		XmlTag(fInfo, "Manufacture", TRUE, gSmbSystemManufacture, NULL);
		XmlTag(fInfo, "Model", TRUE, gSmbSystemModel, NULL);
		XmlTag(fInfo, "Version", TRUE, gSmbSystemVersion, NULL);
		XmlEndTag(fInfo, "System");
		XmlStartTag(fInfo, "BIOS");
		XmlTag(fInfo, "Vendor", TRUE, gSmbBiosVendor, NULL);
		XmlTag(fInfo, "Version", TRUE, gSmbBiosVersion, NULL);
		XmlTag(fInfo, "Date", TRUE, gSmbBiosDate, NULL);
		XmlEndTag(fInfo, "BIOS");
	}
}

VOID
InfoTcg() {
	InitTcg();
	XmlTag(fInfo, "TPM12", TRUE, NULL, " count=\"%d\"", gTcgCount, NULL);
	XmlTag(fInfo, "TPM20", TRUE, NULL, " count=\"%d\"", gTcg2Count, NULL);
}

VOID
InfoBlockDevices() {
    UINTN i;
    XmlTag(fInfo, "BlockDevices", FALSE, NULL, " count=\"%d\"", gBIOCount, NULL);
    FileAsciiPrint(fInfo, "\n");
    gXmlTabs++;
    for (i = 0; i < gBIOCount; ++i) {
        EFI_BLOCK_IO_PROTOCOL *bio;
        bio = EfiGetBlockIO(gBIOHandles[i]);
        if (bio != NULL && bio->Media != NULL) {
            XmlTag(fInfo, "BlockDevice", TRUE, NULL,
                " index=\"%d\" logical=\"%d\" block_size=\"%d\" revision=\"%llx\" read_only=\"%d\" last_block=\"%lld\"", i,
                bio->Media->LogicalPartition, bio->Media->BlockSize, bio->Revision,
                bio->Media->ReadOnly,
                bio->Media->LastBlock, NULL);
        }
    }
    XmlEndTag(fInfo, "BlockDevices");
}

VOID
InfoUsbDevices() {
	InitUsb();
	XmlTag(fInfo, "UsbDevices", TRUE, NULL, " count=\"%d\"", gUSBCount, NULL);
}

VOID
InfoTouch() {
	EFI_STATUS res;
	UINTN i;
	InitTouch();
	XmlTag(fInfo, "TouchDevices", FALSE, NULL, " count=\"%d\"", gTouchCount, NULL);
	FileAsciiPrint(fInfo, "\n");
	gXmlTabs++;
	for (i = 0; i < gTouchCount; ++i) {
		EFI_ABSOLUTE_POINTER_PROTOCOL *aio;
		res = TouchGetIO(gTouchHandles[i], &aio);
		if (!EFI_ERROR(res)) {
			XmlTag(fInfo, "TouchDevice", TRUE, NULL,
				" index=\"%d\" minx=\"%d\" miny=\"%d\" minz=\"%d\" maxx=\"%d\" maxy=\"%d\" maxz=\"%d\" attr=\"0x0%x\"", i,
				aio->Mode->AbsoluteMinX, aio->Mode->AbsoluteMinY, aio->Mode->AbsoluteMinZ,
				aio->Mode->AbsoluteMaxX, aio->Mode->AbsoluteMaxY, aio->Mode->AbsoluteMaxZ,
				aio->Mode->Attributes, NULL);
		}
	}
	XmlEndTag(fInfo, "TouchDevices");
}

VOID
InfoGraph() {
	EFI_STATUS res;
	UINTN i, j;
	InitGraph();
	XmlTag(fInfo, "GraphDevices", FALSE, NULL, " count=\"%d\"", gGraphCount, NULL);
	FileAsciiPrint(fInfo, "\n");
	gXmlTabs++;
	for (i = 0; i < gGraphCount; ++i) {
		EFI_GRAPHICS_OUTPUT_PROTOCOL *gio;
		res = GraphGetIO(gGraphHandles[i], &gio);
		if (!EFI_ERROR(res)) {
			XmlTag(fInfo, "GraphDevice", FALSE, NULL,
				" index=\"%d\" modes=\"%d\" H=\"%d\" V=\"%d\"", i,
				gio->Mode->MaxMode, gio->Mode->Info->HorizontalResolution, gio->Mode->Info->VerticalResolution,
				NULL);
			FileAsciiPrint(fInfo, "\n");
			gXmlTabs++;
			for (j = 0; j < gio->Mode->MaxMode; ++j) {
				EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode;
				UINTN sz = sizeof(mode);
				res = gio->QueryMode(gio, (UINT32)j, &sz, &mode);
				if (!EFI_ERROR(res)) {
					XmlTag(fInfo, "GraphMode", TRUE, NULL,
						" index=\"%d\" H=\"%d\" V=\"%d\"", j,
						mode->HorizontalResolution, mode->VerticalResolution,
						NULL);
				}
			}
			XmlEndTag(fInfo, "GraphDevice");
		}
	}
	XmlEndTag(fInfo, "GraphDevices");
}

VOID
InfoBluetooth() {
	InitBluetooth();
	XmlTag(fInfo, "BluetoothIo", TRUE, NULL, " count=\"%d\"", gBluetoothIoCount, NULL);
	XmlTag(fInfo, "BluetoothConfig", TRUE, NULL, " count=\"%d\"", gBluetoothConfigCount, NULL);
	XmlTag(fInfo, "BluetoothHC", TRUE, NULL, " count=\"%d\"", gBluetoothHcCount, NULL);
}

VOID
InfoCon() {
	EFI_STATUS res;
	UINTN i;
	UINTN cols;
	UINTN rows;
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conOut = gST->ConOut;
	if (conOut == NULL) {
		XmlTag(fInfo, "Console", TRUE, NULL, " available=\"0\"", NULL);
		return;
	}
	XmlTag(fInfo, "Console", FALSE, NULL, " modes=\"%d\" current=\"%d\"", conOut->Mode->MaxMode, conOut->Mode->Mode, NULL);
	FileAsciiPrint(fInfo, "\n");
	gXmlTabs++;
	for (i = 0; i < (UINTN)conOut->Mode->MaxMode; ++i) {
		res = conOut->QueryMode(conOut, i, &cols, &rows);
		if (!EFI_ERROR(res)) {
			XmlTag(fInfo, "TextMode", TRUE, NULL,
				" index=\"%d\" cols=\"%d\" rows=\"%d\"", i, cols, rows, NULL);
		}
	}
	XmlEndTag(fInfo, "Console");
}

/**
The actual entry point for the application.

@param[in] ImageHandle    The firmware allocated handle for the EFI image.
@param[in] SystemTable    A pointer to the EFI System Table.

@retval EFI_SUCCESS       The entry point executed successfully.
@retval other             Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
DcsInfoMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
   EFI_STATUS          res;
//	EFI_INPUT_KEY       key;
	InitBio();
   res = InitFS();
   if (EFI_ERROR(res)) {
      ERR_PRINT(L"InitFS %r\n", res);
		return res;
   }
	res = FileOpen(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\PlatformInfo", &fInfo, EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE, 0);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"PlatformInfo create %r\n", res);
		return res;
	}
	FileAsciiPrint(fInfo, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
	XmlStartTag(fInfo, "PlatformInfo");
	// General info
	InfoEFI();
	InfoSystem();

	// Devices info
	InfoTcg();
	InfoBlockDevices();
	InfoUsbDevices();
	InfoTouch();
	InfoGraph();
	InfoCon();
	InfoBluetooth();
	XmlEndTag(fInfo, "PlatformInfo");

	FileClose(fInfo);
	return EFI_SUCCESS;
}

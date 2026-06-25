/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2008 
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <ntifs.h>
#include <stdio.h>
#include <stdarg.h>
#include "defines.h"
#include "debug.h"
#include "inbv.h"
#include "misc.h"

#ifdef DBG_COM
#define   DEFAULT_BAUD_RATE    115200
#define   SER_RBR(x)   ((x)+0)
#define   SER_THR(x)   ((x)+0)
#define   SER_DLL(x)   ((x)+0)
#define   SER_IER(x)   ((x)+1)
#define   SER_DLM(x)   ((x)+1)
#define   SER_IIR(x)   ((x)+2)
#define   SER_LCR(x)   ((x)+3)
#define   SR_LCR_CS5 0x00
#define   SR_LCR_CS6 0x01
#define   SR_LCR_CS7 0x02
#define   SR_LCR_CS8 0x03
#define   SR_LCR_ST1 0x00
#define   SR_LCR_ST2 0x04
#define   SR_LCR_PNO 0x00
#define   SR_LCR_POD 0x08
#define   SR_LCR_PEV 0x18
#define   SR_LCR_PMK 0x28
#define   SR_LCR_PSP 0x38
#define   SR_LCR_BRK 0x40
#define   SR_LCR_DLAB 0x80
#define   SER_MCR(x)   ((x)+4)
#define   SR_MCR_DTR 0x01
#define   SR_MCR_RTS 0x02
#define   SER_LSR(x)   ((x)+5)
#define   SR_LSR_DR  0x01
#define   SR_LSR_TBE 0x20
#define   SER_MSR(x)   ((x)+6)
#define   SR_MSR_CTS 0x10
#define   SR_MSR_DSR 0x20
#define   SER_SCR(x)   ((x)+7)
#define   COM_BASE (0x3F8)
#endif

#ifdef DBG_COM
void com_putchar(char ch) 
{
	if (ch == '\n') {
		com_putchar('\r');
	}

	while ((READ_PORT_UCHAR (pv(SER_LSR(COM_BASE))) & SR_LSR_TBE) == 0);

	WRITE_PORT_UCHAR(pv(SER_THR(COM_BASE)), ch);
}

void com_print(char *format, ...)
{
	char    dbg_msg[MAX_PATH];
	char   *msg = dbg_msg;
	va_list args;

	va_start(args, format);

	_vsnprintf_s(
		dbg_msg, sizeof(dbg_msg), _TRUNCATE, format, args);

	va_end(args);

	while (*msg) {
		com_putchar(*msg++);
	}
}
#endif /* DBG_COM */

#ifdef DBG_HAL_DISPLAY

void hal_print(char *format, ...)
{
	char    dbg_msg[MAX_PATH];
	va_list args;

	va_start(args, format);

	_vsnprintf(
		dbg_msg, sizeof(dbg_msg), format, args);

	va_end(args);

	InbvDisplayString(dbg_msg);

	if (KeGetCurrentIrql() < DISPATCH_LEVEL) {
		dc_delay(500);
	}
}

#endif /* DBG_HAL_DISPLAY */

void dc_dbg_init()
{
#ifdef DBG_COM
	u32 divisor;
	u8  lcr;
	/* set baud rate and data format (8N1) */
	/*  turn on DTR and RTS  */
    WRITE_PORT_UCHAR(pv(SER_MCR(COM_BASE)), SR_MCR_DTR | SR_MCR_RTS);

	/* set DLAB */
    lcr = READ_PORT_UCHAR(pv(SER_LCR(COM_BASE))) | SR_LCR_DLAB;
    WRITE_PORT_UCHAR(pv(SER_LCR(COM_BASE)), lcr);

	/* set baud rate */
    divisor = 115200 / DEFAULT_BAUD_RATE;
    WRITE_PORT_UCHAR(pv(SER_DLL(COM_BASE)), divisor & 0xff);
    WRITE_PORT_UCHAR(pv(SER_DLM(COM_BASE)), (divisor >> 8) & 0xff);

	/* reset DLAB and set 8N1 format */
    WRITE_PORT_UCHAR(pv(SER_LCR(COM_BASE)), 
		SR_LCR_CS8 | SR_LCR_ST1 | SR_LCR_PNO);

	/* read junk out of the RBR */
	READ_PORT_UCHAR(pv(SER_RBR(COM_BASE)));
#endif /* DBG_COM */

#ifdef DBG_HAL_DISPLAY
	InbvAcquireDisplayOwnership();
	InbvEnableDisplayString(TRUE);
#endif /* DBG_HAL_DISPLAY */
}


void DumpHex(const char* prefix, const void* data, size_t size)
{
	const unsigned char* bytes = (const unsigned char*)data;

	for (size_t i = 0; i < size; i += 32)
	{
		char line[256];
		int offset = 0;

		if (prefix)
			offset += sprintf_s(line + offset, countof(line) - offset, "%s", prefix);

		offset += sprintf_s(line + offset, countof(line) - offset, "%04X: ", (unsigned int)i);

		for (size_t j = 0; j < 32; ++j)
		{
			if (i + j < size)
				offset += sprintf_s(line + offset, countof(line) - offset, "%02X ", bytes[i + j]);
			else
				offset += sprintf_s(line + offset, countof(line) - offset, "   ");
		}

		offset += sprintf_s(line + offset, countof(line) - offset, " |");

		for (size_t j = 0; j < 32; ++j)
		{
			if (i + j < size)
			{
				unsigned char c = bytes[i + j];
				offset += sprintf_s(line + offset, countof(line) - offset, "%c", (c >= 32 && c <= 126) ? c : '.');
			}
			else
				offset += sprintf_s(line + offset, countof(line) - offset, " ");
		}

		offset += sprintf_s(line + offset, countof(line) - offset, "|");

		DbgMsg("%s\n", line);
	}
}
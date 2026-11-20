/** @file
Graph library

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/GraphicsOutput.h>

EFI_HANDLE* gGraphHandles = NULL;
UINTN       gGraphCount = 0;

EFI_GRAPHICS_OUTPUT_PROTOCOL*	gGraphOut = NULL;

EFI_STATUS
InitGraph() {
	EFI_STATUS res;
	res = EfiGetHandles(ByProtocol, &gEfiGraphicsOutputProtocolGuid, 0, &gGraphHandles, &gGraphCount);
	if (gGraphCount > 0) {
		GraphGetIO(gGraphHandles[gGraphCount - 1], &gGraphOut);
	}
	return res;
}

EFI_STATUS
GraphGetIO(
	IN    EFI_HANDLE								Handle,
	OUT   EFI_GRAPHICS_OUTPUT_PROTOCOL**	io
	) {
	if (!io) {
		return EFI_INVALID_PARAMETER;
	}
	return gBS->HandleProtocol(Handle, &gEfiGraphicsOutputProtocolGuid, (VOID**)io);
}

EFI_STATUS
GraphGetModeInfo(
	IN    UINTN mode,
	OUT   EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **info,
	OUT	UINTN* szInfo
	) {
	if (!info || !gGraphOut || mode > gGraphOut->Mode->MaxMode) {
		return EFI_INVALID_PARAMETER;
	}
	return gGraphOut->QueryMode(gGraphOut, (UINT32)mode, szInfo, info);
}


//////////////////////////////////////////////////////////////////////////
// Screen
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
ScreenGetSize(
	OUT UINTN     *Height,
	OUT UINTN     *Width
	)
{
	if (gGraphOut == NULL) return EFI_INVALID_PARAMETER;
	*Height = gGraphOut->Mode->Info->VerticalResolution;
	*Width = gGraphOut->Mode->Info->HorizontalResolution;
	return EFI_SUCCESS;
}

EFI_STATUS ScreenFillRect(
	IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color,
	IN UINTN                         x,
	IN UINTN                         y,
	IN UINTN                         width,
	IN UINTN                         height
	)
{
	if (gGraphOut == NULL) return EFI_INVALID_PARAMETER;

	return gGraphOut->Blt(gGraphOut, color, EfiBltVideoFill, 0, 0, x, y, width, height, width * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
}

EFI_STATUS ScreenDrawBlt(
	IN BLT_HEADER *blt,
	IN UINTN   x,
	IN UINTN   y
	)
{
	if (gGraphOut == NULL || blt == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	return gGraphOut->Blt(gGraphOut, blt->Pixels, EfiBltBufferToVideo, 0, 0, x, y, blt->Width, blt->Height, blt->Width * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
}

EFI_STATUS ScreenUpdateDirty(
	IN BLT_HEADER *bltScreen
	)
{
	EFI_STATUS	res = EFI_SUCCESS;
	if (gGraphOut == NULL || bltScreen == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	if (bltScreen->Dirty.top != bltScreen->Dirty.bottom || bltScreen->Dirty.left != bltScreen->Dirty.right) {
		res = gGraphOut->Blt(gGraphOut, bltScreen->Pixels, EfiBltBufferToVideo,
			bltScreen->Dirty.left, bltScreen->Dirty.top, // Source x,y (left=X, top=Y)
			bltScreen->Dirty.left, bltScreen->Dirty.top, // Dest x,y
			bltScreen->Dirty.right - bltScreen->Dirty.left + 1, bltScreen->Dirty.bottom - bltScreen->Dirty.top + 1,		// width , height
			bltScreen->Width * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
		SetMem(&bltScreen->Dirty, sizeof(bltScreen->Dirty), 0);
	}
	return res;
}

EFI_STATUS 
ScreenSaveBlt(
	OUT BLT_HEADER **bltScreen
	)
{
	UINTN     height;
	UINTN     width;
	EFI_STATUS	res;
	BLT_HEADER*	blt;
	if (!bltScreen) return EFI_INVALID_PARAMETER;
	*bltScreen = NULL;
	res = ScreenGetSize(&height, &width);
	if (EFI_ERROR(res)) return res;
	blt = (BLT_HEADER*)MEM_ALLOC(sizeof(BLT_HEADER) + height * width * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
	if (blt == NULL) return EFI_OUT_OF_RESOURCES;
	blt->Height = (UINT32)height;
	blt->Width = (UINT32)width;
	*bltScreen = blt;
	return gGraphOut->Blt(gGraphOut, blt->Pixels, EfiBltVideoToBltBuffer, 0, 0, 0, 0, blt->Width, blt->Height, blt->Width * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
}

//////////////////////////////////////////////////////////////////////////
// Colors
//////////////////////////////////////////////////////////////////////////

EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorBlack = { 0,0,0,0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorWhite = { 255,255,255,0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorBlue  = { 255,0,0,0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorGreen = { 0,255,0,0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorRed =   { 0,0,255,0 };
EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorGray =  { 128,128,128,0 };
DRAW_CONTEXT	gDrawContext = { { 255, 255, 255, 0 },  DrawOpSet, 0xFFFFFFFF, 128, { 128,128,128, 0}, NULL };
INT32 gBrush3[5*2] = { -1,0, 1,0, 0,1, 0,-1, 0,0 };

//////////////////////////////////////////////////////////////////////////
// Blt
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
BltDrawBlt(
	IN OUT BLT_HEADER* canvas,
	IN BLT_HEADER* blt,
	IN UINTN x,
	IN UINTN y
	) {
	UINTN		row, col;
	DRAW_CONTEXT	ctx;
	ctx.Op = DrawOpSet;
	ctx.Brush = NULL;
	for (row = 0; row < blt->Height; ++row) {
		for (col = 0; col < blt->Width; ++col) {
			ctx.Color = blt->Pixels[col + row * blt->Width];
			BltPoint(canvas, &ctx, x + col, y + row);
		}
	}
	return EFI_SUCCESS;
}

EFI_STATUS
RectMarkDirty(
	IN OUT PRECT rect,
	IN UINTN x,
	IN UINTN y
	) {
	if (!rect) return EFI_INVALID_PARAMETER;
	if (rect->top > y) rect->top = (UINT32)y;
	if (rect->bottom < y) rect->bottom = (UINT32)y;
	if (rect->left > x) rect->left = (UINT32)x;
	if (rect->right < x) rect->right = (UINT32)x;
	return EFI_SUCCESS;
}


EFI_STATUS
BltPointSingle(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN UINTN x,
	IN UINTN y
	) {
	UINTN pos;
	if (!blt || x >= blt->Width || y >= blt->Height) return EFI_INVALID_PARAMETER;
	RectMarkDirty(&blt->Dirty, x, y);
	pos = x + y * blt->Width;
	if (!draw) draw = &gDrawContext;
	switch (draw->Op)
	{
	case DrawOpClear:
		*(UINT32*)&blt->Pixels[pos] &= ~(*(UINT32*)&draw->Color);
		break;
	case DrawOpXor:
		*(UINT32*)&blt->Pixels[pos] ^= *(UINT32*)&draw->Color;
		break;
	case DrawOpOr:
		*(UINT32*)&blt->Pixels[pos] |= *(UINT32*)&draw->Color;
		break;
	case DrawOpSet:
		blt->Pixels[pos] = draw->Color;
		break;
	case DrawOpAlpha:
	{
		UINT8	val;
		val = blt->Pixels[pos].Red;
		blt->Pixels[pos].Red = (UINT8)(val + (((draw->AlphaColor.Red - val) * draw->Alpha) >> 8));

		val = blt->Pixels[pos].Green;
		blt->Pixels[pos].Green = (UINT8)(val + (((draw->AlphaColor.Green - val) * draw->Alpha) >> 8));

		val = blt->Pixels[pos].Blue;
		blt->Pixels[pos].Blue = (UINT8)(val + (((draw->AlphaColor.Blue - val) * draw->Alpha) >> 8));

		break;
	}
	default:
		break;
	}
	return EFI_SUCCESS;
}

EFI_STATUS
BltPoint(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN UINTN x,
	IN UINTN y
	) {
	if (!draw) draw = &gDrawContext;
	if (draw->Brush == NULL) return BltPointSingle(blt, draw, x, y);
	else
	{
		INT32*	offset = draw->Brush;
		do {
			BltPointSingle(blt, draw, x + offset[0], y + +offset[1]);
			offset += 2;
		} while (!(offset[0] == 0 && offset[1] == 0));
		return BltPointSingle(blt, draw, x, y);
	}
}

VOID
BltBox(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN INT32 x0,
	IN INT32 y0,
	IN INT32 x1,
	IN INT32 y1)
{
	BltLine(blt, draw, x0, y0, x1, y0);
	BltLine(blt, draw, x0, y0, x0, y1);
	BltLine(blt, draw, x0, y1, x1, y1);
	BltLine(blt, draw, x1, y0, x1, y1);
}

VOID
BltFill(
	IN BLT_HEADER* blt,
	IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL	fill,
	IN INT32 x0,
	IN INT32 y0,
	IN INT32 x1,
	IN INT32 y1) 
{
	INT32 x;
	INT32 y;
	DRAW_CONTEXT	ctx;
	ctx.Op = DrawOpSet;
	ctx.Brush = NULL;
	ctx.Color = fill;
	for (y = y0; y < y1; ++y) {
		for (x = x0; x < x1; ++x) {
			BltPoint(blt, &ctx, x, y);
		}
	}
}

VOID 
BltLine(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN INT32 x0,
	IN INT32 y0, 
	IN INT32 x1, 
	IN INT32 y1)
{
	int dx = ABS(x1 - x0), sx = x0 < x1 ? 1 : -1;
	int dy = -ABS(y1 - y0), sy = y0 < y1 ? 1 : -1;
	UINT32 mask, dmask, cmask;
	int err = dx + dy, e2;                                   /* error value e_xy */
	mask = draw ? draw->DashLine : gDrawContext.DashLine;
	dmask = mask;
	cmask = 32;
	for (;;) {                                                          /* loop */
		// Dash
		if ((dmask & 1) == 1) {
			BltPoint(blt, draw, x0, y0);
		}
		dmask >>= 1;
		cmask--;
		if (cmask == 0) {
			dmask = mask;
			cmask = 32;
		}
		// next point
		e2 = 2 * err;
		if (e2 >= dy) {                                         /* e_xy+e_x > 0 */
			if (x0 == x1) break;
			err += dy; x0 += sx;
		}
		if (e2 <= dx) {                                         /* e_xy+e_y < 0 */
			if (y0 == y1) break;
			err += dx; y0 += sy;
		}
	}
}



VOID 
BltCircle(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN INT32 xm,
	IN INT32 ym,
	IN INT32 r,
	IN BOOLEAN fill)
{
	int sx = 1;
	int x = -r, y = 0, err = 2 - 2 * r;                /* bottom left to top right */
	UINT32 mask, dmask, cmask;
	mask = draw ? draw->DashLine : gDrawContext.DashLine;
	dmask = mask;
	cmask = 32;
	do {
		if (fill) {
			if (sx != x) {
				int i;
				for (i = ym - y; i <= ym + y; i++) {
					BltPoint(blt, draw, xm + x, i);
					if( x != 0 ) BltPoint(blt, draw, xm - x, i);
				}
				sx = x;
			}
		}	else {
			if ((dmask & 1) == 1) {
				BltPoint(blt, draw, xm - x, ym + y);                            /*   I. Quadrant +x +y */
				BltPoint(blt, draw, xm - y, ym - x);                            /*  II. Quadrant -x +y */
				BltPoint(blt, draw, xm + x, ym - y);                            /* III. Quadrant -x -y */
				BltPoint(blt, draw, xm + y, ym + x);                            /*  IV. Quadrant +x -y */
			}
			dmask >>= 1;
			cmask--;
		}
		if (cmask == 0) {
			dmask = mask;
			cmask = 32;
		}
		r = err;
		if (r <= y) err += ++y * 2 + 1;                             /* e_xy+e_y < 0 */
		if (r >= x || err > y)                  /* e_xy+e_x > 0 or no 2nd y-step */
			err += ++x * 2 + 1;                                     /* -> x-step now */
	} while (x <= 0);
}

extern __int8 gSimplex_ascii_32_126[95][112];
VOID
BltText(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN INT32 x,
	IN INT32 y,
	IN INT32 scale, // 0..256 reduce 256... enlarge
	IN CONST VOID *text,
	IN BOOLEAN wide)
{
	INT32	posX = x;
	INT32 posY = y;
	const char *c;
	for (c = text; *c; c += (wide ? 2 : 1))
	{
		INT8 ch = *c;
		if (ch >= 32 && ch <= 126) {
			INT8 *it = (INT8*)gSimplex_ascii_32_126[ch - 32];
			INT32 nvtcs = *it++;
			INT32 spacing = *it++;
			INT32	fromX = -1;
			INT32 fromY = -1;
			INTN i;
			for (i = 0; i < nvtcs; ++i) {
				INT32 toX = *it++;
				INT32 toY = *it++;
				if ((fromX != -1 || fromY != -1) && (toX != -1 || toY != -1)) {
					BltLine(
						blt, draw,
						posX + ((fromX * scale) >> 8), posY + (((25 - fromY) * scale) >> 8),
						posX + ((toX * scale) >> 8), posY + (((25 - toY) * scale) >> 8));
				}
				fromX = toX;
				fromY = toY;
			}
			posX += (spacing * scale) >> 8;
		}
		// Next line
		if (ch == '\n') {
			posX = x;
			posY += 30 * scale >> 8;
		}
	}
}

// Monospace version - fixed character width for console output
// Width of 24 units at scale 96 gives ~9 pixels, matching typical console char width
#define MONO_CHAR_WIDTH 24
VOID
BltTextMono(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN INT32 x,
	IN INT32 y,
	IN INT32 scale, // 0..256 reduce 256... enlarge
	IN CONST VOID *text,
	IN BOOLEAN wide)
{
	INT32	posX = x;
	INT32 posY = y;
	const char *c;
	for (c = text; *c; c += (wide ? 2 : 1))
	{
		INT8 ch = *c;
		if (ch >= 32 && ch <= 126) {
			INT8 *it = (INT8*)gSimplex_ascii_32_126[ch - 32];
			INT32 nvtcs = *it++;
			it++; // Skip variable spacing, we use fixed width
			INT32	fromX = -1;
			INT32 fromY = -1;
			INTN i;
			for (i = 0; i < nvtcs; ++i) {
				INT32 toX = *it++;
				INT32 toY = *it++;
				if ((fromX != -1 || fromY != -1) && (toX != -1 || toY != -1)) {
					BltLine(
						blt, draw,
						posX + ((fromX * scale) >> 8), posY + (((25 - fromY) * scale) >> 8),
						posX + ((toX * scale) >> 8), posY + (((25 - toY) * scale) >> 8));
				}
				fromX = toX;
				fromY = toY;
			}
			posX += (MONO_CHAR_WIDTH * scale) >> 8;
		}
		// Next line
		if (ch == '\n') {
			posX = x;
			posY += 30 * scale >> 8;
		}
	}
}

//////////////////////////////////////////////////////////////////////////
// Bmp
//////////////////////////////////////////////////////////////////////////

#pragma pack(1)
typedef struct {
	UINT8   Blue;
	UINT8   Green;
	UINT8   Red;
	UINT8   Reserved;
} BMP_COLOR_MAP;

typedef struct {
	CHAR8         CharB;
	CHAR8         CharM;
	UINT32        Size;
	UINT16        Reserved[2];
	UINT32        ImageOffset;
	UINT32        HeaderSize;
	UINT32        PixelWidth;
	UINT32        PixelHeight;
	UINT16        Planes;       // Must be 1
	UINT16        BitPerPixel;  // 1, 4, 8, or 24
	UINT32        CompressionType;
	UINT32        ImageSize;    // Compressed image size in bytes
	UINT32        XPixelsPerMeter;
	UINT32        YPixelsPerMeter;
	UINT32        NumberOfColors;
	UINT32        ImportantColors;
} BMP_IMAGE_HEADER;
#pragma pack()

EFI_STATUS BmpGetSize(
	IN const unsigned char*      BmpImage,
	IN UINTN      BmpImageSize,
	OUT UINTN     *Height,
	OUT UINTN     *Width
	)
{
	BMP_IMAGE_HEADER              *BmpHeader;

	if (sizeof(BMP_IMAGE_HEADER) > BmpImageSize) {
		return EFI_INVALID_PARAMETER;
	}

	BmpHeader = (BMP_IMAGE_HEADER *)BmpImage;

	if (BmpHeader->CharB != 'B' || BmpHeader->CharM != 'M') {
		return EFI_UNSUPPORTED;
	}

	//
	// Only support BITMAPINFOHEADER format.
	// BITMAPFILEHEADER + BITMAPINFOHEADER = BMP_IMAGE_HEADER
	//
	if (BmpHeader->HeaderSize != sizeof(BMP_IMAGE_HEADER) - ((UINTN)&(((BMP_IMAGE_HEADER *)0)->HeaderSize))) {
		return EFI_UNSUPPORTED;
	}

	*Height = BmpHeader->PixelHeight;
	*Width = BmpHeader->PixelWidth;
	return EFI_SUCCESS;
}

EFI_STATUS 
BmpToBlt(
	IN CONST VOID      *BmpImage,
	IN  UINTN     BmpImageSize,
	OUT BLT_HEADER **blt
	)
{
	UINT8                         *Image;
	UINT8                         *ImageHeader;
	BMP_IMAGE_HEADER              *BmpHeader;
	BMP_COLOR_MAP                 *BmpColorMap;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL *Blt_;
	UINT64                        BltBufferSize;
	UINTN                         Index;
	UINTN                         Height;
	UINTN                         Width;
	UINTN                         ImageIndex;
	UINTN                         DataSizePerLine;
	UINT32                        ColorMapNum;

	if (sizeof(BMP_IMAGE_HEADER) > BmpImageSize) {
		return EFI_INVALID_PARAMETER;
	}

	BmpHeader = (BMP_IMAGE_HEADER *)BmpImage;

	if (BmpHeader->CharB != 'B' || BmpHeader->CharM != 'M') {
		return EFI_UNSUPPORTED;
	}

	//
	// Doesn't support compress.
	//
	if (BmpHeader->CompressionType != 0) {
		return EFI_UNSUPPORTED;
	}

	//
	// Only support BITMAPINFOHEADER format.
	// BITMAPFILEHEADER + BITMAPINFOHEADER = BMP_IMAGE_HEADER
	//
	if (BmpHeader->HeaderSize != sizeof(BMP_IMAGE_HEADER) - ((UINTN)&(((BMP_IMAGE_HEADER *)0)->HeaderSize))) {
		return EFI_UNSUPPORTED;
	}

	//
	// The data size in each line must be 4 byte alignment.
	//
	DataSizePerLine = ((BmpHeader->PixelWidth * BmpHeader->BitPerPixel + 31) >> 3) & (~0x3);
	BltBufferSize = MultU64x32(DataSizePerLine, BmpHeader->PixelHeight);
	if (BltBufferSize > (UINT32)~0) {
		return EFI_INVALID_PARAMETER;
	}

	if ((BmpHeader->Size != BmpImageSize) ||
		(BmpHeader->Size < BmpHeader->ImageOffset) ||
		(BmpHeader->Size - BmpHeader->ImageOffset != BmpHeader->PixelHeight * DataSizePerLine)) {
		return EFI_INVALID_PARAMETER;
	}

	//
	// Calculate Color Map offset in the image.
	//
	Image = (UINT8 *)BmpImage;
	BmpColorMap = (BMP_COLOR_MAP *)(Image + sizeof(BMP_IMAGE_HEADER));
	if (BmpHeader->ImageOffset < sizeof(BMP_IMAGE_HEADER)) {
		return EFI_INVALID_PARAMETER;
	}

	if (BmpHeader->ImageOffset > sizeof(BMP_IMAGE_HEADER)) {
		switch (BmpHeader->BitPerPixel) {
		case 1:
			ColorMapNum = 2;
			break;
		case 4:
			ColorMapNum = 16;
			break;
		case 8:
			ColorMapNum = 256;
			break;
		default:
			ColorMapNum = 0;
			break;
		}
		if (BmpHeader->ImageOffset - sizeof(BMP_IMAGE_HEADER) != sizeof(BMP_COLOR_MAP) * ColorMapNum) {
			return EFI_INVALID_PARAMETER;
		}
	}

	//
	// Calculate graphics image data address in the image
	//
	Image = ((UINT8 *)BmpImage) + BmpHeader->ImageOffset;
	ImageHeader = Image;

	BltBufferSize = MultU64x32((UINT64)BmpHeader->PixelWidth, BmpHeader->PixelHeight);
	//
	// Ensure the BltBufferSize * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL) doesn't overflow
	//
	if (BltBufferSize > DivU64x32((UINTN)~0, sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL))) {
		return EFI_UNSUPPORTED;
	}
	BltBufferSize = MultU64x32(BltBufferSize, sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));

	*blt = MEM_ALLOC((UINTN)BltBufferSize + sizeof(**blt));

	(*blt)->Width = BmpHeader->PixelWidth;
	(*blt)->Height = BmpHeader->PixelHeight;

	//
	// Convert image from BMP to Blt buffer format
	//
	BltBuffer = (*blt)->Pixels;
	for (Height = 0; Height < BmpHeader->PixelHeight; Height++) {
		Blt_ = &BltBuffer[(BmpHeader->PixelHeight - Height - 1) * BmpHeader->PixelWidth];
		for (Width = 0; Width < BmpHeader->PixelWidth; Width++, Image++, Blt_++) {
			switch (BmpHeader->BitPerPixel) {
			case 1:
				//
				// Convert 1bit BMP to 24-bit color
				//
				for (Index = 0; Index < 8 && Width < BmpHeader->PixelWidth; Index++) {
					Blt_->Red = BmpColorMap[((*Image) >> (7 - Index)) & 0x1].Red;
					Blt_->Green = BmpColorMap[((*Image) >> (7 - Index)) & 0x1].Green;
					Blt_->Blue = BmpColorMap[((*Image) >> (7 - Index)) & 0x1].Blue;
					Blt_++;
					Width++;
				}

				Blt_--;
				Width--;
				break;

			case 4:
				//
				// Convert BMP Palette to 24-bit color
				//
				Index = (*Image) >> 4;
				Blt_->Red = BmpColorMap[Index].Red;
				Blt_->Green = BmpColorMap[Index].Green;
				Blt_->Blue = BmpColorMap[Index].Blue;
				if (Width < (BmpHeader->PixelWidth - 1)) {
					Blt_++;
					Width++;
					Index = (*Image) & 0x0f;
					Blt_->Red = BmpColorMap[Index].Red;
					Blt_->Green = BmpColorMap[Index].Green;
					Blt_->Blue = BmpColorMap[Index].Blue;
				}
				break;

			case 8:
				//
				// Convert BMP Palette to 24-bit color
				//
				Blt_->Red = BmpColorMap[*Image].Red;
				Blt_->Green = BmpColorMap[*Image].Green;
				Blt_->Blue = BmpColorMap[*Image].Blue;
				break;

			case 24:
				Blt_->Blue = *Image++;
				Blt_->Green = *Image++;
				Blt_->Red = *Image;
				break;

			default:
				MEM_FREE(*blt);
				*blt = NULL;
				return EFI_UNSUPPORTED;
				break;
			};

		}

		ImageIndex = (UINTN)(Image - ImageHeader);
		if ((ImageIndex % 4) != 0) {
			//
			// Bmp Image starts each row on a 32-bit boundary!
			//
			Image = Image + (4 - (ImageIndex % 4));
		}
	}

	return EFI_SUCCESS;
}

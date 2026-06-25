/** @file
EFI console print with attribute (based on shell print)

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 
Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/DebugLib.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/Shell.h>
#include <Protocol/ShellParameters.h>

//////////////////////////////////////////////////////////////////////////
// Custom print based on shell print (copied here to avoid runtime limitation)
//////////////////////////////////////////////////////////////////////////

#define ATTRPRINT_BUFSIZE 4096

BOOLEAN	gShellReady = FALSE;
EFI_SHELL_PARAMETERS_PROTOCOL* mEfiShellParametersProtocol = NULL;
EFI_SHELL_PROTOCOL* mEfiShellProtocol = NULL;

VOID 
SetShellAPI(
	IN VOID* shellProtocol,
	IN VOID* shellParametersProtocol) {
	mEfiShellParametersProtocol = (EFI_SHELL_PARAMETERS_PROTOCOL*)shellParametersProtocol;
	mEfiShellProtocol = (EFI_SHELL_PROTOCOL*)shellProtocol;
}

/**
  Safely append with automatic string resizing given length of Destination and
  desired length of copy from Source.

  append the first D characters of Source to the end of Destination, where D is
  the lesser of Count and the StrLen() of Source. If appending those D characters
  will fit within Destination (whose Size is given as CurrentSize) and
  still leave room for a NULL terminator, then those characters are appended,
  starting at the original terminating NULL of Destination, and a new terminating
  NULL is appended.

  If appending D characters onto Destination will result in an overflow of the size
  given in CurrentSize the string will be grown such that the copy can be performed
  and CurrentSize will be updated to the new size.

  If Source is NULL, there is nothing to append, just return the current buffer in
  Destination.

  if Destination is NULL, then ASSERT()
  if Destination's current length (including NULL terminator) is already more then
  CurrentSize, then ASSERT()

  @param[in, out] Destination   The String to append onto
  @param[in, out] CurrentSize   on call the number of bytes in Destination.  On
                                return possibly the new size (still in bytes).  if NULL
                                then allocate whatever is needed.
  @param[in]      Source        The String to append from
  @param[in]      Count         Maximum number of characters to append.  if 0 then
                                all are appended.

  @return Destination           return the resultant string.
**/
CHAR16*
EFIAPI
StrnCatGrow2 (
  IN OUT CHAR16           **Destination,
  IN OUT UINTN            *CurrentSize,
  IN     CONST CHAR16     *Source,
  IN     UINTN            Count
  )
{
  UINTN DestinationStartSize;
  UINTN NewSize;

  //
  // ASSERTs
  //
  ASSERT(Destination != NULL);

  //
  // If there's nothing to do then just return Destination
  //
  if (Source == NULL) {
    return (*Destination);
  }

  //
  // allow for un-initialized pointers, based on size being 0
  //
  if (CurrentSize != NULL && *CurrentSize == 0) {
    *Destination = NULL;
  }

  //
  // allow for NULL pointers address as Destination
  //
  if (*Destination != NULL) {
    ASSERT(CurrentSize != 0);
    DestinationStartSize = StrSize(*Destination);
    ASSERT(DestinationStartSize <= *CurrentSize);
  } else {
    DestinationStartSize = 0;
//    ASSERT(*CurrentSize == 0);
  }

  //
  // Append all of Source?
  //
  if (Count == 0) {
    Count = StrLen(Source);
  }

  //
  // Test and grow if required
  //
  if (CurrentSize != NULL) {
    NewSize = *CurrentSize;
    if (NewSize < DestinationStartSize + (Count * sizeof(CHAR16))) {
      while (NewSize < (DestinationStartSize + (Count*sizeof(CHAR16)))) {
        NewSize += 2 * Count * sizeof(CHAR16);
      }
      *Destination = MEM_REALLOC(*CurrentSize, NewSize, *Destination);
      *CurrentSize = NewSize;
    }
  } else {
    NewSize = (Count+1)*sizeof(CHAR16);
    *Destination = MEM_ALLOC(NewSize);
  }

  //
  // Now use standard StrnCat on a big enough buffer
  //
  if (*Destination == NULL) {
    return (NULL);
  }
  
  StrnCatS(*Destination, NewSize/sizeof(CHAR16), Source, Count);
  return *Destination;
}


/**
  This is a find and replace function.  Upon successful return the NewString is a copy of
  SourceString with each instance of FindTarget replaced with ReplaceWith.

  If SourceString and NewString overlap the behavior is undefined.

  If the string would grow bigger than NewSize it will halt and return error.

  @param[in] SourceString              The string with source buffer.
  @param[in, out] NewString            The string with resultant buffer.
  @param[in] NewSize                   The size in bytes of NewString.
  @param[in] FindTarget                The string to look for.
  @param[in] ReplaceWith               The string to replace FindTarget with.
  @param[in] SkipPreCarrot             If TRUE will skip a FindTarget that has a '^'
                                       immediately before it.
  @param[in] ParameterReplacing        If TRUE will add "" around items with spaces.

  @retval EFI_INVALID_PARAMETER       SourceString was NULL.
  @retval EFI_INVALID_PARAMETER       NewString was NULL.
  @retval EFI_INVALID_PARAMETER       FindTarget was NULL.
  @retval EFI_INVALID_PARAMETER       ReplaceWith was NULL.
  @retval EFI_INVALID_PARAMETER       FindTarget had length < 1.
  @retval EFI_INVALID_PARAMETER       SourceString had length < 1.
  @retval EFI_BUFFER_TOO_SMALL        NewSize was less than the minimum size to hold
                                      the new string (truncation occurred).
  @retval EFI_SUCCESS                 The string was successfully copied with replacement.
**/
EFI_STATUS
EFIAPI
StrCopySearchAndReplace(
  IN CHAR16 CONST                     *SourceString,
  IN OUT CHAR16                       *NewString,
  IN UINTN                            NewSize,
  IN CONST CHAR16                     *FindTarget,
  IN CONST CHAR16                     *ReplaceWith,
  IN CONST BOOLEAN                    SkipPreCarrot,
  IN CONST BOOLEAN                    ParameterReplacing
  )
{
  UINTN Size;
  CHAR16 *Replace;

  if ( (SourceString == NULL)
    || (NewString    == NULL)
    || (FindTarget   == NULL)
    || (ReplaceWith  == NULL)
    || (StrLen(FindTarget) < 1)
    || (StrLen(SourceString) < 1)
   ){
    return (EFI_INVALID_PARAMETER);
  }
  Replace = NULL;
  if (StrStr(ReplaceWith, L" ") == NULL || !ParameterReplacing) {
    Replace = StrnCatGrow2(&Replace, NULL, ReplaceWith, 0);
  } else {
    Replace = MEM_ALLOC(StrSize(ReplaceWith) + 2*sizeof(CHAR16));
    if (Replace != NULL) {
      UnicodeSPrint(Replace, StrSize(ReplaceWith) + 2*sizeof(CHAR16), L"\"%s\"", ReplaceWith);
    }
  }
  if (Replace == NULL) {
    return (EFI_OUT_OF_RESOURCES);
  }
  NewString = ZeroMem(NewString, NewSize);
  while (*SourceString != CHAR_NULL) {
    //
    // if we find the FindTarget and either Skip == FALSE or Skip  and we
    // don't have a carrot do a replace...
    //
    if (StrnCmp(SourceString, FindTarget, StrLen(FindTarget)) == 0
      && ((SkipPreCarrot && *(SourceString-1) != L'^') || !SkipPreCarrot)
     ){
      SourceString += StrLen(FindTarget);
      Size = StrSize(NewString);
      if ((Size + (StrLen(Replace)*sizeof(CHAR16))) > NewSize) {
        MEM_FREE(Replace);
        return (EFI_BUFFER_TOO_SMALL);
      }
      StrCatS(NewString, NewSize/sizeof(CHAR16), Replace);
    } else {
      Size = StrSize(NewString);
      if (Size + sizeof(CHAR16) > NewSize) {
			MEM_FREE(Replace);
        return (EFI_BUFFER_TOO_SMALL);
      }
      StrnCatS(NewString, NewSize/sizeof(CHAR16), SourceString, 1);
      SourceString++;
    }
  }
  MEM_FREE(Replace);
  return (EFI_SUCCESS);
}

/**
  Internal worker function to output a string.

  This function will output a string to the correct StdOut.

  @param[in] String       The string to print out.

  @retval EFI_SUCCESS     The operation was successful.
  @retval !EFI_SUCCESS    The operation failed.
**/
EFI_STATUS
EFIAPI
AttrPrintTo (
  IN CONST CHAR16 *String
  )
{
	UINTN Size;
	Size = StrSize(String) - sizeof(CHAR16);
	if (Size == 0) {
		return (EFI_SUCCESS);
	}
	if (mEfiShellParametersProtocol != NULL) {
		return (mEfiShellProtocol->WriteFile(mEfiShellParametersProtocol->StdOut, &Size, (VOID*)String));
	}
	return gST->ConOut->OutputString(gST->ConOut, (CHAR16*)String);
}

/**
  Print at a specific location on the screen.

  This function will move the cursor to a given screen location and print the specified string

  If -1 is specified for either the Row or Col the current screen location for BOTH
  will be used.

  if either Row or Col is out of range for the current console, then ASSERT
  if Format is NULL, then ASSERT

  In addition to the standard %-based flags as supported by UefiLib Print() this supports
  the following additional flags:
    %N       -   Set output attribute to normal
    %H       -   Set output attribute to highlight
    %E       -   Set output attribute to error
    %B       -   Set output attribute to blue color
    %V       -   Set output attribute to green color
    %R       -   Set output attribute to red color

  Note: The background color is controlled by the shell command cls.

  @param[in] Col        the column to print at
  @param[in] Row        the row to print at
  @param[in] Format     the format string
  @param[in] Marker     the marker for the variable argument list

  @return EFI_SUCCESS           The operation was successful.
  @return EFI_DEVICE_ERROR      The console device reported an error.
**/
EFI_STATUS
EFIAPI
InternalAttrPrintWorker(
  IN INT32                Col OPTIONAL,
  IN INT32                Row OPTIONAL,
  IN CONST CHAR16         *Format,
  IN VA_LIST              Marker
  )
{
  EFI_STATUS        Status;
  CHAR16            *ResumeLocation;
  CHAR16            *FormatWalker;
  UINTN             OriginalAttribute;
  CHAR16            *mPostReplaceFormat;
  CHAR16            *mPostReplaceFormat2;

  mPostReplaceFormat = (CHAR16*)MEM_ALLOC (ATTRPRINT_BUFSIZE);
  mPostReplaceFormat2 = (CHAR16*)MEM_ALLOC (ATTRPRINT_BUFSIZE);

  if (mPostReplaceFormat == NULL || mPostReplaceFormat2 == NULL) {
    MEM_FREE(mPostReplaceFormat);
    MEM_FREE(mPostReplaceFormat2);
    return (EFI_OUT_OF_RESOURCES);
  }

  Status            = EFI_SUCCESS;
  OriginalAttribute = gST->ConOut->Mode->Attribute;

  //
  // Back and forth each time fixing up 1 of our flags...
  //
  Status = StrCopySearchAndReplace(Format,              mPostReplaceFormat,  ATTRPRINT_BUFSIZE, L"%N", L"%%N", FALSE, FALSE);
  Status = StrCopySearchAndReplace(mPostReplaceFormat,  mPostReplaceFormat2, ATTRPRINT_BUFSIZE, L"%E", L"%%E", FALSE, FALSE);
  Status = StrCopySearchAndReplace(mPostReplaceFormat2, mPostReplaceFormat,  ATTRPRINT_BUFSIZE, L"%H", L"%%H", FALSE, FALSE);
  Status = StrCopySearchAndReplace(mPostReplaceFormat,  mPostReplaceFormat2, ATTRPRINT_BUFSIZE, L"%B", L"%%B", FALSE, FALSE);
  Status = StrCopySearchAndReplace(mPostReplaceFormat2, mPostReplaceFormat,  ATTRPRINT_BUFSIZE, L"%V", L"%%V", FALSE, FALSE);
  Status = StrCopySearchAndReplace(mPostReplaceFormat,  mPostReplaceFormat2, ATTRPRINT_BUFSIZE, L"%O", L"%%O", FALSE, FALSE);
  CopyMem(mPostReplaceFormat, mPostReplaceFormat2, ATTRPRINT_BUFSIZE);

  //
  // Use the last buffer from replacing to print from...
  //
  UnicodeVSPrint (mPostReplaceFormat2, ATTRPRINT_BUFSIZE, mPostReplaceFormat, Marker);

  if (Col != -1 && Row != -1) {
    Status = gST->ConOut->SetCursorPosition(gST->ConOut, Col, Row);
  }

  FormatWalker = mPostReplaceFormat2;
  while (*FormatWalker != CHAR_NULL) {
    //
    // Find the next attribute change request
    //
    ResumeLocation = StrStr(FormatWalker, L"%");
    if (ResumeLocation != NULL) {
      *ResumeLocation = CHAR_NULL;
    }
    //
    // print the current FormatWalker string
    //
    if (StrLen(FormatWalker)>0) {
      Status = AttrPrintTo(FormatWalker);
      if (EFI_ERROR(Status)) {
        break;
      }
    }

    //
    // update the attribute
    //
    if (ResumeLocation != NULL) {
      if (*(ResumeLocation-1) == L'^') {
        //
        // Move cursor back 1 position to overwrite the ^
        //
        gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - 1, gST->ConOut->Mode->CursorRow);

        //
        // Print a simple '%' symbol
        //
        Status = AttrPrintTo(L"%");
        ResumeLocation = ResumeLocation - 1;
      } else {
        switch (*(ResumeLocation+1)) {
          case (L'N'):
            gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);
            break;
          case (L'E'):
            gST->ConOut->SetAttribute(gST->ConOut, EFI_TEXT_ATTR(EFI_YELLOW, ((OriginalAttribute&(BIT4|BIT5|BIT6))>>4)));
            break;
          case (L'H'):
            gST->ConOut->SetAttribute(gST->ConOut, EFI_TEXT_ATTR(EFI_WHITE, ((OriginalAttribute&(BIT4|BIT5|BIT6))>>4)));
            break;
          case (L'B'):
            gST->ConOut->SetAttribute(gST->ConOut, EFI_TEXT_ATTR(EFI_BLUE, ((OriginalAttribute&(BIT4|BIT5|BIT6))>>4)));
            break;
          case (L'V'):
            gST->ConOut->SetAttribute(gST->ConOut, EFI_TEXT_ATTR(EFI_GREEN, ((OriginalAttribute&(BIT4|BIT5|BIT6))>>4)));
            break;
          case (L'O'):
            gST->ConOut->SetAttribute(gST->ConOut, EFI_TEXT_ATTR(EFI_RED, ((OriginalAttribute&(BIT4|BIT5|BIT6))>>4)));
            break;
          default:
            //
            // Print a simple '%' symbol
            //
            Status = AttrPrintTo(L"%");
            if (EFI_ERROR(Status)) {
              break;
            }
            ResumeLocation = ResumeLocation - 1;
            break;
        }
      }
    } else {
      //
      // reset to normal now...
      //
      break;
    }

    //
    // update FormatWalker to Resume + 2 (skip the % and the indicator)
    //
    FormatWalker = ResumeLocation + 2;
  }

  gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);

  MEM_FREE(mPostReplaceFormat);
  MEM_FREE(mPostReplaceFormat2);
  return (Status);
}

/**
  Print at a specific location on the screen.

  This function will move the cursor to a given screen location and print the specified string.

  If -1 is specified for either the Row or Col the current screen location for BOTH
  will be used.

  If either Row or Col is out of range for the current console, then ASSERT.
  If Format is NULL, then ASSERT.

  In addition to the standard %-based flags as supported by UefiLib Print() this supports
  the following additional flags:
    %N       -   Set output attribute to normal
    %H       -   Set output attribute to highlight
    %E       -   Set output attribute to error
    %B       -   Set output attribute to blue color
    %V       -   Set output attribute to green color
    %O       -   Set output attribute to red color

  Note: The background color is controlled by the shell command cls.

  @param[in] Col        the column to print at
  @param[in] Row        the row to print at
  @param[in] Format     the format string
  @param[in] ...        The variable argument list.

  @return EFI_SUCCESS           The printing was successful.
  @return EFI_DEVICE_ERROR      The console device reported an error.
**/
EFI_STATUS
EFIAPI
AttrPrintEx(
  IN INT32                Col OPTIONAL,
  IN INT32                Row OPTIONAL,
  IN CONST CHAR16         *Format,
  ...
  )
{
  VA_LIST           Marker;
  EFI_STATUS        RetVal;
  if (Format == NULL) {
    return (EFI_INVALID_PARAMETER);
  }
  VA_START (Marker, Format);
  RetVal = InternalAttrPrintWorker(Col, Row, Format, Marker);
  VA_END(Marker);
  return(RetVal);
}

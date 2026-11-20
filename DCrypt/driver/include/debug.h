#ifndef _DEBUG_
#define _DEBUG_

//#define DBG_MSG
//#define DBG_COM
//#define DBG_HAL_DISPLAY


#ifdef DBG_MSG
 
#ifdef DBG_COM
  void com_print(char *format, ...);
  #define DbgMsg com_print
#else 
#ifdef DBG_HAL_DISPLAY
  void hal_print(char *format, ...);
  #define DbgMsg hal_print
#else
  #define DbgMsg(_msg, ...) DbgPrintEx(DPFLTR_DEFAULT_ID, /*DPFLTR_INFO_LEVEL*/ 0xFFFFFFFF, "dcrypt: "##_msg, ##__VA_ARGS__)
#endif /* DBG_HAL_DISPLAY */
#endif /* DBG_COM */

#else /* DBG_MSG */
  #define DbgMsg(_msg, ...) __noop
#endif

void DumpHex(const char* prefix, const void* data, size_t size);

#ifdef DBG_MSG
 void dc_dbg_init();
#endif

#endif


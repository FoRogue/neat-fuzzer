/*
 * nocore.so: подгружается в таргет через AFL_PRELOAD и делает процесс «не дампабельным».
 * В Docker Desktop (WSL2) core_pattern = "|/wsl-capture-crash ...": каждый краш запускает
 * внешний обработчик (~20-90 мс), даже при ulimit -c 0. PR_SET_DUMPABLE=0 отключает дамп целиком.
 */
#include <sys/prctl.h>

__attribute__((constructor)) static void nocore_init(void) { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0); }

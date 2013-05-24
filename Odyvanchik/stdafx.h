// stdafx.h: включаемый файл дл€ стандартных системных включаемых файлов
// или включаемых файлов дл€ конкретного проекта, которые часто используютс€, но
// не часто измен€ютс€
//

#pragma once

#include "targetver.h"
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <string>
#include <Windows.h>
#include "accctrl.h"
#include "aclapi.h"
#include "psapi.h"
#include "Sddl.h"
#include <lm.h>			//header for netapi32.lib
#include <exception>
#include <list>
#include <map>
#include "Process.h"
#include <limits>
#pragma comment(lib, "advapi32.lib")	//for get process info and so on
#pragma comment(lib, "netapi32.lib")	//for users list
typedef std::list<USER_INFO_20> USERS_LIST;
typedef std::list<GROUP_INFO_2> GROUPS_LIST;
typedef std::list<Process*> PROCESSES;
typedef std::map<DWORD,BOOL> RIDS_LIST;

USERS_LIST usersList();
GROUPS_LIST groupsList();
const char *dword_to_binary(DWORD x);
const std::string humanize(DWORD x);



// TODO: ”становите здесь ссылки на дополнительные заголовки, требующиес€ дл€ программы

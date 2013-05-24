// Odyvanchik.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"

const int mask_length = 8;
const int procid_length = 4;
int _tmain(int argc, _TCHAR* argv[])
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;
	DWORD dwReturnCode;

	dwReturnCode =  EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ); //Получаем pid процесов и их кол-во
	if (!dwReturnCode){
		printf_s("EnumProcess error %d\n",GetLastError());
		return -1;
	}
	PROCESSES processes;//list процессов 
    
	// Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD); //почему именно так- это вопрос к msdn

    for ( i = 0; i < cProcesses; i++ ){
        if( aProcesses[i] != 0 ){
			try {
				processes.push_back(new Process(aProcesses[i]));
			} catch(ProcessException& e){//ловим ошибки при создании класса Process
				printf("id=%d ",aProcesses[i]);
				e.what();
			}
        }
    }

	PROCESSES::iterator proc;
	RIDS_LIST rids;
	// Write all info about process. also store all USED RIDs
	for (proc = processes.begin(); proc != processes.end() ; ++proc){
		printf("id=%d rid=%d: ",proc._Ptr->_Myval->GetID(),proc._Ptr->_Myval->GetOwnRID());//PID процессорва и RID владельца
		ALLOWED_ACES aces = proc._Ptr->_Myval->GetAllowedACEs();
		DENIED_ACES daces = proc._Ptr->_Myval->GetDeniedACEs();
		rids[proc._Ptr->_Myval->GetOwnRID()]=TRUE; //Sorry for chinese style. I realy don't mind how does it look like RIGHT
		printf("Allowed aces:[");
		for(ALLOWED_ACES::iterator ace = aces.begin(); ace != aces.end(); ++ace){
			printf("[%u : %u] ",ace._Ptr->_Myval->SidStart,ace._Ptr->_Myval->Mask);//Соответствие маски и RID из ACE
			rids[ace._Ptr->_Myval->SidStart]=TRUE;
		}
		printf("Denied aces:[");
		for(DENIED_ACES::iterator dace = daces.begin(); dace != daces.end(); ++dace){
			printf("[%u : %u] ",dace._Ptr->_Myval->SidStart,dace._Ptr->_Myval->Mask);//Соответствие маски и RID из ACE
			rids[dace._Ptr->_Myval->SidStart]=TRUE;
		}
		printf("]\n");
	}

	USERS_LIST userslist = usersList();//Добавим в лист пользователей RID РЕАЛЬНЫХ ПОЛЬЗОВАТЕЛЕЙ,а не всяких системных и не понятных.
	USERS_LIST::iterator user;
	for (user = userslist.begin(); user != userslist.end(); ++user)
		rids[user._Ptr->_Myval.usri20_user_id] = TRUE;

	RIDS_LIST::iterator rid;
	//Header of table
	_tprintf(TEXT("%* "),procid_length);
	for (rid=rids.begin();rid != rids.end(); ++rid){//В загаловке таблицы Юзеры
		printf("%*d ",mask_length,rid._Ptr->_Myval.first);
	}

	//Body of table
	printf("\n");
	for (proc = processes.begin(); proc != processes.end() ; ++proc){//В строках - процессы и маски
		printf("%*d ",procid_length,proc._Ptr->_Myval->GetID());
		for (rid=rids.begin();rid != rids.end(); ++rid){
			//printf("%s ",dword_to_binary(proc._Ptr->_Myval->mask_for_rid(rid._Ptr->_Myval.first))); //Представить маску в бинарном виде-выглядит страшно, но можно вручную понять маску
			printf("%0*x ",mask_length,proc._Ptr->_Myval->mask_for_rid(rid._Ptr->_Myval.first));	//в 16-ричной форме-как в документации msdn. ffffffff == owner
		}
		std::cout<<std::endl;
	}

	for (proc = processes.begin(); proc != processes.end() ; ++proc){
		proc._Ptr->_Myval->~Process();
	}
	return 0;
}
const char *dword_to_binary(DWORD x){
	static char b[33];
	b[0]='\0';

	DWORD z = MAXDWORD;
    for (; z > 0; z >>= 1)
        strcat_s(b, ((x & z) == z) ? "1" : "0");

    return b;
}
USERS_LIST usersList(){//Вернет всех пользователей
	USERS_LIST users;
	USER_INFO_20 *pBuf;//структура 20 уровня ( как 80 только 20)
	USER_INFO_20 *pTempBuf;
	DWORD filter = //global users
			FILTER_NORMAL_ACCOUNT | 
			FILTER_INTERDOMAIN_TRUST_ACCOUNT | 
			FILTER_TEMP_DUPLICATE_ACCOUNT | 
			FILTER_WORKSTATION_TRUST_ACCOUNT | 
			FILTER_SERVER_TRUST_ACCOUNT;
	DWORD dwlevel = 20;	//уровень необходимой информации. 20 == инфа о user.rid
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;	//сколько прочитано юзеов
	DWORD dwTotalEntries = 0;	//сколько их всего
	DWORD dwResumeHandle = 0;	//откуда продолжить чтение
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;

	do{//вызываем NetUserEnum пока не закончатся пользоваели
		nStatus = NetUserEnum(
			pszServerName,//Имя компьютера, при NULL == локальный
			dwlevel,
			filter,	
			(LPBYTE*)&pBuf,
			dwPrefMaxLen,
			&dwEntriesRead,
			&dwTotalEntries,
			&dwResumeHandle);
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)){
			for (i=0; i < dwEntriesRead; i++){
				if ((pTempBuf = pBuf) != NULL){
					for (i=0; i < dwEntriesRead; ++i){
						//printf("%d\t",pTempBuf->usri20_user_id);
						users.push_back(*pTempBuf);
						pTempBuf++;
						dwTotalCount++;
					}
				}
			}
		} else {
			printf("A system error has occured %d\n",nStatus);
		}
		if (pBuf != NULL){
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	}while(nStatus == ERROR_MORE_DATA);//вызываем NetUserEnum пока не закончатся пользоваели
	if (pBuf != NULL){
		NetApiBufferFree(pBuf);
		pBuf = NULL;
	}
	return users;
}

GROUPS_LIST groupsList(){//вернет все группы, аналогично юзерам
	GROUPS_LIST groups;
	GROUP_INFO_2 *pBuf;
	GROUP_INFO_2 *pTempBuf;
	DWORD dwlevel = 2;	//уровень необходимой информации. 2 == инфа о group.rid
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;

	do{//вызываем NetUserEnum пока не закончатся пользоваели
		nStatus = NetGroupEnum(
			pszServerName,
			dwlevel,
			(LPBYTE*)&pBuf,
			dwPrefMaxLen,
			&dwEntriesRead,
			&dwTotalEntries,
			&dwResumeHandle);
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)){
			for (i=0; i < dwEntriesRead; i++){
				if ((pTempBuf = pBuf) != NULL){
					for (i=0; i < dwEntriesRead; ++i){
						//printf("%d\t",pTempBuf->grpi2_group_id);
						groups.push_back(*pTempBuf);
						pTempBuf++;
						dwTotalCount++;
					}
				}
			}
		} else {
			printf("A system error has occured %d\n",nStatus);
		}
		if (pBuf != NULL){
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	}while(nStatus == ERROR_MORE_DATA);//вызываем NetUserEnum пока не закончатся пользоваели
	if (pBuf != NULL){
		NetApiBufferFree(pBuf);
		pBuf = NULL;
	}
	return groups;
}
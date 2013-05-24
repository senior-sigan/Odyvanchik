#include "stdafx.h"
#include "Process.h"

Process::Process(DWORD id)
{
	_id = id;
	_ownerDomain = NULL;
	_ownerName = NULL;
	_pName = NULL;
	_handle = OpenProcess(PROCESS_ALL_ACCESS,FALSE, _id );
	if (_handle == INVALID_HANDLE_VALUE){
		throw(ProcessException("handle error",GetLastError()));
	}

	DWORD dwRtnCode = GetSecurityInfo(//получаем DACL,owner для процесса
		 _handle,
		 SE_KERNEL_OBJECT,
		 DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
		 &_ownerSID,
		 &_ownerGroupSID,
		 &_dacl,
		 NULL,
		 &_psd
	);
	if (dwRtnCode != ERROR_SUCCESS) {
		  throw(ProcessException("GetSecurityInfo error ", GetLastError()));
	}
	ownerNameDomain();	//сразу же получаем все имена
	processNameEx();
	fillAceList(); // и заполняем массив ACE
}
Process::~Process(void)
{
	GlobalFree(_pName);
	LocalFree(_psd);
	GlobalFree(_ownerDomain);
	GlobalFree(_ownerName);
}



void Process::processNameEx(){
	DWORD dwRtnCode = 0;
	DWORD size = 1024;	//Надеемся что влезет
	_pName = (LPSTR)GlobalAlloc(
			  GMEM_FIXED,
			  size);
	if (_pName == NULL) {
		DWORD dwErrorCode = 0;
		dwErrorCode = GetLastError();
		throw(ProcessException("GlobalAlloc error = ",dwErrorCode));
	}
	dwRtnCode = GetProcessImageFileNameA(_handle,_pName,size);
	if (dwRtnCode == 0){
		DWORD error = GetLastError();
		throw(ProcessException("GetProcesImageFileName error ",error));
	}
}
void Process::ownerNameDomain(){
	DWORD dwRtnCode = 0;
	BOOL bRtnBool = TRUE;
	SID_NAME_USE eUse = SidTypeUnknown;
	DWORD size = 1024;

	// Reallocate memory for the buffers.
	_ownerName = (LPTSTR)GlobalAlloc(
			  GMEM_FIXED,
			  size);

	// Check GetLastError for GlobalAlloc error condition.
	if (_ownerName == NULL)
		throw(ProcessException("GlobalAlloc error = ",GetLastError()));

	_ownerDomain = (LPTSTR)GlobalAlloc(
           GMEM_FIXED,
           size);

    // Check GetLastError for GlobalAlloc error condition.
	if (_ownerDomain == NULL)
		  throw(ProcessException("GlobalAlloc error = ", GetLastError()));

    // Second call to LookupAccountSid to get the account name.
	
    bRtnBool = LookupAccountSid(
          NULL,                   // name of local or remote computer
		  _ownerSID,              // security identifier
		  _ownerName,               // account name buffer
          (LPDWORD)&size,   // size of account name buffer 
		  _ownerDomain,             // domain name
          (LPDWORD)&size, // size of domain name buffer
          &eUse);                 // SID type

    // Check GetLastError for LookupAccountSid error condition.
    if (bRtnBool == FALSE) {
          DWORD dwErrorCode = 0;
          dwErrorCode = GetLastError();
          if (dwErrorCode == ERROR_NONE_MAPPED)
			  throw(ProcessException("Account owner not found for specified SID = ",dwErrorCode));
          else 
			  throw(ProcessException("Error in LookupAccountSid = ",dwErrorCode));
	}; 

	_ownerRID = parseRID(_ownerSID);
	return;
}

DWORD Process::parseRID(PSID psd){
	LPSTR sid;
	DWORD rid = 0;
	ConvertSidToStringSidA(psd,&sid);//Превращаем структуру в строку
	std::string ssid(sid);//Теперь char строку превращаем в нормальную string чтобы были методы stoi substr и прочие
	unsigned found = ssid.find_last_of("-");
	rid = std::stoi(ssid.substr(found+1));
	LocalFree(sid);
	return rid;
}

void Process::fillAceList(){ 
	ACL_SIZE_INFORMATION aclSizeInfo;
	ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
    aclSizeInfo.AclBytesInUse = sizeof(ACL);

	ACL_REVISION_INFORMATION aclRevisionInformation;
	ZeroMemory(&aclRevisionInformation,sizeof(ACL_REVISION_INFORMATION));
	GetAclInformation(
		_dacl,
		(LPVOID)&aclRevisionInformation,
		sizeof(ACL_REVISION_INFORMATION),
		AclRevisionInformation);

	DWORD dwRtnCode = GetAclInformation(//Узнаем всю информацию о ACL. - Кол-во ACE  в ней
		_dacl,
		(LPVOID)&aclSizeInfo,
		sizeof(ACL_SIZE_INFORMATION),
		AclSizeInformation);

	if (!dwRtnCode)
		  throw(ProcessException("GetAclInformation error =",GetLastError()));
	
	PVOID pAce;
	for (DWORD i=0;i<aclSizeInfo.AceCount;++i){//По всем ACE
		if (GetAce(_dacl,i,&pAce)){
			switch (((ACE_HEADER*)pAce)->AceType)
			{
			case ACCESS_ALLOWED_ACE_TYPE:
				_allowedACEs.push_back((ACCESS_ALLOWED_ACE*)pAce);
				break;
			case ACCESS_DENIED_ACE_TYPE:
				_deniedACEs.push_back((ACCESS_DENIED_ACE*)pAce);
				break;
			default:
				printf("Undefined type\n");
				break;
			}
		}else
			throw(ProcessException("GetAce ERROR = ", GetLastError()));
	 }
}

BOOL Process::AddAceToProc(DWORD mask,PSID psid){//Здесь происходит очень сильная магия. И я не разобрался до конца почему тут косяки
	//Смысл в том, что нельзя просто так добавить ACE в DACL. 
	//Придется создать DACL бОльшего размера чем предыдущий, и скопировать все в новый из старого.
	//Потом вручную насоздавть структур и сохранить их. 
	//Проблема в том, что почему-то не сохраняется нужный RID. ВЫдается ошибка, что сессия уже используется.
	printf("Adding ace\n");
	BOOL				 bSuccess = FALSE;
	ACCESS_ALLOWED_ACE	*pAce = NULL;
	ACL_SIZE_INFORMATION aclSizeInfo;
	PACL				 pacl;
	PACL				 pNewAcl = NULL;
	PSECURITY_DESCRIPTOR psd = NULL;
	PSECURITY_DESCRIPTOR psdNew = NULL;
	PVOID				 pTemAce;
	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
	DWORD				 dwSidSize = 0;
	DWORD				 dwSidSizeNeeded;
	DWORD				 dwNewAclSize;
	BOOL				 bDaclPresent;
	BOOL				 bDaclExist;
	
	__try{
		if (!GetUserObjectSecurity(
			_handle,
			&si,
			psd,
			dwSidSize,
			&dwSidSizeNeeded)
		)
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER){
			psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
               GetProcessHeap(),
               HEAP_ZERO_MEMORY,
               dwSidSizeNeeded);

			if (psd == NULL){
				printf("psd: %d\n",GetLastError());
				__leave;
			}

			psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
               GetProcessHeap(),
               HEAP_ZERO_MEMORY,
               dwSidSizeNeeded);

			if (psdNew == NULL){
				printf("psdNew : %d\n",GetLastError());
				__leave;
			}

			dwSidSize = dwSidSizeNeeded;

			if (!GetUserObjectSecurity(
				_handle,
				&si,
				psd,
				dwSidSize,
				&dwSidSizeNeeded)
			){
				printf("GetUserObjectSEcurity: %d\n",GetLastError());
				__leave;
			}
		}else{
			printf("Some thing else: %d\n",GetLastError());
			__leave;
		}
		

		if (!InitializeSecurityDescriptor(
			psdNew,
			SECURITY_DESCRIPTOR_REVISION)
		){
			printf("init secur descr: %d\n",GetLastError());
			__leave;
		}

		if (!GetSecurityDescriptorDacl(
            psd,
            &bDaclPresent,
            &pacl,
            &bDaclExist)
		){
			printf("get dacl: %d\n",GetLastError());
			__leave;
		}

		ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse = sizeof(ACL);

		if (pacl != NULL){
			if (!GetAclInformation(
               pacl,
               (LPVOID)&aclSizeInfo,
               sizeof(ACL_SIZE_INFORMATION),
               AclSizeInformation)
			){
				printf("get acl info -size : %d\n",GetLastError());
				__leave;
			}
		}
		
		dwNewAclSize = aclSizeInfo.AclBytesInUse +
			(2*sizeof(ACCESS_ALLOWED_ACE)) + (2*GetLengthSid(psid)) -
            (2*sizeof(DWORD));
		pNewAcl = (PACL)HeapAlloc(
			GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			dwNewAclSize);
		if (pNewAcl == NULL)
			__leave;
		if (!InitializeAcl(pNewAcl,dwNewAclSize,ACL_REVISION)){
			printf("init new acl : %d \n",GetLastError());
			__leave;
		}

		if (bDaclPresent){
         // Copy the ACEs to the new ACL.
			if (aclSizeInfo.AceCount){
				for (DWORD i=0; i < aclSizeInfo.AceCount; i++){
				// Get an ACE.
					if (!GetAce(pacl, i, &pTemAce))
						__leave;
					// Add the ACE to the new ACL.
					if (!AddAce(
					 pNewAcl,
				     ACL_REVISION,
                     MAXDWORD,
					 pTemAce,
					 ((PACE_HEADER)pTemAce)->AceSize)
					){
						printf("add ace in filling: %d",GetLastError());
						__leave;
					}
				}
			}
		}

		pAce = (ACCESS_ALLOWED_ACE *)HeapAlloc(
			GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
		if (pAce==NULL)
			__leave;

		pAce->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
		pAce->Header.AceFlags = CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
		pAce->Header.AceSize = LOWORD(sizeof(ACCESS_ALLOWED_ACE)+GetLengthSid(psid)-sizeof(DWORD));
		pAce->Mask = mask;
//		if(!CopySid(GetLengthSid(psid), &pAce->SidStart, psid)){ //official way to save sid in ace, but strange
//			printf("copy sid : %d\n",GetLastError());
//			__leave;
//		}
		pAce->SidStart = parseRID(psid);
		if(!AddAce(
			pNewAcl,
			ACL_REVISION,
			MAXDWORD,
			(LPVOID)pAce,
			pAce->Header.AceSize)
			)
		{
			printf("add new ace %d\n",GetLastError()); 
			__leave;
		}
		printf("WAIT!!! %d %u     %d\n",pAce->SidStart,pAce->Mask,parseRID(psid));
		if(!SetSecurityDescriptorDacl(
			psdNew,
			TRUE,
			pNewAcl,
			FALSE)
			)
		{
			printf("set dacl %d\n",GetLastError());
			__leave;
		}
		if(!SetKernelObjectSecurity(_handle,si,psdNew)){
			printf("set obj secur %d\n",GetLastError());
			__leave;
		}
		bSuccess = TRUE;		
		printf("Success. added %u for %d\n",pAce->Mask,pAce->SidStart);
	}
	__finally{
		if (pAce != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pAce);

		if (pNewAcl != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

		if (psd != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

		if (psdNew != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
	} 
	return bSuccess;
}

//=======GETTERs==================
LPSTR Process::GetName() const{
	return _pName;
}
LPTSTR Process::GetOwnName() const{
	return _ownerName;
}
LPTSTR Process::GetOwnDomain() const{
	return _ownerDomain;
}
DWORD Process::GetID() const{
	return _id;
}
DWORD Process::GetOwnRID() const{
	return _ownerRID;
}
ALLOWED_ACES Process::GetAllowedACEs() const{
	return _allowedACEs;
}
DENIED_ACES Process::GetDeniedACEs() const{
	return _deniedACEs;
}
PSID Process::GetOwnSID() const{
	return _ownerSID;
}
DWORD Process::mask_for(Process* that) const{
	DWORD mask = 0;
	if (that == this){
		return -1; 
	}
	//parse allowed ace
	
	ALLOWED_ACES that_allowed_aces = that->GetAllowedACEs();
	for (ALLOWED_ACES::const_iterator i = that_allowed_aces.begin(); i != that_allowed_aces.end(); ++i){
		if (this->_ownerRID == i._Ptr->_Myval->SidStart){ 
			mask |= i._Ptr->_Myval->Mask;
		}
	}
	DENIED_ACES that_denied_aces = that->GetDeniedACEs();
	for (DENIED_ACES::const_iterator i = that_denied_aces.begin(); i != that_denied_aces.end(); ++i){
		if (this->_ownerRID == i._Ptr->_Myval->SidStart){ 
			mask ^= i._Ptr->_Myval->Mask;
		}
	}
	return mask;
}
DWORD Process::mask_for_rid(DWORD rid) const{
	DWORD mask = 0;
	
	if (rid == _ownerRID)
		return MAXDWORD;
	
	ALLOWED_ACES::const_iterator aAce;
	for (aAce = _allowedACEs.begin(); aAce != _allowedACEs.end(); ++aAce)
		if (aAce._Ptr->_Myval->SidStart == rid)
			mask |= aAce._Ptr->_Myval->Mask;	//add right to mask
	
	DENIED_ACES::const_iterator dAce;
	for (dAce = _deniedACEs.begin(); dAce != _deniedACEs.end(); ++dAce)
		if (aAce._Ptr->_Myval->SidStart == rid)
			mask ^= dAce._Ptr->_Myval->Mask; // remove right from mask

	return mask;
}


//=====Exceptions========
ProcessException::ProcessException(const char* info, DWORD error){
	_info = info;
	_error = error;
}
void ProcessException::what() const {
	printf("%s = %d\n",_info,_error);
}
ProcessException::~ProcessException(void){
}
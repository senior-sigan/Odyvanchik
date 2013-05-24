#pragma once

typedef std::list<ACCESS_ALLOWED_ACE*> ALLOWED_ACES;
typedef std::list<ACCESS_DENIED_ACE*> DENIED_ACES;

class Process
{
	DWORD				_id;			//PID процесса
	HANDLE				_handle;				
	PSECURITY_DESCRIPTOR _psd;
	PACL				_dacl;
	PACL				_sacl;
	LPSTR				_pName;			//Имя процесса
	LPTSTR				_ownerName;		//Имя владельца процесса
	LPTSTR				_ownerDomain;		
	PSID				_ownerSID;		//SID владельца
	DWORD				_ownerRID;			
	PSID				_ownerGroupSID;	//SID группы
	ALLOWED_ACES		_allowedACEs;	//Лист разрешаюших ACE
	DENIED_ACES			_deniedACEs;	//Лист запрещающих ACE
	
	DWORD parseRID(PSID);		//конвертирует SID в RID, оставляет только последние числа из SID
	void ownerNameDomain();
	void processNameEx();
	void fillAceList();
	
public:
	Process(DWORD id);
	~Process(void);
	BOOL		AddAceToProc(DWORD mask, PSID psid);//Пытаемся добавить свое ACE в лист. Вроде добавляет но для какого то магического RID=1281 
	//=====Getters================
	DWORD		GetID()			const;
	DWORD		GetOwnRID()		const;
	LPSTR		GetName()		const;
	LPTSTR		GetOwnName()	const;
	LPTSTR		GetOwnDomain()	const;
	PSID		GetOwnSID()		const;
	ALLOWED_ACES GetAllowedACEs() const;
	DENIED_ACES GetDeniedACEs()	const;
	DWORD		mask_for(Process* that) const;	//Какие права тот процесс имеет на данный
	DWORD		mask_for_rid(DWORD rid) const;	//Какие права имеет данный юзер на процесс
};
class ProcessException//Класс исключений для процессов
{
	const char* _info;
	DWORD		_error;
public:
	ProcessException(const char*,DWORD);
	~ProcessException(void);
	virtual void what() const;
};

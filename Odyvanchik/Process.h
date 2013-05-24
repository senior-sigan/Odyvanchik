#pragma once

typedef std::list<ACCESS_ALLOWED_ACE*> ALLOWED_ACES;
typedef std::list<ACCESS_DENIED_ACE*> DENIED_ACES;

class Process
{
	DWORD				_id;			//PID ��������
	HANDLE				_handle;				
	PSECURITY_DESCRIPTOR _psd;
	PACL				_dacl;
	PACL				_sacl;
	LPSTR				_pName;			//��� ��������
	LPTSTR				_ownerName;		//��� ��������� ��������
	LPTSTR				_ownerDomain;		
	PSID				_ownerSID;		//SID ���������
	DWORD				_ownerRID;			
	PSID				_ownerGroupSID;	//SID ������
	ALLOWED_ACES		_allowedACEs;	//���� ����������� ACE
	DENIED_ACES			_deniedACEs;	//���� ����������� ACE
	
	DWORD parseRID(PSID);		//������������ SID � RID, ��������� ������ ��������� ����� �� SID
	void ownerNameDomain();
	void processNameEx();
	void fillAceList();
	
public:
	Process(DWORD id);
	~Process(void);
	BOOL		AddAceToProc(DWORD mask, PSID psid);//�������� �������� ���� ACE � ����. ����� ��������� �� ��� ������ �� ����������� RID=1281 
	//=====Getters================
	DWORD		GetID()			const;
	DWORD		GetOwnRID()		const;
	LPSTR		GetName()		const;
	LPTSTR		GetOwnName()	const;
	LPTSTR		GetOwnDomain()	const;
	PSID		GetOwnSID()		const;
	ALLOWED_ACES GetAllowedACEs() const;
	DENIED_ACES GetDeniedACEs()	const;
	DWORD		mask_for(Process* that) const;	//����� ����� ��� ������� ����� �� ������
	DWORD		mask_for_rid(DWORD rid) const;	//����� ����� ����� ������ ���� �� �������
};
class ProcessException//����� ���������� ��� ���������
{
	const char* _info;
	DWORD		_error;
public:
	ProcessException(const char*,DWORD);
	~ProcessException(void);
	virtual void what() const;
};

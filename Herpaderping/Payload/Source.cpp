#include <Windows.h>

int main()
{
	MessageBox(NULL, L"I am the payload!", L"Payload", MB_OK | MB_ICONINFORMATION);
	return 0;
}
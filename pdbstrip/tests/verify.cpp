#include <dia2.h>
#include <atlbase.h>
#include <windows.h>
#include <iostream>

HRESULT CreateDiaSource(const wchar_t* dll, IDiaDataSource** result) {
    HMODULE module = LoadLibraryW(dll);
    if (!module) return HRESULT_FROM_WIN32(GetLastError());
    using DllGetClassObjectFn = HRESULT (STDAPICALLTYPE*)(REFCLSID, REFIID, void**);
    auto getClassObject = reinterpret_cast<DllGetClassObjectFn>(
        GetProcAddress(module, "DllGetClassObject"));
    if (!getClassObject) return HRESULT_FROM_WIN32(GetLastError());
    CComPtr<IClassFactory> factory;
    HRESULT hr = getClassObject(
        __uuidof(DiaSource), __uuidof(IClassFactory),
        reinterpret_cast<void**>(&factory));
    if (FAILED(hr)) return hr;
    return factory->CreateInstance(
        nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void**>(result));
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3 && argc != 4) return 2;
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return 3;

    CComPtr<IDiaDataSource> source;
    CComPtr<IDiaSession> session;
    CComPtr<IDiaSymbol> global;
    HRESULT hr = CreateDiaSource(argv[2], &source);
    if (SUCCEEDED(hr)) hr = source->loadDataFromPdb(argv[1]);
    if (SUCCEEDED(hr)) hr = source->openSession(&session);
    if (SUCCEEDED(hr)) hr = session->get_globalScope(&global);
    if (FAILED(hr)) {
        std::wcerr << L"DIA failed to open " << argv[1] << L": 0x"
                   << std::hex << static_cast<unsigned long>(hr) << L"\n";
        CoUninitialize();
        return 4;
    }

    CComPtr<IDiaEnumSourceFiles> files;
    hr = session->findFile(nullptr, nullptr, nsNone, &files);
    if (FAILED(hr) || !files) {
        std::wcerr << L"DIA failed to enumerate source files: 0x"
                   << std::hex << static_cast<unsigned long>(hr) << L"\n";
        CoUninitialize();
        return 6;
    }
    LONG fileCount = 0;
    hr = files->get_Count(&fileCount);
    if (FAILED(hr)) {
        std::wcerr << L"DIA failed to count source files: 0x"
                   << std::hex << static_cast<unsigned long>(hr) << L"\n";
        CoUninitialize();
        return 6;
    }
    if (fileCount != 0) {
        std::wcerr << L"source files remain: " << fileCount << L"\n";
        CoUninitialize();
        return 6;
    }

    if (argc == 4) {
        CComPtr<IDiaEnumSymbols> functions;
        hr = global->findChildren(
            SymTagFunction, argv[3], nsCaseSensitive, &functions);
        if (FAILED(hr) || !functions) {
            std::wcerr << L"DIA failed to enumerate functions: 0x"
                       << std::hex << static_cast<unsigned long>(hr) << L"\n";
            CoUninitialize();
            return 5;
        }
        LONG functionCount = 0;
        hr = functions->get_Count(&functionCount);
        if (FAILED(hr)) {
            std::wcerr << L"DIA failed to count functions: 0x"
                       << std::hex << static_cast<unsigned long>(hr) << L"\n";
            CoUninitialize();
            return 5;
        }
        if (functionCount == 0) {
            std::wcerr << argv[3] << L" was not retained\n";
            CoUninitialize();
            return 5;
        }
    }

    std::wcout << L"DIA loaded the PDB and found no source files\n";
    CoUninitialize();
    return 0;
}

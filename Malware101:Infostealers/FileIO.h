#pragma once


namespace FileIO
{


    inline std::string GetAppPath()
    {
        CHAR app_data_path[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, app_data_path) == S_OK)
        {
            std::string local_state_path(app_data_path);
            return local_state_path;
        }
        return "";
    }


    inline std::string GetDbPath(BROWSER browser) {
        return GetAppPath() + ACCOUNT_DB_PATHS[browser];
    }

    inline std::string GetLocalState(BROWSER browser)
    {
        return GetAppPath() + LOCAL_STATE_PATHS[browser];
    }

    inline std::string ReadFileToString(const std::string& file_path)
    {
        // Open the file
        HANDLE file_handle = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_handle == INVALID_HANDLE_VALUE)
        {
            // Failed to open the file, return an empty string
            return "";
        }

        // Get the file size
        DWORD file_size = GetFileSize(file_handle, NULL);
        if (file_size == INVALID_FILE_SIZE)
        {
            // Failed to get the file size, close the file handle and return an empty string
            CloseHandle(file_handle);
            return "";
        }

        // Allocate a buffer for the file data
        std::string file_data;
        file_data.resize(file_size);

        // Read the file data into the buffer
        DWORD bytes_read;
        BOOL result = ReadFile(file_handle, &file_data[0], file_size, &bytes_read, NULL);
        CloseHandle(file_handle);
        if (!result || bytes_read != file_size)
        {
            // Failed to read the file data, return an empty string
            return "";
        }

        // Return the file data as a std::string
        return file_data;
    }

    

}
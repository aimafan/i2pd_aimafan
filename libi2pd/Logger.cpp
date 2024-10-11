#include "Logger.h"
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>


// 获取当前时间的字符串表示
std::string GetCurrentTimeString()
{
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S")
       << '.' << std::setw(3) << std::setfill('0') << ms.count();
    return ss.str();
}

// 日志函数的实现
void LogToFile(const std::string &message)
{
    std::ofstream file("./default.log", std::ios::app);
    if (file.is_open())
    {
        file << GetCurrentTimeString() << " ; " << message << std::endl;
        file.close();
    }
    else
    {
        std::cerr << "无法打开日志文件："
                  << "./default.log" << std::endl;
    }
}
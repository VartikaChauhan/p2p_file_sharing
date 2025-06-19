#pragma once
#include <string>
#include <map>

std::map<std::string, std::pair<std::string, int>> loadPeersFromJSON(const std::string& filepath);
bool dfsFileSearch(const std::string& filename, const std::map<std::string, std::pair<std::string, int>>& peers, std::string& foundIP, int& foundPort);

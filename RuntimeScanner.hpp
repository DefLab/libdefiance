/*   _ _ _         _       __ _                      
 *  | (_) |__   __| | ___ / _(_) __ _ _ __   ___ ___ 
 *  | | | '_ \ / _` |/ _ \ |_| |/ _` | '_ \ / __/ _ \
 *  | | | |_) | (_| |  __/  _| | (_| | | | | (_|  __/
 *  |_|_|_.__/ \__,_|\___|_| |_|\__,_|_| |_|\___\___|
 * 
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#ifndef RUNTIMESCANNER_HPP
#define RUNTIMESCANNER_HPP

#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <fstream>
#include <functional>
#include <cstdarg>
#include "RuleParser.hpp"

//#define DEBUG_RUNTIME_PROCESSRULE
#ifdef DEBUG_RUNTIME_PROCESSRULE
#define DEBUG_RUNTIME_PR(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_RUNTIME_PR(x)
#endif

//#define DEBUG_RUNTIME_BASESTR_RULE_SET
#ifdef DEBUG_RUNTIME_BASESTR_RULE_SET
#define DEBUG_RUNTIME_BRS(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_RUNTIME_BRS(x)
#endif

#define PASS -1
#define STOP 403

const std::string empty = std::string();

enum METHOD {
    METHOD_GET = 0,
    METHOD_POST,
    METHOD_PUT,
    UNSUPPORTED_METHOD,
};

static const char *methods[] = {"GET", "POST", "PUT", NULL};

enum CONTENT_TYPE {
    CONTENT_TYPE_UNSUPPORTED = 0,
    CONTENT_TYPE_URL_ENC, // application/x-www-form-urlencoded
    CONTENT_TYPE_MULTIPART, // multipart/form-data
    CONTENT_TYPE_APP_JSON, // application/json
};

enum TRANSFER_ENCODING {
    TRANSFER_ENCODING_UNSUPPORTED = 0,
    TRANSFER_ENCOING_CHUNKED
};

enum LOG_LVL {
    LOG_LVL_EMERG = 0,
    LOG_LVL_ALERT,
    LOG_LVL_CRIT,
    LOG_LVL_ERR,
    LOG_LVL_WARNING,
    LOG_LVL_NOTICE,
    LOG_LVL_INFO,
    LOG_LVL_DEBUG
};

typedef struct {
    std::string zone;
    std::set<unsigned long> ruleId;
    std::string varname;
    std::string content;
} match_info_t; 

class RuntimeScanner {
    friend class JsonValidator;
private:
    RuleParser& parser;
    std::stringstream matchVars;
    unsigned int rulesMatchedCount = 0;
    std::string uri;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<std::pair<std::string, std::string>> get;
    std::string rawContentType;

public:
    METHOD method = UNSUPPORTED_METHOD;
    CONTENT_TYPE contentType = CONTENT_TYPE_UNSUPPORTED;
    TRANSFER_ENCODING transferEncoding = TRANSFER_ENCODING_UNSUPPORTED;
    bool transferEncodingProvided = false;
    unsigned long contentLength = 0;
    bool contentLengthProvided = false;
    std::string body;
    unsigned long bodyLimit = 0;
    bool bodyLimitExceeded = false;
    
    int pid = 0;
    long connectionId = 0;
    std::string threadId;
    std::string clientIp;
    std::string requestedHost;
    std::string serverHostname;
    std::string fullUri;
    std::string protocol;
    std::string softwareVersion;

    LOG_LVL logLevel = LOG_LVL_EMERG;
    void *errorLogFile;
    void *learningLogFile;
    void *learningJSONLogFile;
    
    bool learning;
    bool extensiveLearning;
    bool libinjSQL;
    bool libinjXSS;

    std::unordered_map<std::string, int> matchScores;
    std::unordered_map<std::string, match_info_t> matchInfos;

    bool block = false;
    bool drop = false;
    bool allow = false;
    bool log = false;

    std::function<int(void *file, const void *buf, size_t *len)> writeLogFn;

    RuntimeScanner(RuleParser &parser) : parser(parser) {}
    void setUri(char *uri);
    void addHeader(char* key, char* val);
    void addGETParameter(char* key, char* val);
    void streamToFile(const std::stringstream &ss, void *file);
    int processHeaders();
    int processBody();
    void logg(int priority, void *file, const char *fmt, ...);
    void applyRuleAction(const rule_action_t &rule_action);
    void checkLibInjection(MATCH_ZONE zone, const std::string &name, const std::string &value);
    void basestrRuleset(MATCH_ZONE zone, const std::string &name, const std::string &value,
                        const std::vector<http_rule_t> &rules);
    bool processRuleBuffer(const std::string &str, const http_rule_t &rl, unsigned long &nbMatch);
    void applyCheckRule(const http_rule_t &rule, unsigned long nbMatch, const std::string &name, const std::string &value,
                        MATCH_ZONE zone, bool targetName);
    void applyRuleMatch(const http_rule_t &rule, unsigned long nbMatch, MATCH_ZONE zone, const std::string &name,
                        const std::string &value, bool targetName);
    void writeLearningLog();
    void writeExtensiveLog(const http_rule_t &rule, MATCH_ZONE zone, const std::string &name,
                           const std::string &value, bool targetName);
    void writeJSONLearningLog();
    bool parseFormDataBoundary(unsigned char **boundary, unsigned long *boundary_len);
    void multipartParse(u_char *src, unsigned long len);
    bool contentDispositionParser(unsigned char *str, unsigned char *line_end,
                                  unsigned char **fvarn_start, unsigned char **fvarn_end,
                                  unsigned char **ffilen_start, unsigned char **ffilen_end);
    int processAction();
    bool splitUrlEncodedRuleset(char *str, const std::vector<http_rule_t> &rules, MATCH_ZONE zone);
};

#endif /* RUNTIMESCANNER_HPP */


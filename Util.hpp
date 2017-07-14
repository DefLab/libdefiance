/*   _ _ _         _       __ _                      
 *  | (_) |__   __| | ___ / _(_) __ _ _ __   ___ ___ 
 *  | | | '_ \ / _` |/ _ \ |_| |/ _` | '_ \ / __/ _ \
 *  | | | |_) | (_| |  __/  _| | (_| | | | | (_|  __/
 *  |_|_|_.__/ \__,_|\___|_| |_|\__,_|_| |_|\___\___|
 * 
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#ifndef LIBDEFIANCE_UTIL_H
#define LIBDEFIANCE_UTIL_H

#define UNESCAPE_URI       1
#define UNESCAPE_REDIRECT  2

#include <vector>
#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

static const char *logLevels[] = {"emerg", "alert", "crit", "error", "warn", "notice", "info", "debug", NULL};

// Shell colors
#define KNRM "\x1B[0m"
#define KRED "\x1B[31m"
#define KGRN "\x1B[32m"
#define KYEL "\x1B[33m"
#define KBLU "\x1B[34m"
#define KMAG "\x1B[35m"
#define KCYN "\x1B[36m"
#define KWHT "\x1B[37m"

typedef struct {
    size_t len = 0;
    u_char *data;
} str_t;

namespace Util {
    inline std::string &ltrim(std::string &s) { // trim from start
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
        return s;
    }

    inline std::string &rtrim(std::string &s) { // trim from end
        s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
        return s;
    }

    inline std::string &trim(std::string &s) { // trim from both ends
        return ltrim(rtrim(s));
    }

    inline unsigned long countSubstring(const std::string &str, const std::string &sub) {
        if (sub.length() == 0) return 0;
        unsigned long count = 0;
        for (size_t offset = str.find(sub); offset != std::string::npos;
             offset = str.find(sub, offset + sub.length())) {
            ++count;
        }
        return count;
    }

    inline unsigned long countSubstring(const char *str, size_t len, const char *pattern, size_t patternLen) {
        char *p;
        unsigned long count = 0;
        unsigned long idx = 0;
        while ((p = (char *) memmem(str + idx, len - idx, pattern, patternLen)) != NULL) {
            count++;
            idx = (p - str) + patternLen;
        }
        return count;
    }

    inline unsigned long countSubstring(const char *str, const char *pattern, size_t patternLen) {
        unsigned long count = 0;
        char *p = (char *) str;
        while ((p = strstr(p, pattern)) != NULL) {
            count++;
            p += patternLen;
        }
        return count;
    }

    inline bool caseEqual(const std::string &str1, const std::string &str2) {
        if (str1.size() != str2.size()) {
            return false;
        }
        for (std::string::const_iterator c1 = str1.begin(), c2 = str2.begin(); c1 != str1.end(); ++c1, ++c2) {
            if (tolower(*c1) != tolower(*c2)) {
                return false;
            }
        }
        return true;
    }

    int naxsi_unescape_uri(u_char **dst, u_char **src, size_t size, unsigned int type);

    /* unescape routine, returns number of nullbytes present */
    inline int naxsi_unescape(str_t *str) {
        u_char *dst, *src;
        u_int nullbytes = 0, bad = 0, i;

        dst = str->data;
        src = str->data;

        bad = (u_int) naxsi_unescape_uri(&src, &dst, str->len, 0);
        str->len = src - str->data;
        //tmp hack fix, avoid %00 & co (null byte) encoding :p
        for (i = 0; i < str->len; i++)
            if (str->data[i] == 0x0) {
                nullbytes++;
                str->data[i] = '0';
            }
        return (nullbytes + bad);
    }

    inline char *strnchr(const char *s, int c, unsigned long len) {
        int cpt;
        for (cpt = 0; cpt < len && s[cpt]; cpt++)
            if (s[cpt] == c)
                return ((char *) s + cpt);
        return (NULL);
    }

    std::vector<std::string> split(const std::string &s, char delim);
    std::pair<std::string, std::string> splitAtFirst(const std::string &s, std::string delim);
    std::vector<std::string>
    parseRawDirective(std::string raw_directive);
    std::vector<int> splitToInt(std::string &s, char delimiter);
    std::string apacheTimeFmt();
    std::string naxsiTimeFmt();
    std::string formatLog(int loglevel, const std::string &clientIp);
    std::string escapeQuotes(const std::string &before);
    std::string unescape(const std::string &s);
}

#endif //LIBDEFIANCE_UTIL_H

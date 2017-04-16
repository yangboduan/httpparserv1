#include <string>
#include <boost/regex.hpp>
#include <iostream>

using namespace std;
using namespace boost;

bool onMessageBegin (const char *data){
    regex reg("GET.*");
    if( regex_match(data,reg))
	return 1;
    else
	return 0;
}


string onMessageHost(const string& str){
    regex reg(".*\r\nHost:(.*?)\r\n");
    string::const_iterator start(str.begin()),
                            end(str.end());
    
    match_results<string::const_iterator> what;
 
    if (regex_search(start,end,what,reg,match_default)){
        return what[1];
    }
 
}

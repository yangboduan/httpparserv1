#include <string>
#include <boost/regex.hpp>
#include <iostream>

using namespace std;
using namespace boost;

bool onMessageBegin (const char *data){
    regex reg("GET.*");
    if( regex_match(data,reg))
	cout<<"include GET"<<endl;
}

bool onMessagehost (const char *data){
    regex reg(".*\r\nHost:(.*?)\r\n");
    cmatch what;
    if (regex_match(data,what,reg)){
        cout<<what[1];
    }
}

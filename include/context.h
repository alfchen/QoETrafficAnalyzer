/*
 * framework/context.h
 * PACO
 *
 * Created by: Qi Alfred Chen, 12/09/2013
 *
 */

#ifndef _PACO_CONTEXT_H
#define _PACO_CONTEXT_H

#include "stl.h"

class Context {
private:
	vector<string> appNameMap;
	vector<string> appBehaviorLog;
	int ETHER_HDR_LEN;
public:
    Context();
    void setEtherLen(int etherlen);
    int getEtherLen();
    vector<string> getAppNameMap();
    void addAppName(string appname);
    void clearAppNameMap();
    string getAppNameByIndex(int index);

    vector<string> getAppBehaviorLog();
    void addAppBehavior(string appbehavior);
    void clearAppBehaviorLog();
    string getAppBehaviorByIndex(int index);

};

#endif /* _PACO_CONTEXT_H */

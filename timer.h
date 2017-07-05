/*
 * timer.h
 *
 *  Created on: September 26, 2002
 *      Author: simon10k
 *      SOURCE:	http://www.gamedev.net/community/forums/topic.asp?topic_id=394974&whichpage=1&#2617522
 */
#ifndef _TIMER_
#define _TIMER_

#include <ctime>

class Timer {
    clock_t counter;
public:
    Timer(): counter(0) {};

    bool elapsed(clock_t ms)
    {
        clock_t tick = std::clock();

        if(((tick - counter) % 15000000) >= ms)
        {
             counter = tick;
             return true;
        }

        return false;
    }
};

#endif


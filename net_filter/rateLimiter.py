from cmath import e
from itertools import count
from threading import RLock,Condition
import time,datetime


doc = """
    限流器:
        多线程竞态，并发消费能力，设置最大瞬时并发度+最大区间并发量(比如每1min内只能消费100个，需要使用nextAvaiTime)
"""

class TimeRecord:
    def __init__(self,time_interval = 60) -> None:
        self.record = []
        self.time_interval = time_interval
        self.n = 0
    
    def append(self,amount,insert_back=False):
        time = cur_time_instance()
        start_time = time - self.time_interval
        idx = -1
        for i,tup in enumerate(self.record):
            if start_time>tup[0]:
                idx = i
                continue
            else:
                break

        if insert_back:
            self.record.append((time,amount))
            self.record = self.record[idx+1:] 
            self.n = sum([t[1] for t in self.record])
            return self.n
        else:
            self.record = self.record[idx+1:] 
            self.n = sum([t[1] for t in self.record])
            return self.n+amount
    

def cur_time_instance():
    return time.time()


class RateLimiter():
    def __init__(self,seconds_permits=5,minutes_permits=100) -> None:
        self.seconds_p = seconds_permits
        self.min_p = minutes_permits
        self.second_record = TimeRecord(1)
        self.min_record = TimeRecord(60)
        self.lock = RLock()
        self.next_free_time = cur_time_instance()

    def try_acquire(self,n):
        res = False
        with self.lock:
            can_insert = (self.second_record.append(n)<self.seconds_p) and (self.min_record.append(n)<self.min_p)

            if can_insert:
                self.second_record.append(n,insert_back=True)
                self.min_record.append(n,insert_back=True)
                res = can_insert
        return res

if __name__ == '__main__':
    r = RateLimiter()
    print(r.try_acquire(1))
    print(r.try_acquire(5))
    for i in range(50):
        time.sleep(1)
        print(r.try_acquire(4))



 

    
/*
User space qemu process cpu scheduler based on cpu_usage
*/
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <sched.h>
#include <sstream>
#include <string>
#include <linux/sched.h>

#include "usched.hpp"
#include "cpu.h"
#include "hfi.h"

#define MAX_HISTORY 10
#define test 0

namespace fs = std::filesystem;

const static int nprocs = get_nprocs_conf();
const static int CLK = sysconf(_SC_CLK_TCK);

static std::unordered_map<pid_t, struct pid_info>
    pool; //<<pid>,pid_info/tid_info>
static std::mutex pool_mutex;
static unsigned long long *cpu_prev_stat;
static unsigned int THREASHOLD = 100;

// insert or update tid

bool upsert_to_monitor_pool(pid_t qemu_id, pid_t tid,
                            struct pid_info *_pid_info,
                            struct core_info *_core_map)
{
    if (_core_map == NULL) {
        printf("coer_info ptr null!\n");
        return false;
    }
    if (qemu_id == tid)
        return false;
    std::lock_guard<std::mutex> lock(pool_mutex);
    if (qemu_id == tid) {
        return false;
    }

    std::string path = "/proc/" + std::to_string(qemu_id) + "/task/" +
                       std::to_string((tid)) + "/stat";
    std::ifstream fs(path);
    std::stringstream buffer;
    buffer << fs.rdbuf();
    std::string str;
    std::vector<std::string> data;
    int idx = 0, stateidx = -1;
    std::string state[] = {"R", "S", "D", "Z", "T", "t",
                           "W", "X", "x", "K", "W", "P"};
    while (buffer >> str) {
        data.emplace_back(str);
        if (stateidx == -1) {
            for (std::string s : state)
                if (s.compare(str) == 0)
                    stateidx = idx;
        }
        idx++;
    }
    buffer.clear();
    fs.clear();
    fs.close();

    if (stateidx == -1) {
        return false;
    }
    // calc process usage
    int last_cpu, utime, stime;
    last_cpu = stoi(data[stateidx + TID_STAT_ITEM::PROCESSOR]);
    utime = stoull(data[stateidx + TID_STAT_ITEM::UTIME]);
    stime = stoull(data[stateidx + TID_STAT_ITEM::STIME]);

    if (_pid_info == NULL) { // insert
        struct pid_usage_info pui((double)0, utime, stime);
        struct pid_info tmp(tid, qemu_id, last_cpu, pui);
        pool.insert(std::make_pair(tid, tmp));
        return true;

    } else { // update
        _pid_info->last_cpu = last_cpu;
        _pid_info->_pid_usage_info.percent =
            (double)(utime + stime - _pid_info->_pid_usage_info.utime -
                     _pid_info->_pid_usage_info.stime) *
            100 /
            (_core_map[last_cpu]._total -
             cpu_prev_stat[last_cpu]); // proc_time/per_cpu_time
        _pid_info->_pid_usage_info.utime = utime;
        _pid_info->_pid_usage_info.stime = stime;
        return true;
    }
    return false;
}

void remove_from_monitor_pool(pid_t qemu_id, pid_t tid)
{
    std::lock_guard<std::mutex> lock(pool_mutex);
    for (std::unordered_map<pid_t, struct pid_info>::iterator it = pool.begin();
         it != pool.end();) {
        if (it->second.ppid == qemu_id)
            pool.erase(it);
        else
            it++;
    }
}

void set_usched_threshold(unsigned int num) { THREASHOLD = num; }

void usched_entry(struct core_info *_core_map)
{
    if (_core_map == NULL) {
        printf("coer_info ptr null!\n");
        return;
    }
    if (cpu_prev_stat == NULL) {
        cpu_prev_stat = (decltype(cpu_prev_stat))malloc(
            sizeof(unsigned long long) * nprocs);
        for (int i = 0; i < nprocs; i++) {
            cpu_prev_stat[i] = _core_map[i]._total;
        }
        return;
    }

    for (auto it = pool.begin(); it!=pool.end();++it) {
        upsert_to_monitor_pool(it->second.ppid, it->second._thread_id, &it->second,
                               _core_map);
        pid_t tmpid = usched_check(_core_map, &it->second);

        if (tmpid != -1) {
            if (usched_commit_change(it->first)) {
                printf("usched_change succeed!\n");
            } else
                printf("usched_change failed!\n");

        } else {
            if (it->second.sched == true)
                if (usched_revert_change(it->first))
                    printf("usched_unchanged succeed!\n");
                else
                    printf("usched_unchanged failed!\n");
        }
    }
    for (int i = 0; i < nprocs; i++) {
        cpu_prev_stat[i] = _core_map[i]._total;
    }
}

// check if need to sched, return pthread collection
pid_t usched_check(struct core_info *_core_map, struct pid_info *_pid_info)
{
    printf("pid %d : Thread %d  -> Core %d at %.2f%% utime %lld stime %lld\n", _pid_info->ppid,
           _pid_info->_thread_id, _pid_info->last_cpu,
           _pid_info->_pid_usage_info.percent,
           _pid_info->_pid_usage_info.utime,
           _pid_info->_pid_usage_info.stime);
    if ((int)_pid_info->_pid_usage_info.percent >= THREASHOLD &&
        _core_map[_pid_info->last_cpu].type == INTEL_ATOM) {
        return _pid_info->_thread_id;
    }
    return -1;
}

// commit change
bool usched_commit_change(pid_t _thread_id)
{
    if (set_affinity_byid(_thread_id, pool.find(_thread_id)->second.last_cpu,
                          MASK_DIR::CPUOFF)) {
        pool.find(_thread_id)->second.sched = true;
        pool.find(_thread_id)
            ->second.cpuoff.emplace(pool.find(_thread_id)->second.last_cpu);
    }
    return true;
}

// reverse change
bool usched_revert_change(pid_t _thread_id)
{

    while (pool.find(_thread_id)->second.cpuoff.size() > 0)
        if (set_affinity_byid(_thread_id,
                              pool.find(_thread_id)->second.cpuoff.front(),
                              MASK_DIR::CPUON)) {
            pool.find(_thread_id)->second.cpuoff.pop();
        }
    pool.find(_thread_id)->second.sched = false;
    return true;
}

// affinity get & set <bool,cpu_set_t*>
bool set_affinity_byid(pid_t _thread_id, int cpu_id, enum MASK_DIR md)
{
    switch (md) {
    case CPUON:
        printf("cpu %d affinity set for %d\n", cpu_id, _thread_id);
        break;
    case CPUOFF:
        printf("cpu %d affinity unset for %d\n", cpu_id, _thread_id);
        break;
    default:
        break;
    }
    cpu_set_t *cpumask = CPU_ALLOC(nprocs);
    sched_getaffinity(_thread_id, sizeof(cpumask), cpumask);

    switch (md) {
    case CPUON:
        CPU_SET_S(cpu_id, sizeof(cpumask), cpumask);
        break;
    case CPUOFF:

        CPU_CLR_S(cpu_id, sizeof(cpumask), cpumask);
        break;
    default:
        printf("maskdir err\n");
        return false;
        break;
    }
    if (0 != sched_setaffinity(_thread_id, sizeof(cpumask), cpumask)) {
        printf("set affinity failed\n");
        return false;
    }
    CPU_FREE(cpumask);
    return true;
}

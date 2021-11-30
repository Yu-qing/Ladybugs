import os
import time

ALL_TESTS = {
    "access_control" : ["0.4.10", "0.4.25"],
    "arithmetic" : ["0.4.11", "0.4.15", "0.4.16", "0.4.18", "0.4.19", "0.4.21", "0.4.23", "0.4.25"],
    "bad_randomness" : ["0.4.13", "0.4.16", "0.4.21", "0.4.24", "0.4.25"],
    "denial_of_service" : ["0.4.0", "0.4.15", "0.4.24", "0.4.25"],
    "front_running" :  ["0.4.2", "0.4.16", "0.4.22", "0.4.24"],
    "other" : ["0.4.19"],
    "reentrancy" : ["0.4.0", "0.4.2", "0.4.15", "0.4.18", "0.4.19", "0.4.23",  "0.4.24", "0.4.25"],
    "short_addresses" :  ["0.4.11"],
    "time_manipulation" : ["0.4.15",  "0.4.25"],
    "unchecked_low_level_calls" : ["0.4.9", "0.4.10", "0.4.13", "0.4.16", "0.4.18", "0.4.19", "0.4.23", "0.4.24", "0.4.25", "0.4.26"]
}

start = time.time()
for bug in ALL_TESTS:
    for solc in ALL_TESTS[bug]:
        print("\n", bug, solc)
        solc_cmd = "solc-select use {0}".format(solc)
        tool_cmd = "slither {0}/".format(bug+"/"+solc)
        os.system(solc_cmd + "&&" + tool_cmd)
end = time.time()
print("spend time : ", end-start, "(s)")
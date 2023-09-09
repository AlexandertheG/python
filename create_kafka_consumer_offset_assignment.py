#!/usr/bin/python3
import json

idx = 0
arr = []
result = {"version":1, "partitions":[]}
repl_set = {1, 2, 3}
with open("curr_consumer_offset_assignment.txt") as fd:
    lines = fd.readlines()
    for ln in lines:
        ln = ln.rstrip()
        if ln:
            repl_num = int(ln.split("Isr: ")[1])
            curr_set = {repl_num}
            new_repl_set = repl_set - curr_set
            new_repl_arr = [repl_num]
            new_repl_arr.extend(list(new_repl_set))
            tmp_dict = {"topic":"__consumer_offsets", "partition":idx, "replicas": new_repl_arr}
            result["partitions"].append(tmp_dict)
            arr.append(tmp_dict)
            idx+=1

print(json.dumps(result))

#! /usr/bin/env python3

import json
import re


def tvdump(topic, tvs):
    with open(filename(topic), "w") as f:
        f.write(json.dumps(tvs, indent=2))

    print(json.dumps(tvs, indent=2))


def filename(topic):
    return re.sub(r"[^a-z0-9]+", "-", topic.lower()) + ".json"


header = True
in_tv = False
tv = {}
tvs = []
must_fail = False
with open("../draft-irtf-cfrg-aegis-aead.md") as f:
    for line in f:
        line = line.strip()
        if line == "":
            continue
        if line.startswith("# Test Vectors"):
            header = False
            continue
        if header:
            continue

        if line.startswith("## "):
            if len(tvs) > 0:
                tvdump(topic, tvs)
            topic = line[3:]
            tv_name = topic
            tvs = []
            continue

        if line.startswith("### "):
            tv_name = line[4:]
            tv = {"test": tv_name}
            in_tv = False
            continue

        if line == "~~~ test-vectors":
            in_tv = True
            tv = {"name": tv_name}
            if must_fail:
                tv["error"] = "verification failed"
                must_fail = False
            continue

        if line == "~~~":
            tvs.append(tv)
            in_tv = False
            current_key = None
            continue

        if line.find("verification failed") != -1:
            must_fail = True
            continue

        if line == "After initialization:":
            tv_name = tv_name + " (after initialization)"

        if not in_tv:
            continue

        parts = line.split(":")
        if len(parts) == 2:
            key = parts[0].strip()
            value = parts[1].strip()
            if key == "After Update":
                continue
            if key in tv:
                key = key + "_2"
            tv[key] = value
            current_key = key
            continue

        if not current_key:
            continue

        tv[key] += line.strip()

tvdump(topic, tvs)

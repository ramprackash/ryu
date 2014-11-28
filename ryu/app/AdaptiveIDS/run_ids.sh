#!/bin/sh



export PYTHONPATH=$PYTHONPATH:.

RYUDIR="./ryu"

if [ -d "$RYUDIR" ]; then
    ./bin/ryu-manager --observe-links ryu.app.sdnhub_apps.fileserver ryu.app.sdnhub_apps.host_tracker_rest  ryu.app.rest_topology ryu.app.ofctl_rest ryu/app/AdaptiveIDS/ids_main.py
    #./bin/ryu-manager --observe-links ryu.app.sdnhub_apps.fileserver ryu.app.sdnhub_apps.host_tracker_rest  ryu.app.rest_topology ryu.app.sdnhub_apps.stateless_lb_rest ryu.app.sdnhub_apps.tap_rest ryu.app.ofctl_rest
else
    echo "Run this script from the top level 'ryu' directory as follows:"
    echo "        ./ryu/app/AdaptiveIDS/run_ids.sh"
    exit
fi

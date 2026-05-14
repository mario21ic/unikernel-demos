#!/bin/bash
set -xe

ops image create -c ops-config.json main
ops image list

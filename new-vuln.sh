#!/bin/bash
prev=$(find reports/GO-* | tail -n 1 | sed -n 's/reports\/GO-[0-9]*-\([0-9]*\).toml/\1/p')
new=$(printf "%04d" $(expr $prev + 1))
year=$(date +"%Y")
cp template reports/GO-$year-$new.toml

#!/bin/bash


LINE_LIST=`cat results/meas_#0.out | cut -f1 | cut -d"=" -f2 |sort -gu`

rm plot.dat 2> /dev/null
touch plot.dat

for line in $LINE_LIST; do
  VALUE=""

    METRIC=`cat results/meas_#0.out | grep "LINE=$line " | cut -f2 | cut -d"=" -f2`
    if [[ -z $METRIC ]]; then 
      METRIC=0.0; 
    fi
    VALUE="$VALUE $METRIC"

  echo "$line $VALUE" >> plot.dat
done

echo "call \"plot.gp\"" | gnuplot


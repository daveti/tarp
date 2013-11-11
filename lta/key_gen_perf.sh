# Key generation performance measurement for TARP
# Nov 10, 2013
# daveti@cs.uoregon.edu
# http://davejingtian.org

#!/bin/sh

# Create the log file
touch time_perf.log
touch time_perf_lta.log

# Create the loop
i=1
while [ $i -le 100 ]
do
	./tarp_genkeys perf_$i 1024 1 >> time_perf.log
	i=`expr $i + 1`
done

# Create final perf file
touch time.perf

# Process the log file
grep crypto* time_perf.log | cut -d [ -f2 | cut -d ] -f1 > time.perf

# Create the loop for the LTA ticket generation
j=1
while [ $j -le 100 ]
do
	./lta b8:ca:3a:8e:39:b3 128.223.6.114 ./perf_${j}_priv.txt >> time_perf_lta.log
	j=`expr $j + 1`
done

# Create the final perf file for lta
touch time.lta.perf

# Process the log file
grep crypto* time_perf_lta.log | cut -d [ -f2 | cut -d ] -f1 > time.lta.perf

# Clear the key files
rm -rf perf_*

# Done
echo "key_gen_perf.sh done"

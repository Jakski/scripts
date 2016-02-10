#!/bin/bash

function printUsage {
    echo "Usage: [command] [value] [value]"
}

#declaring amount of CPUs
out=$(ls /sys/devices/system/cpu | grep -c "cpu[[:xdigit:]]")
out=$(( $out-1 )) 

if [ ${1:-null} == "null" ]; then
    printUsage
    exit
fi

case $1 in
    '-s')
        if [ ${2:-null} == "null" ]; then
            if [ $(cat /sys/devices/system/cpu/intel_pstate/no_turbo) == 1 ]; then
                echo 'Intel Turbo Boost turned OFF'
            else
                echo 'Intel Turbo Boost turned ON'
            fi
            echo "Max power:$(cat /sys/devices/system/cpu/intel_pstate/max_perf_pct)"
            echo "Min power:$(cat /sys/devices/system/cpu/intel_pstate/min_perf_pct)"

            echo
            for i in $(eval echo {0..$out})
            do
                echo -n "Core $i governor:"
                cat /sys/devices/system/cpu/cpu$i/cpufreq/scaling_governor
            done

            echo
            if [ "$(whoami)" == "root" ]; then
                for i in $(eval echo {0..$out})
                do
                    freq=$(cat /sys/devices/system/cpu/cpu$i/cpufreq/cpuinfo_cur_freq)
                    freq=$(echo "scale=2;$freq/1000000" | bc)
                    echo "Core $i frequency is: $freq GHz"
                done
            fi
        fi
        ;;
    '-p')
        if [ ${2:-nil} == "nil" ]; then
            cat /etc/cpuoptrc
            exit
        else if [ $(whoami) != "root" ]; then
            echo "Permission denied"
            exit
        fi
    fi
    OIFS=$IFS
    IFS=";"
    exec 0</etc/cpuoptrc
    while read -a line; do
        if [ ${line[0]} != '#' ] && [ ${line[0]} == $2 ]; then
            echo ${line[1]} | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 
            echo ${line[2]} > /sys/devices/system/cpu/intel_pstate/max_perf_pct
            echo ${line[3]} > /sys/devices/system/cpu/intel_pstate/min_perf_pct
            if [ ${line[4]} == "yes" ]; then
                echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo
            else
                echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
            fi
            found=true
            break
        fi
    done 
    if [ "$found" == true ]; then
        echo "Processor adjusted"
    else
        echo "Choosen profile does not exist"
    fi
    exec 0<&-
    IFS=$OIFS
    ;;
'-b')
    if [ ${2:-nil} == "nil" ]; then
        printUsage
        exit
    fi
    if [ $(whoami) != "root" ]; then
        echo "Permission denied"
        exit
    fi
    case $2 in
        'off')
            echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
            ;;
        'on')
            echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo
            ;;
        *)
            printUsage
            exit
            ;;    
    esac
    ;;
*)
    printUsage
    ;;
esac	

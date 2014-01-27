QoETrafficAnalyzer
==================

QoETrafficAnalyzer for T-Mobile Project

##Usage##
 make

 ./qoetranalyzer **<trace list file name>** **<output file folder name>**

##Example##
 ./qoetranalyzer ./sampledata/traceList ./sampledata/output/

The example includes two trace files using AROandAppController under network condition of WiFi and LTE respectively.

The user can (1) generate the the trace files using AROandAppController application (2) use a trace list file to specify which traces are of interest (3) use QoE traffic analyzer to parse the trace files specified tracelist file one by one, and see the output QoE metric in csv format in the output file folder.

RobustNet

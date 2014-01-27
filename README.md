QoETrafficAnalyzer
==================

QoETrafficAnalyzer for T-Mobile Project

##Usage##
To run the get the QoE metrics,  
1. generate the the trace files using AROandAppController application.  
2. use a trace list file to specify which traces are of interest.  
3. use QoE traffic analyzer to parse the trace files specified tracelist file.  
4. see the output QoE metric in csv format in the output file folder.  

###Command###
To run QoE traffic Analyzer:    
 make  
 ./qoetranalyzer <trace list file name> <output file folder name> 

##Example##
 ./qoetranalyzer ./sampledata/traceList ./sampledata/output/

The example includes two trace files using AROandAppController under network condition of WiFi and LTE respectively.



RobustNet

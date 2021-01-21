# Sniffer

## Description

Receives network traffic, extracts features and forms a dataset.

## App.config

```
<add key="PcapName" value="c:\sniffer\pcap\test1.pcap" />
<add key="SessionDir" value="c:\sniffer\sessions\" />
<add key="DatasetName" value="c:\sniffer\dataset\packets_train.csv" />
<add key="DatasetMinifiedName" value="c:\sniffer\dataset\packets_train_minified.csv" />   
```

Directories "c:\sniffer\pcap", "c:\sniffer\sessions", "c:\sniffer\dataset" must be created before starting.

## Run

Sniffer/windows-exe/Sniffer.exe
# 🌟 System Monitoring — High CPU & Memory Usage

A beginner-friendly collection of Splunk searches to monitor high CPU and memory usage on Windows and Linux systems. Each search includes a short description, purpose, and SPL query.

## Windows High CPU/Memory Usage

```spl
# CPU Usage
index=windows sourcetype=Perfmon:CPU | stats avg(CounterValue) by host, Instance_Name

# Memory Usage
index=windows sourcetype=Perfmon:Memory | stats avg(CounterValue) by host
```

## Linux High CPU/Memory Usage

```spl
# CPU Usage
index=linux sourcetype=linux_top | stats avg(cpu) by host, process

# Memory Usage
index=linux sourcetype=linux_sysstat | stats avg(mem_used) by host, process
```

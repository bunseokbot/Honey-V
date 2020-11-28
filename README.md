# Honey-V
Honeypot framework can be able to monitor realtime event based on container

## Usage

### Build
```
go build
./honeypot
```

### Deploy a honeypot

```
./honeypot deploy -n <name of honeypot> -p <host_port:container_port> -i <name of image> -f <Dockerfile> -e <environment>
```

### Monitor honeypot

```
./honeypot monitor
```

### Remove honeypot

```
./honeypot remove -n <name of honeypot>
```

### Event collection mode

```
./honeypot collect -i <interval:60m> -p <path of event storage>
```

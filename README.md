# Anon - Go library to anonymize logs and data

Anon can be used automatically to anonymize IPv4, IPV6 and Domains when you log or write to files.
For automatic log anonymization, use ```anon.Writer```. Here is example:
```go
log.SetOutput(anon.New(os.Stderr))
```
After this line log will be anonymized. Log line 
```
202/12/09 17:21:53 My address is 192.168.1.100
```
will be change to 
```
2023/12/09 17:21:53 My address is IP:9ccm7EXhEmyALzoVm3zjCC9Kbbe
```

To anonymize other types beside IPv4/IPv6/Domain, use ```Hide``` function:
Example:
```go
log.Printf("Issuer: %s; Subject: %s", cert.Issuer, anon.Hide(cert.Subject))
```

If you need some type of data to be anonymized automaticaly, you can add your own anonymizer:
```go
    anon.Add("uuid", regexp.MustCompile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
```
From now on all uuid's in you log file will be anonymized.
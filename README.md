# Anon - Go library to anonymize logs and data

Package anon provides ability to avoid logging sensitive data by anonymizing it automatically using regexes.
Anon supports IPv4, IPv6 and domain names and can be extended to other data types.

## Functions:

### func Add
```golang
func Add(prefix string, regex *regexp.Regexp)
```
Add provides ability to extend list of types of anonymized data as suun as one can provide appropriate regex

### func Hide
```go
func Hide(v any) string
```
Hide - anonymize given value

func SetSalt
```go
func SetSalt(s []byte)
```
SetSalt - set fixed salt value instead generated randomly on each program run.

### type Writer
Writer - io.Writer comply struct that anonymezes all of the date written into it before passing to the next io.Writer.

```go
type Writer struct {
    // contains filtered or unexported fields
}
```

### func New
```go
func New(target io.Writer) Writer
```
New - return new Writer to anonymize all of the data written to target io.Writer.

### func (Writer) Write

```go
func (w Writer) Write(p []byte) (n int, err error)
```
Write - anonymize data and write in to the target io.Writer

## Usage Examples:

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
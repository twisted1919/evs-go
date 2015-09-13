# evs-go
An Email Validation Server written in GO language.  


### install  
```
go get github.com/twisted1919/evs-go
```

### usage
```
$GOPATH/bin/evs-go -help  
```

### notes  
[x] command line flags take priority over the ones from configuration file  
[x] make sure you have RDNS records for your IP(s) running the server
[x] make sure you use -email.from flag to set your from email address  
[x] make sure you use -server.password flag to set a password if the server listens on a public interface  
[x] set -verbose=true and -vduration=true in order to get some debug information
[x] do not abuse this tool, it can be a very useful tool but also can work against you if not used properly

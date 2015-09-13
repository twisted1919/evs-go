# evs-go
An Email Validation Server written in GO language.  
It's purpose is to check each email address if it is valid by checking the MX records and by doing an actual communication with the SMTP server(no email is actual sent).  
The results are not interpreted in any way, is up to you to do it. If the email is valid (see known issues) you will get back a text starting with the OK wording, otherwise, you will get back the exact rejection reason, as shown below:

```php
[status] => success
[message] => Request completed, verified 3 emails in 2.909988133s
[emails] =>
    (
        [contact@mailwizz.com] => OK
        [contact@onetwist.com] => 550 5.1.1 The email account that you tried to reach does not exist. Please try
        [idontexist@mailwizz.com] => 550 5.1.1 <idontexist@mailwizz.com>: Recipient address rejected: User unknown in virtual mailbox table
    )
```

### Install  
```
go get github.com/twisted1919/evs-go
```

### Usage
Start the server with proper flags, use -help to see available options:
```
$GOPATH/bin/evs-go -help  
```
While the server is running, you can connect to it using curl or any other programming language (see examples folder for PHP example) and start shoving emails at it and wait for results.

### Notes  
* command line flags take priority over the ones from configuration file  
* make sure you have RDNS records for your IP(s) running the server  
* make sure you use -email.from flag to set your from email address  
* make sure you use -server.password flag to set a password if the server listens on a public interface  
* set -verbose=true and -vduration=true in order to get some debug information
* do not abuse this tool, it can be a very useful tool but also can work against you if not used properly  


### Known issues  
Some providers, like Yahoo, might report false positives simply because they accept any emails you shive at them. Currently i don't have a workaround for this. feel free to suggest one.


Enjoy.

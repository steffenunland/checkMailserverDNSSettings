# mailserver-check

Takes a mailserver domain, checks relevant records for that domain, and returns the records as well
as whether they were found or not.


## dev usage
`go run main.go -domain domain.tld`

# build
`go build .`

## usage 
`./checkMailserver
mailserver-check

Takes a mailserver domain, checks relevant records for that domain, and returns the records as well
as whether they were found or not.
Commands:  -domain string
    	The domain whose records you want to check.`

e.g.
`./checkMailserver -domain xxxx-xxxx.de`
``
`   OKAY  IP-ADDRESS: 42.42.42.42`
`   OKAY  MX Records: xxxx-us01.mail.protection.outlook.com.`
`   OKAY  SPF Record: v=spf1 include:spf.protection.outlook.com -all`
`   CRITICAL  DKIM Record: Can't find a record`



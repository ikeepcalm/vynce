

                ██╗   ██╗██╗   ██╗███╗   ██╗ ██████╗███████╗
                ██║   ██║╚██╗ ██╔╝████╗  ██║██╔════╝██╔════╝
                ██║   ██║ ╚████╔╝ ██╔██╗ ██║██║     █████╗  
                ╚██╗ ██╔╝  ╚██╔╝  ██║╚██╗██║██║     ██╔══╝  
                 ╚████╔╝    ██║   ██║ ╚████║╚██████╗███████╗
                  ╚═══╝     ╚═╝   ╚═╝  ╚═══╝ ╚═════╝╚══════╝

# Uncover, assess, conquer.

> Vynce is a web vulnerability scanner. It helps you to identify vulnerabilities in your web applications. Packaged as CLI tool!

The name comes as a play on the word “Vince” (a name derived from Vincent, meaning to conquer) and the concept of “vulnerability intelligence.” 

## Usage

```bash
# Show help
java -jar vulnscan.jar --help

# Run a scan
java -jar vulnscan.jar scan https://example.com

# Run with specific tests
java -jar vulnscan.jar scan https://example.com -t SQL,XSS,CSRF

# List reports
java -jar vulnscan.jar report list
```

## License

[MIT License (c) 2025](LICENSE)
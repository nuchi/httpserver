# A simple HTTP server.

I wrote this simple static page HTTP server for fun, directly from raw sockets. It has extremely limited functionality. Don't use it in production. By default, it only accepts local connections on port 8000. This is customizable.

It serves files in the `./www/` directory, relative to the file `httpserver.py`.

Usage:
```bash
$ python httpserver.py
```

## Limitations

`httpserver` only accepts GET requests. It only accepts file paths under ~1000 characters. It will totally ignore all headers. All responses will only include one header: `Content-Length`.

## Further notes

I designed it to be secure against such trickery as `GET /../../../../../etc/passwd`. Please let me know if you find a vulnerability.
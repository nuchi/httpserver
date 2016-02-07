# A simple HTTP server.

I wrote this simple static page HTTP server for fun, directly from raw sockets. It has extremely limited functionality. Don't use it in production. By default, it only accepts local connections on port 8000. This is customizable.

It serves files in the `www/` directory, relative to the file `httpserver.py`.

It will also run cgi scripts placed in the `cgi-bin/` directory. The cgi script should set the `Content-type` header; the server will handle only `Content-length`. The HTTP request headers will be passed to the cgi script as environment variables, after being made upper case and prepended with `CLIENT_`. For example, a header `Content-length: 13` will result in the cgi script having an environment variable `CLIENT_CONTENT_LENGTH` variable set to 13. (The `CLIENT_` is to prevent someone setting the `PATH` variable via a header.)

Usage:
```bash
$ python httpserver.py
```

## Limitations

`httpserver` only accepts GET requests for static files. It will accept GET and POST requests to cgi scripts.

## Further notes

I designed it to be secure against such trickery as `GET /../../../../../etc/passwd`. Please let me know if you find a vulnerability.
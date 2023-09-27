# apache-prosever-nginx
An nsible role that sets up the Nginx web server on a Proserver.

## Configuration options
### security_headers
The default security headers shipped with this role are as follows:

```yaml
nginx_security_headers_default:
  - header: "X-Frame-Options"
    value: "SAMEORIGIN"
    always: yes
  - header: "X-Content-Type-Options"
    value: "nosniff"
    always: yes
  - header: "X-XSS-Protection"
    value: "1; mode=block"
    always: yes
  - header: "Referrer-Policy"
    value: "no-referrer-when-downgrade"
    always: yes
  - header: "Content-Security-Policy"
    value: "frame-ancestors 'self'"
    always: yes
  - header: "Strict-Transport-Security"
    value: >-
      {% if nginx.hsts %}max-age={{ nginx.hsts.max_age }}{% if nginx.hsts.include_subdomains %};includeSubdomains{% endif %}{% if nginx.hsts.preload %}; preload{% endif %}{% endif %}
    always: yes
```

You can use the `nginx.security_headers` variable to either overwrite the values of the default headers, or define new ones. The two variables (`nginx_security_headers_default` and `nginx.security_headers`) will then be merged and templated to `{{ nginx.prefix.config }}/include/security_headers.conf`.

```yaml
nginx:
  security_headers:
    # Will override the default Content-Security-Policy
    - header: "Content-Security-Policy"
      value: "frame-ancestors 'self'; frame-src 'self'"
      always: yes
    # Will be added to the default headers
    - header: "Permissions-Policy"
      value: "geolocation=(self)"
      always: yes
```

### prefix
`nginx.prefix.config`: The configuration directory for Nginx. Defaults to `/etc/nginx` for Linux and `/usr/local/etc/nginx` for FreeBSD.

`nginx.prefix.log`: The directory for Nginx logs

```yaml
nginx:
  prefix:
    config: >-
      {%- if ansible_system == 'Linux' -%}
        /etc/nginx
      {%- else -%}
        /usr/local/etc/nginx
      {%- endif -%}
    log: /var/log/nginx
```

### worker_processes
The number of Nginx worker processes to be spawned. Defaults to 8

```yaml
nginx:
  worker_processes: 8
```

### nameservers, nameservers_valid, nameservers_ipv6

Specifies the resolvers that Nginx will use. Defaults to Cloudflare's IPv6 public DNS

```yaml
nginx:
  nameserver:
    - '[2606:4700:4700::1111]:53'
    - '[2606:4700:4700::1001]:53' 
  nameservers_valid: 300s
  nameservers_ipv6: "on"
```

### server_names_hash_max_size, server_names_hash_bucket_size

Specifies the max size and bucket size for the server names hash. These parameters have no default values but adjusting them may be useful if you use multiple long domain names and/or get this error when trying to run Nginx:

```yaml
nginx: [emerg] could not build the server_names_hash, you should increase server_names_hash_bucket_size
```

Start with a value of 64 and try increasing the value by a power of 2 if you keep getting the error (e.g. 128, 256, 512, etc.)

```yaml
nginx:
  server_names_hash_max_size:
  server_names_hash_bucket_size:
```

### dhparam_bits

Specifies the size of [Diffie-Hellman](https://wiki.openssl.org/index.php/Diffie-Hellman_parameters) parameters to be generated. The default key size in OpenSSL is 1024 bits, which [may be considered insecure by some users](https://web.archive.org/web/20230716110750/https://weakdh.org/). This role sets the default size to 4096. However, a `dhparam.pem` file with 4096 bits may take a long time to generate (as much as one hour on some hardware). Adjust the size according to your needs.

### moved_permanently, redirects

Both `redirects` and `moved_permanently` specify HTTP/HTTPS redirects in the following format:

```yaml
nginx:
  redirects:
    http://example.com: https://www.example.com
    https://example.com: https://www.example.com
```

A different format is also available, allowing you to specify the HTTP code of the redirect. The default redirect code is 301.

```yaml
nginx:
  moved_permanently:
    http://example.com:
      url: https://www.example.com
      code: 307
```

`redirects` and `moved_permanently` can be used **interchangeably**.

### real_ip_header, set_real_ip_from

If your web server is behind a proxy or a load balancer, such as Cloudflare, you will see the Cloudflare proxy IP addresses in your logs, instead of the actual IP addresses of your visitors. 

To fix that, you will need to specify the name of the header that actually carries the actual IP address of the request (`X-Real-IP` by default), as well as the proxy IP addresses that need to be replaced by the original visitors' IPs. For example:

```yaml
nginx:
  real_ip_header: X-Real-IP
  set_real_ip_from: 
    - 192.168.2.1/24
    - 192.168.2.2
    - 2001:0db8::/32;
```

In case of Cloudflare, an up-to-date list of Cloudflare's IP ranges can be found [here](https://www.cloudflare.com/ips/)



# apache-prosever-nginx
An Ansible role that sets up the Nginx web server on a Proserver.

## Dependencies
[ansible-proserver-dehydrated](https://github.com/punktDe/ansible-proserver-dehydrated) is required to manage HTTPS certificates

## Configuration options
### security_headers
The default security headers shipped with this role are as follows:

```yaml
nginx_security_headers_default:
  - header: "X-Frame-Options"
    value: "SAMEORIGIN"
    always: yes
  - header: "Permissions-Policy"
    value: "camera=(self), display-capture=(self), fullscreen=(self), geolocation=(self), microphone=(self), web-share=(self)"
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

```yaml  
nginx:
  dhparam_bits: 4096
```

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

To fix that, you will need to specify the name of the header that actually carries the origin IP address of the request (`X-Real-IP` by default), as well as the proxy IP addresses that need to be replaced by the original visitors' IPs. For example:

```yaml
nginx:
  real_ip_header: X-Real-IP
  set_real_ip_from: 
    - 192.168.2.1/24
    - 192.168.2.2
    - 2001:0db8::/32;
```

In case of Cloudflare, an up-to-date list of Cloudflare's IP ranges can be found [here](https://www.cloudflare.com/ips/)

### proxy_ssl_trusted_certificate

Specifies the CA certificates that will be used to verify upstream TLS. Defaults to `/etc/ssl/certs/ca-certificates.crt` on Linux and `/usr/local/share/certs/ca-root-nss.crt` on other operating systems.

```yaml
nginx:
  proxy_set_trusted_certificate >- 
    {%- if ansible_system == 'Linux' -%}
      /etc/ssl/certs/ca-certificates.crt
    {%- else -%}
      /usr/local/share/certs/ca-root-nss.crt
    {%- endif -%}
```

### hsts

Gives you control over the HSTS policy. The defaults are as follows:

```yaml
nginx:
  hsts:
    max_age: 31536000
    include_subdomains: no
    preload: no
```

### log_format, log_formats

`log_format` lets you choose between `main` and `json` for the log format. Main is the default and is more human-readable out of the box, whereas JSON may be useful for further parsing and processing.

```yaml
nginx:
  log_format: main
```

`log_formats` gives you control over the information written to the logs for each format. By default, only the fields in the JSON format are adjusted:

```yaml
nginx:
  log_formats:
    json:
      fields:
        host: $host
        remote_addr: $remote_addr
        remote_user: $remote_user
        time_iso8601: $time_iso8601
        request_method: $request_method
        request_uri: $request_uri
        server_protocol: $server_protocol
        status: $status
        body_bytes_sent: $body_bytes_sent
        http_referer: $http_referer
        http_user_agent: $http_user_agent
        http_x_forwarded_for: $http_x_forwarded_for
        http_x_real_ip: $http_x_real_ip
        request_id: $request_id
        request_time: $request_time
        bytes_sent: $bytes_sent
        request_length: $request_length
        connection: $connection
        connection_requests: $connection_requests
        sent_http_content_type: $sent_http_content_type
        dnt: $dnt
```

### ansible_info

```yaml
nginx:
  ansible_info:
    server_name:
    private_api:
```

Provides a way to serve the current `inventory_hostname` in a JSON format at the domain name specified by `nginx.ansible_info.server_name`.

The relevant snippet from the `http.d/default.conf` template is as follows:
```jinja2
    location = / {
        add_header Content-Type application/json;
        return 200 '{"inventory_hostname": "{{ inventory_hostname }}"}';
    }
```

If `private_api` is set, the endpoint will additionally expose group names and all HTTPS endpoints at the location specified by the `private_api` variable, as shown in the following `http.d/default.conf` snippet:

```jinja2
    {% if nginx.ansible_info.private_api %}
    location {{ nginx.ansible_info.private_api }} {
        add_header Content-Type application/json;
        return 200 '{"inventory_hostname": "{{ inventory_hostname }}", "groups": {{ group_names|to_json }}, "https_endpoints": {{ (dehydrated.domains.keys()|list + dehydrated.domains.values()|sum(start=[]))|to_json }}}';
    }
    {% endif %}
```

### dynamic_modules_path, dynamic_modules

`dynamic_modules_path` specifies the path to the modules folder. Defaults to `/usr/lib/nginx/modules` on Linux and `/usr/local/libexec/nginx` on other operating systems:

```yaml
nginx:
  dynamic_modules_path: >-
      {%- if ansible_system == 'Linux' -%}
        /usr/lib/nginx/modules
      {%- else -%}
        /usr/local/libexec/nginx
      {%- endif -%}
```

`dynamic_modules` speficies the modules to be loaded. The `ngx_http_headers_more_filter_modules.so` is only loaded on Linux, whereas the `ngx_stream_module.so` is loaded by default on all operating systems:

```yaml
nginx:
  dynamic_modules:
    ngx_http_headers_more_filter_module.so: "{{ false if ansible_system == 'Linux' else true }}"
    ngx_stream_module.so: no
```

### htpasswd

The `httpasswd` parameter allows you to specify basic auth credentials and include them in your configurations. By default, no credentials are specified.

Example:
```yaml
nginx:
  htpasswd:
    example: # the file name for the htpasswd file
      user: password
```

The credentials are provisioned to `{{ nginx.prefix.config }}/include` and can then be then used in your templates and configuration files as follows:
```jinja2
auth_basic_user_file {{ nginx.prefix.config }}/include/example.htpasswd;
```

### stub_status_port

```yaml
nginx:
  stub_status_port:
```

If set, serves a [simple web page](https://nginx.org/en/docs/http/ngx_http_stub_status_module.html) with basic Nginx status data on the specified port.


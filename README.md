# apache-prosever-apache
An Ansible role that sets up Apache on a Proserver.

## Configuration options
### Security headers
The default security headers shipped with this role are as follows:

```
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

```
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

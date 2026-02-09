<!-- BEGIN_ANSIBLE_DOCS -->
<!--
Do not edit README.md directly!

This file is generated automatically by aar-doc and will be overwritten.

Please edit meta/argument_specs.yml instead.
-->
# ansible-proserver-nginx

Nginx role for Proserver

## Supported Operating Systems

- Debian 12, 13
- Ubuntu 24.04, 22.04
- FreeBSD [Proserver](https://infrastructure.punkt.de/de/produkte/proserver.html)

## Role Arguments



An Ansible role that sets up the Nginx web server on a Proserver.

[ansible-proserver-dehydrated](https://github.com/punktDe/ansible-proserver-dehydrated) is required to manage HTTPS certificates.

#### Options for `nginx`

|Option|Description|Type|Required|Default|
|---|---|---|---|---|
| `package` | By default the package 'nginx' will be installed. If you require the smaller version 'nginx-light' you can overwrite the default package name. | str | no | nginx |
| `user` | The user nginx runs as. Defaults to 'www-data' on Linux and 'www' on others. | str | no |  |
| `worker_processes` | The number of Nginx worker processes to be spawned. | int | no | 8 |
| `worker_rlimit_nofile` | Changes the limit on the maximum number of open files (RLIMIT_NOFILE) for worker processes. | int | no |  |
| `prefix` | Paths for configuration and logs. | dict of 'prefix' options | no |  |
| `nameservers` | Specifies the resolvers that Nginx will use. Defaults to Cloudflare's IPv6 public DNS. | list of 'str' | no | ['[2606:4700:4700::1111]:53', '[2606:4700:4700::1001]:53'] |
| `nameservers_valid` | Time for which the resolver results are valid. | str | no | 300s |
| `nameservers_ipv6` | Enables or disables looking up of IPv6 addresses for resolved names. | str | no | on |
| `server_names_hash_max_size` | Specifies the max size for the server names hash. Adjusting this may be useful if you use multiple long domain names. | int | no |  |
| `server_names_hash_bucket_size` | Specifies the bucket size for the server names hash. Start with a value of 64 and try increasing by a power of 2 (128, 256...) if you see '[emerg] could not build the server_names_hash'. | int | no |  |
| `dhparam_bits` | Specifies the size of [Diffie-Hellman](https://wiki.openssl.org/index.php/Diffie-Hellman_parameters) parameters to be generated. The default size is set to 4096. Adjust according to your needs as large keys take time to generate. | int | no | 4096 |
| `proxy_ssl_trusted_certificate` | Specifies the CA certificates that will be used to verify upstream TLS. Defaults to system CA bundle. | path | no |  |
| `security_headers` | Define or override security headers. These are merged with `nginx_security_headers_default` and written to `{{ nginx.prefix.config }}/include/security_headers.conf`. Structure: `- header: 'Name', value: 'Val', always: yes` | list of 'dict' | no | [] |
| `hsts` | Gives you control over the HSTS policy. | dict of 'hsts' options | no |  |
| `default_server` | If true, configures a default server block. | bool | no | True |
| `client_max_body_size` | Sets the maximum allowed size of the client request body. | str | no | 100M |
| `redirects` | Specify HTTP/HTTPS redirects. Format: `http://example.com: https://www.example.com` Can be used interchangeably with `moved_permanently`. | dict | no |  |
| `moved_permanently` | Specify redirects with optional status codes. Format: `http://example.com: { url: https://..., code: 307 }` | dict | no |  |
| `real_ip_header` | The header that carries the origin IP address (useful behind proxies like Cloudflare). | str | no | X-Real-IP |
| `set_real_ip_from` | Dictionary of trusted proxy IP addresses to replace with original visitor IPs. Values are flattened. | dict | no |  |
| `proxy` | Proxy settings. | dict of 'proxy' options | no |  |
| `log_format` | Choose between `main` and `json` log format. | str | no | main |
| `log_formats` | Control information written to logs. Keys are format names. Values can have `fields` (for JSON) or `value` (for raw string). | dict | no |  |
| `modsecurity` | Configuration for [ModSecurity v3](https://github.com/SpiderLabs/ModSecurity). Disabled by default. Activate by setting `enabled: true`. recommended to start with `dry_run: true`. | dict of 'modsecurity' options | no |  |
| `security_txt` | Adds [RFC9116](https://www.rfc-editor.org/info/rfc9116) compliance. If `Contact` is set, creates a compliant endpoint at `/.well-known/security.txt`. | dict of 'security_txt' options | no |  |
| `dynamic_modules_path` | Path to the modules folder. | path | no |  |
| `dynamic_modules` | Specifies which modules to load. Example: `ngx_stream_module.so: no` | dict | no |  |
| `htpasswd` | Specify basic auth credentials. Format: `filename: { user: password }`. Provisioned to `{{ nginx.prefix.config }}/include`. | dict | no |  |
| `stub_status_port` | If set, serves a stub_status page on this port. | int | no |  |
| `mimetypes` | Override or add new mimetypes. Format: `type-name: { key: 'application/x-type', value: ['ext1'] }` | dict | no |  |
| `ansible_info` | Expose inventory hostname and other info via JSON. | dict of 'ansible_info' options | no |  |

#### Options for `nginx.prefix`

|Option|Description|Type|Required|Default|
|---|---|---|---|---|
| `config` | The configuration directory for Nginx. Defaults to `/etc/nginx` for Linux and `/usr/local/etc/nginx` for FreeBSD. | path | no |  |
| `log` | The directory for Nginx logs | path | no | /var/log/nginx |
| `modsecurity` | ModSecurity paths | dict of 'modsecurity' options | no |  |

#### Options for `nginx.prefix.modsecurity`

|Option|Description|Type|Required|Default|
|---|---|---|---|---|
| `config` |  | path | no | /usr/local/etc/modsecurity |
| `log` |  | path | no | /var/log/modsecurity |

#### Options for `nginx.hsts`

|Option|Description|Type|Required|Default|
|---|---|---|---|---|
| `max_age` |  | int | no | 31536000 |
| `include_subdomains` |  | bool | no | False |
| `preload` |  | bool | no | False |

#### Options for `nginx.proxy`

|Option|Description|Type|Required|Default|
|---|---|---|---|---|
| `hide_headers` | List of headers to hide from the upstream response. | list of 'str' | no |  |

#### Options for `nginx.modsecurity`

|Option|Description|Type|Required|Default|
|---|---|---|---|---|
| `enabled` | Activate ModSecurity. | bool | no | False |
| `dry_run` | If true, sets SecRuleEngine to 'DetectionOnly'. If false, set to 'On' (blocking). | bool | no | True |
| `owasp_crs` | OWASP Core Rule Set configuration. | dict of 'owasp_crs' options | no |  |
| `config` | Key-value pairs for `modsecurity.conf`. mostly follows SpiderLabs' recommended settings. | dict | no |  |
| `actions` | Define custom ModSecurity actions. | dict | no |  |
| `rules` | Define ModSecurity rules to be written to `modsecurity.conf`. | dict | no |  |

#### Options for `nginx.modsecurity.owasp_crs`

|Option|Description|Type|Required|Default|
|---|---|---|---|---|
| `enabled` |  | bool | no | True |
| `version` |  | str | no | 3.3.5 |

#### Options for `nginx.security_txt`

|Option|Description|Type|Required|Default|
|---|---|---|---|---|
| `Contact` | Contact information (email, url, etc). | str | no |  |
| `Expires` | Expiration date (defaults to 5 years from now). | str | no |  |
| `Encryption` |  | str | no |  |
| `Acknowledgments` |  | str | no |  |
| `Preferred_Languages` |  | str | no | en |
| `Canonical` |  | str | no |  |
| `Policy` |  | str | no |  |
| `Hiring` |  | str | no |  |
| `CSAF` |  | str | no |  |

#### Options for `nginx.ansible_info`

|Option|Description|Type|Required|Default|
|---|---|---|---|---|
| `server_name` | Domain name to serve the info on. | str | no |  |
| `private_api` | Location path to expose extended info (groups, endpoints). | str | no |  |

#### Choices for main > nginx > log_format

|Choice|
|---|
| main |
| json |

## Dependencies
- dehydrated

## Installation
Add this role to the requirements.yml of your playbook as follows:
```yaml
roles:
  - name: ansible-proserver-nginx
    src: https://github.com/punktDe/ansible-proserver-nginx
```

Afterwards, install the role by running `ansible-galaxy install -r requirements.yml`

## Example Playbook

```yaml
- hosts: all
  roles:
    - name: nginx
```

<!-- END_ANSIBLE_DOCS -->

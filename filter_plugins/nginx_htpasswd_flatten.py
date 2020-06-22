def nginx_htpasswd_flatten(htpasswds: dict) -> list:
    htpasswds_users = []
    for htpasswd, users in htpasswds.items():
        for username, password in users.items():
            crypt_scheme = 'apr_md5_crypt'

            if not isinstance(password, str):
                options = password
                password = options['password']
                if 'crypt_scheme' in options:
                    crypt_scheme = options['crypt_scheme']

            htpasswds_users.append({
                'htpasswd': htpasswd,
                'username': username,
                'password': password,
                'crypt_scheme': crypt_scheme,
            })
    return htpasswds_users


def nginx_htpasswd_flatten_test():
    return nginx_htpasswd_flatten({
        "file1": {
            "user1": "password1",
            "user2": {
                "password": "password2",
                "crypt_scheme": "plaintext"
            }
        },
        "file2": {
            "user2": "password2",
            "user3": {
                "password": "password3"
            }
        },
    }) == [{'htpasswd': 'file1', 'username': 'user1', 'password': 'password1', 'crypt_scheme': 'apr_md5_crypt'},
           {'htpasswd': 'file1', 'username': 'user2', 'password': 'password2', 'crypt_scheme': 'plaintext'},
           {'htpasswd': 'file2', 'username': 'user2', 'password': 'password2', 'crypt_scheme': 'apr_md5_crypt'},
           {'htpasswd': 'file2', 'username': 'user3', 'password': 'password3', 'crypt_scheme': 'apr_md5_crypt'}]


class FilterModule(object):
    def filters(self):
        return {
            'nginx_htpasswd_flatten': nginx_htpasswd_flatten,
        }


if __name__ == '__main__':
    print(nginx_htpasswd_flatten_test())

import ipaddress

def ip_sort(ip_list):
    def sort_key(addr):
        net = ipaddress.ip_network(addr, strict=False)
        return (net.version, int(net.network_address), net.prefixlen)

    return sorted(ip_list, key=sort_key)

class FilterModule:
    def filters(self):
        return {'ip_sort': ip_sort}

import requests
import ipaddress
import time

# ================= НАСТРОЙКИ =================
KEENETIC_URL = "http://10.120.0.1:81/rci/"
INTERFACE = "OpenVPN0"

MIN_PREFIX = 24
BATCH_SIZE = 50
SLEEP = 0.3

ASNS = {
    "meta": 32934,
    "google": 15169,
    "cloudflare": 13335,
}
# =============================================

# ---------- PRIVATE NETWORKS ----------
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]

def is_private(net):
    """Проверяем, полностью ли сеть лежит в приватных диапазонах"""
    for p in PRIVATE_NETS:
        if net.network_address >= p.network_address and net.broadcast_address <= p.broadcast_address:
            return True
    return False

def filter_private(networks):
    return [n for n in networks if not is_private(n)]

# ---------- HTTP POST ----------
def keenetic_post(payload):
    r = requests.post(KEENETIC_URL, json=payload, timeout=120)
    r.raise_for_status()
    return r.json()

# ---------- ASN ----------
def get_as_prefixes(asn):
    url = "https://stat.ripe.net/data/announced-prefixes/data.json"
    r = requests.get(url, params={"resource": f"AS{asn}"}, timeout=60)
    r.raise_for_status()
    nets = [ipaddress.ip_network(p["prefix"]) for p in r.json()["data"]["prefixes"] if ":" not in p["prefix"]]
    return nets

def aggregate(networks):
    collapsed = ipaddress.collapse_addresses(networks)
    return {n for n in collapsed if n.prefixlen <= MIN_PREFIX}

# ---------- KEENETIC ROUTES ----------
def get_current_routes():
    payload = [{"show": {"ip": {"route": {}}}}]
    data = keenetic_post(payload)
    result = set()
    for block in data:
        for r in block.get("show", {}).get("ip", {}).get("route", []):
            if r.get("interface") != INTERFACE:
                continue
            result.add(ipaddress.ip_network(r["destination"], strict=False))
    return result

# ---------- BUILD CMDS ----------
def build_delete_cmd(net):
    if net.prefixlen == 32:
        return {"ip": {"route": {"host": str(net.network_address), "no": True}}}
    return {"ip": {"route": {"network": str(net.network_address), "mask": str(net.netmask), "no": True}}}

def build_add_cmd(net):
    return {"ip": {"route": {"gateway": "", "auto": True, "interface": INTERFACE, "network": str(net.network_address), "mask": str(net.netmask)}}}

def chunked(lst):
    for i in range(0, len(lst), BATCH_SIZE):
        yield lst[i:i + BATCH_SIZE]

# ---------- MAIN ----------
def main():
    print("▶ Получаем ASN-префиксы")
    raw = []
    for name, asn in ASNS.items():
        p = get_as_prefixes(asn)
        print(f"  {name}: {len(p)}")
        raw.extend(p)

    desired = aggregate(raw)
    desired = filter_private(desired)
    desired = set(desired)

    print(f"\n▶ Desired маршрутов: {len(desired)} (после агрегации /{MIN_PREFIX} и фильтра приватных сетей)")

    print("\n▶ Читаем текущие маршруты Keenetic")
    current = get_current_routes()
    current = set(filter_private(current))  # исключаем приватные сети из текущих маршрутов
    print(f"▶ Current OpenVPN0 маршрутов (публичные): {len(current)}")

    to_add = sorted(desired - current)
    to_del = sorted(current - desired)

    print("\n▶ DIFF")
    print(f"  ➕ добавить: {len(to_add)}")
    print(f"  ➖ удалить:  {len(to_del)}")

    # ---- DELETE ----
    if to_del:
        print("\n▶ Удаляем лишние маршруты")
        cmds = [build_delete_cmd(n) for n in to_del]
        done = 0
        for batch in chunked(cmds):
            keenetic_post(batch)
            done += len(batch)
            print(f"  удалено {done}/{len(cmds)}")
            time.sleep(SLEEP)
        for n in to_del:
            print(f"  - {n}")

    # ---- ADD ----
    if to_add:
        print("\n▶ Добавляем новые маршруты")
        cmds = [build_add_cmd(n) for n in to_add]
        done = 0
        for batch in chunked(cmds):
            keenetic_post(batch)
            done += len(batch)
            print(f"  добавлено {done}/{len(cmds)}")
            time.sleep(SLEEP)
        for n in to_add:
            print(f"  + {n}")

    # ---- SAVE CONFIGURATION ----
    print("\n▶ Сохраняем конфигурацию на Keenetic")
    save_payload = [{"system": {"configuration": {"save": {}}}}]
    keenetic_post(save_payload)
    print("✅ Конфигурация сохранена")

    print("\n✅ Синхронизация завершена")

if __name__ == "__main__":
    main()


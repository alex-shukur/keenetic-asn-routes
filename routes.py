import requests
import ipaddress
import time

# ================= НАСТРОЙКИ =================
KEENETIC_URL = "http://10.120.0.1:81/rci/"
INTERFACE = "OpenVPN0"

MIN_PREFIX = 24  # Минимальный префикс для агрегации (не крупнее чем /24)
BATCH_SIZE = 50
SLEEP = 0.3

ASNS = {
    "meta": 32934,
    "google": 15169,
    "cloudflare": 13335,
}

MANUAL_NETWORKS = [
    "149.154.175.50/32",
    "149.154.161.144/32",
]

# =============================================

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
    for p in PRIVATE_NETS:
        if net.subnet_of(p) or net == p:
            return True
    return False

def keenetic_post(payload):
    r = requests.post(KEENETIC_URL, json=payload, timeout=120)
    r.raise_for_status()
    return r.json()

def get_as_prefixes(asn):
    url = "https://stat.ripe.net/data/announced-prefixes/data.json"
    r = requests.get(url, params={"resource": f"AS{asn}"}, timeout=60)
    r.raise_for_status()
    nets = [ipaddress.ip_network(p["prefix"]) for p in r.json()["data"]["prefixes"] if ":" not in p["prefix"]]
    return nets

def aggregate_networks(networks):
    """Агрегирует сети в максимально возможные блоки"""
    collapsed = ipaddress.collapse_addresses(networks)
    return list(collapsed)

def get_current_routes():
    """Получает текущие маршруты из Keenetic"""
    payload = [{"show": {"ip": {"route": {}}}}]
    data = keenetic_post(payload)
    
    current_routes = {}
    for block in data:
        for r in block.get("show", {}).get("ip", {}).get("route", []):
            if r.get("interface") != INTERFACE:
                continue
            
            dest = r.get("destination")
            if not dest:
                continue
            
            try:
                net = ipaddress.ip_network(dest, strict=False)
                if is_private(net):
                    continue
                
                # Сохраняем маршрут
                if net not in current_routes:
                    current_routes[net] = r
            except:
                continue
    
    return current_routes

def is_route_covered_by_current(aggregated_net, current_routes):
    """
    Проверяет, покрывается ли агрегированная сеть существующими маршрутами
    """
    # Для /32 маршрутов (отдельные IP) проверяем точное совпадение
    if aggregated_net.prefixlen == 32:
        return aggregated_net in current_routes
    
    # Получаем все подсети /24 (или меньше, если агрегированная сеть меньше /24)
    prefix_to_check = min(aggregated_net.prefixlen, MIN_PREFIX)
    
    # Разбиваем агрегированную сеть на подсети нужного размера
    try:
        subnets = list(aggregated_net.subnets(new_prefix=prefix_to_check))
    except ValueError:
        # Если сеть меньше MIN_PREFIX, не разбиваем
        subnets = [aggregated_net]
    
    # Проверяем, что каждая подсеть покрыта текущими маршрутами
    for subnet in subnets:
        subnet_covered = False
        
        # Ищем, есть ли маршрут точно на эту подсеть
        if subnet in current_routes:
            subnet_covered = True
        else:
            # Или маршрут, который покрывает эту подсеть (более крупный)
            for current_net in current_routes:
                if subnet.subnet_of(current_net):
                    subnet_covered = True
                    break
        
        if not subnet_covered:
            return False
    
    return True

def find_routes_to_add(desired_aggregated, manual_nets, current_routes):
    """
    Находит, какие агрегированные маршруты нужно добавить
    Ручные маршруты добавляются всегда (если их нет)
    """
    to_add = []
    
    # Сначала обрабатываем ручные маршруты (они добавляются всегда, если отсутствуют)
    print("\n  Проверка ручных маршрутов:")
    for manual_net in manual_nets:
        if manual_net in current_routes:
            print(f"    ✓ {manual_net} уже существует")
        else:
            print(f"    ➕ {manual_net} нужно добавить")
            to_add.append(manual_net)
    
    # Затем обрабатываем агрегированные ASN маршруты
    print("\n  Проверка агрегированных ASN маршрутов:")
    asn_networks = [net for net in desired_aggregated if net not in manual_nets]
    
    for aggregated_net in asn_networks:
        # Если агрегированная сеть уже есть в текущих маршрутах
        if aggregated_net in current_routes:
            print(f"    ✓ {aggregated_net} уже существует")
            continue
        
        # Проверяем, покрывается ли агрегированная сеть текущими маршрутами
        if is_route_covered_by_current(aggregated_net, current_routes):
            print(f"    ⏭️ {aggregated_net} уже покрыт существующими маршрутами, пропускаем")
            continue
        
        # Нужно добавить
        print(f"    ➕ {aggregated_net} нужно добавить")
        to_add.append(aggregated_net)
    
    return to_add

def find_routes_to_remove(desired_aggregated, manual_nets, current_routes):
    """
    Находит, какие маршруты нужно удалить
    Ручные маршруты никогда не удаляются
    """
    to_remove = []
    
    # Создаем множество всех желаемых сетей (включая ручные)
    all_desired = set(desired_aggregated) | set(manual_nets)
    
    for current_net in current_routes:
        # Никогда не удаляем ручные маршруты
        if current_net in manual_nets:
            continue
        
        # Проверяем, не покрывает ли текущий маршрут какой-то из желаемых агрегированных
        is_needed = False
        
        for desired_net in desired_aggregated:
            # Если текущая сеть является подсетью желаемой агрегированной
            if current_net.subnet_of(desired_net):
                is_needed = True
                break
            
            # Или если текущая сеть точно совпадает с желаемой
            if current_net == desired_net:
                is_needed = True
                break
        
        if not is_needed:
            to_remove.append(current_net)
    
    return to_remove

def build_delete_cmd(net):
    if net.prefixlen == 32:
        return {"ip": {"route": {"host": str(net.network_address), "no": True}}}
    return {"ip": {"route": {"network": str(net.network_address), "mask": str(net.netmask), "no": True}}}

def build_add_cmd(net):
    return {"ip": {"route": {"gateway": "", "auto": True, "interface": INTERFACE, 
                             "network": str(net.network_address), "mask": str(net.netmask)}}}

def chunked(lst):
    for i in range(0, len(lst), BATCH_SIZE):
        yield lst[i:i + BATCH_SIZE]

def main():
    print("=" * 60)
    print("Синхронизация маршрутов OpenVPN0")
    print("=" * 60)
    
    # 1. Получаем префиксы от AS
    print("\n▶ Получаем ASN-префиксы")
    all_prefixes = []
    for name, asn in ASNS.items():
        p = get_as_prefixes(asn)
        print(f"  {name}: {len(p)} префиксов")
        all_prefixes.extend(p)
    
    # 2. Агрегируем их
    desired_aggregated = aggregate_networks(all_prefixes)
    print(f"\n▶ После агрегации ASN: {len(desired_aggregated)} сетей")
    for net in list(desired_aggregated)[:10]:
        print(f"    {net}")
    if len(desired_aggregated) > 10:
        print(f"    ... и еще {len(desired_aggregated) - 10}")
    
    # 3. Парсим ручные сети
    print("\n▶ Парсим ручные IP/сети")
    manual_nets = []
    for net_str in MANUAL_NETWORKS:
        try:
            if ":" in net_str and "/" not in net_str:
                ip_part = net_str.split(":")[0]
                net_str = f"{ip_part}/32"
            
            net = ipaddress.ip_network(net_str, strict=False)
            if not is_private(net):
                manual_nets.append(net)
                print(f"    ✓ {net}")
        except ValueError as e:
            print(f"    ⚠️ Ошибка '{net_str}': {e}")
    
    print(f"\n▶ Ручных маршрутов: {len(manual_nets)}")
    
    # 4. Получаем текущие маршруты из Keenetic
    print("\n▶ Читаем текущие маршруты Keenetic")
    current_routes = get_current_routes()
    print(f"▶ Текущих маршрутов: {len(current_routes)}")
    
    # Показываем примеры текущих маршрутов
    if current_routes:
        print("  Примеры текущих маршрутов:")
        for i, net in enumerate(list(current_routes.keys())[:10]):
            print(f"    {net}")
    
    # 5. Определяем, что нужно добавить
    to_add = find_routes_to_add(desired_aggregated, manual_nets, current_routes)
    
    # 6. Определяем, что нужно удалить (ручные никогда не удаляем)
    to_remove = find_routes_to_remove(desired_aggregated, manual_nets, current_routes)
    
    print("\n" + "=" * 60)
    print("▶ РЕЗУЛЬТАТ:")
    print(f"  ➕ добавить: {len(to_add)} маршрутов")
    print(f"  ➖ удалить:  {len(to_remove)} маршрутов")
    
    if to_add:
        print("\n  Маршруты для добавления:")
        for net in to_add:
            print(f"    + {net}")
    
    if to_remove:
        print("\n  Маршруты для удаления:")
        for net in to_remove[:20]:
            print(f"    - {net}")
        if len(to_remove) > 20:
            print(f"    ... и еще {len(to_remove) - 20}")
    
    # 7. Удаляем лишние маршруты
    if to_remove:
        print("\n▶ Удаляем лишние маршруты")
        cmds = [build_delete_cmd(net) for net in to_remove]
        for i, batch in enumerate(chunked(cmds)):
            keenetic_post(batch)
            print(f"  удалено {(i+1)*len(batch)}/{len(cmds)}")
            time.sleep(SLEEP)
    
    # 8. Добавляем новые маршруты
    if to_add:
        print("\n▶ Добавляем новые маршруты")
        cmds = [build_add_cmd(net) for net in to_add]
        for i, batch in enumerate(chunked(cmds)):
            keenetic_post(batch)
            print(f"  добавлено {(i+1)*len(batch)}/{len(cmds)}")
            time.sleep(SLEEP)
    
    # 9. Сохраняем конфигурацию
    if to_add or to_remove:
        print("\n▶ Сохраняем конфигурацию")
        keenetic_post([{"system": {"configuration": {"save": {}}}}])
        print("✅ Конфигурация сохранена")
    else:
        print("\n✅ Изменений не требуется")
    
    print("\n✅ Синхронизация завершена")

if __name__ == "__main__":
    main()

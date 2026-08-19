# Traceflow

> 🇬🇧 English documentation: **[README.en.md](README.en.md)**

Диагностика сетевого пути для overlay-сетей (VXLAN) на базе eBPF.

Traceflow отправляет специально маркированный пакет и наблюдает, через какие
хосты он проходит — как `traceroute`, но видит не только IP-маршрутизацию, а
ещё туннели, VNI и коммутацию на хостах-гипервизорах. eBPF-программа на TC-хуке
каждого интерфейса распознаёт «наш» пакет и порождает **observation** — запись о
том, что пакет прошёл через эту точку. **Коллектор** собирает observations со
всех хостов по общему `id` и восстанавливает полный путь.

## Как распознаётся «наш» пакет — два уровня фильтрации

| Уровень | Проверка | Зачем |
|--------|----------|-------|
| L1 | `DSCP=62` (ToS=`0xF8` в IP-заголовке) | Одна инструкция. 99.99% трафика с другим DSCP отсеивается мгновенно, не читая payload. |
| L2 | magic `0x54464C4F` («TFLO») в payload | DSCP=62 может использовать и чужой трафик; magic гарантирует, что это наш пакет. |

Дополнительно `TTL=255` у отправителя → `hop = 255 - TTL`. L2-коммутация
(OVS-bridge) TTL не меняет: несколько observations на одном L3-хопе имеют
одинаковый `hop`, но разные `node_id`.

## Управляющая структура в payload (`traceflow_meta`, 30 байт)

Лежит сразу за транспортным заголовком (ICMP/UDP/TCP):

| Поле | Размер | Значение |
|------|--------|----------|
| `magic` | 4 | `0x54464C4F` («TFLO»), network byte order |
| `id` | 16 | UUIDv4 — идентификатор запуска, общий для всех хопов |
| `intercept` | 1 | 1 = перехватить пакет (не форвардить) |
| `need_response` | 1 | 1 = ответить обратно |
| `timestamp` | 8 | время отправки (unix ns, little-endian) — для latency |

Контракт по байт-порядку зафиксирован в `internal/tfmeta` и `bpf/traceflow.h` —
менять только синхронно на обеих сторонах.

## Флаги загрузки eBPF

| Флаг | Значения | Смысл |
|------|----------|-------|
| `allow_intercept` | true / false | Разрешено ли дропать пакеты. Tap=true, VXLAN=false |
| `interface_type`  | **auto** / regular / vxlan | Как парсить кадр (по умолчанию `auto`) |

**Гибридный `interface_type`.** Значение по умолчанию — `auto`: eBPF на каждом
пакете (уже после L1-фильтра DSCP, т.е. для 0.01% трафика) пробует распарсить
кадр как VXLAN и, если outer-заголовок не UDP/4789, мгновенно откатывается на
regular. `regular`/`vxlan` — явные режимы без автоопределения, если хочется
детерминизма. В observation всегда пишется **фактически определённый** тип
(`REGULAR`/`VXLAN`), не `auto`.

**Двойной safety guard** — дроп происходит, только если выполнены оба условия:

1. *userspace:* на явном `vxlan`-порту агент принудительно ставит
   `allow_intercept=false`;
2. *ядро (структурно):* eBPF **никогда не дропает VXLAN-инкапсулированный
   пакет**, даже при `allow_intercept=true` в режиме `auto`. Гарантия держится
   на факте инкапсуляции, а не на том, что оператор не забыл флаг.

Итог: `allow_intercept` в `auto`-режиме действует только на «плоские» кадры;
транзитный (инкапсулированный) трафик всегда только наблюдается.

## VXLAN-парсинг

На интерфейсе с `interface_type=vxlan` eBPF видит инкапсулированный кадр:

```
[outer Eth][outer IP][UDP:4789][VXLAN(VNI)][inner Eth][inner IP][L4][traceflow_meta]
```

Программа пропускает outer-заголовки, читает 24-битный VNI, парсит inner IP —
именно там DSCP=62 и `traceflow_meta`. VNI пишется в observation. На
`interface_type=regular` парсинг сразу `[Eth][IP][L4][payload]`. В режиме `auto`
(по умолчанию) выбор делается автоматически по наличию outer UDP/4789 — см.
«Гибридный `interface_type`» выше.

## Компоненты

```
bpf/traceflow.c        eBPF/TC: 2-уровневый фильтр, VXLAN, VLAN, IPv6, ringbuf
bpf/traceflow.h        общие структуры (meta, observation, config, stats)
internal/tfmeta        константы + (де)сериализация + HMAC traceflow_meta
internal/pkt           сборка пакетов Eth/IP{4,6}/ICMP{,v6}/UDP/TCP/VXLAN + чексуммы
internal/observation   декодирование ringbuf-записей -> JSON
internal/ovs           обнаружение OVS/OVN (ovs-vsctl/ovn-nbctl/ovn-sbctl) + парсеры
agent/                 загрузчик eBPF, reader, responder, watchers, метрики, emitter
client/                отправитель marked-пакетов + AF_PACKET-sniffer
collector/             HTTP-коллектор: группировка observations по run id
scripts/               demo-netns.sh, lab-2az-vxlan.sh
tests/                 unit (Go) + интеграционные (netns/veth/VXLAN/OVN)
```

### Agent — по одному на каждый гипервизор

1. Грузит eBPF через `cilium/ebpf` (pure Go, без CGO).
2. Пишет config map: `allow_intercept`, `interface_type`.
3. Attach к TC-хуку (ingress + egress) через TCX.
4. Читает observations из ringbuf в горутине, печатает JSON (indent).
5. **Снимает данные на всём транзите, но отвечает только на dst VM.**
   Observations (шаг 4) пишутся на каждой точке пути независимо. А ответ на
   `need_response=1` строится **только если inner `dst_ip` входит в `--local-ip`**
   этого агента (адреса локальной VM за tap'ом). Транзитные хопы и VTEP/gateway
   (`--local-ip` пуст) — **observe-only**, никогда не отвечают. Так на один probe
   приходит ровно один ответ — от гипервизора назначения. Типы ответов:
   - ICMP → Echo Reply
   - UDP → UDP-ответ
   - TCP → SYN-ACK / data-ответ / FIN-ACK (сессия строится в userspace)
   - VXLAN → инкапсулированный ICMP Reply с тем же VNI

Так как probe адресован **на** VM, при развороте адресов src ответа = MAC/IP
самой VM — то, что ожидает OVN port security.

Ответы уходят через **AF_PACKET** (L2 raw socket) — напрямую в интерфейс, минуя
маршрутизацию ядра. В контейнерной среде это принципиально: пакеты, которые
отправляет сам стек ядра, уходят с `src=собственный IP` и до получателя не
доходят.

### Client — отправитель проб

| Команда | Что делает |
|---------|-----------|
| `icmp`  | ICMP Echo Request (marked). С `--response` ждёт Echo Reply |
| `udp`   | UDP-пакет (marked). С `--response` ждёт UDP-ответ |
| `tcp`   | TCP handshake: SYN → SYN-ACK → ACK |
| `ptcp`  | handshake + data + FIN — полный TCP-диалог |
| `vxlan` | инкапсулированный marked ICMP с заданным VNI |

Отправка IPv4 без VLAN — через AF_INET raw socket с `IP_HDRINCL` (сами ставим
ToS/TTL/payload, маршрутизацию делает ядро). **IPv6 или VLAN** требуют L2-кадра,
поэтому идут через AF_PACKET и нужны флаги `--iface` и `--dst-mac` (плюс
`--vlan N` для тега; `--src-mac` по умолчанию = MAC интерфейса). `--dst` понимает
и IPv4, и IPv6 — семейство определяется автоматически. Приём ответов — через
AF_PACKET sniffer на всех интерфейсах (парсит VLAN и IPv6) с фильтрацией по UUID
запуска, чтобы обойти собственный TCP/UDP-стек ядра.

```bash
# IPv6 ICMPv6 через tap (L2-инъекция)
sudo bin/client icmp --dst fd00::2 --iface tap0 --dst-mac 52:54:00:aa:bb:cc --response
# VLAN-tagged IPv4 проба
sudo bin/client icmp --dst 10.0.0.2 --iface tap0 --dst-mac 52:54:00:aa:bb:cc --vlan 42
```

## Observation

Каждый перехваченный marked-пакет даёт запись:

```json
{
  "id": "3f2b...-uuid",
  "node_id": "hv-07",
  "hop": 1,
  "direction": "INGRESS",
  "vni": 100,
  "action": "FORWARDED",
  "vlan": 42,
  "protocol": "ICMP",
  "ip_version": 4,
  "ifindex": 7,
  "iface": "tap0abc",
  "logical_switch": "ls-tenant-a",
  "az": "az-east-1",
  "src_ip": "10.10.0.1",
  "dst_ip": "10.10.0.2",
  "tcp_flags": "SYN|ACK",
  "iface_type": "VXLAN",
  "timestamp": "2026-08-19T12:00:00.123Z",
  "capture_ns": 51230948120,
  "latency_ns": 351200
}
```

- `timestamp` — wall-clock захвата (агент), `capture_ns` — монотонное время ядра
  (`bpf_ktime_get_ns`) для точного порядка и оценки задержки ringbuf.
- `latency_ns = now_агента − meta.timestamp`, **клампится в 0**; если разница
  отрицательная (рассинхрон часов между хостами), добавляется `clock_skew: true`.
  Достоверна только при PTP; иначе служит грубой оценкой.

## Watch-режим (авто-attach к tap'ам VM)

Вместо статического `--iface` агент умеет сам следить за портами OVS и
подключаться к tap'ам VM по мере их появления:

```bash
sudo bin/agent --watch --node-id hv-07 --metrics-addr :9099
```

Каждые `--watch-interval` (по умолчанию 5s) агент вызывает `ovs-vsctl` и находит
OVN-VIF порты (`external_ids:iface-id`), attach'ит к новым eBPF (ingress+egress),
detach'ит исчезнувшие. Для каждого tap'а IP VM резолвятся из OVN NB
(`ovn-nbctl`, best-effort) и передаются per-tap responder'у как `--local-ip` —
так «отвечает только dst VM» работает без ручной настройки. Если `ovn-nbctl`
недоступен, tap просто наблюдается (observe-only). Требует `ovs-vsctl`/`ovn-nbctl`
в PATH и прав на их сокеты.

### `--watch-vxlan` — per-tenant VXLAN-интерфейсы (меж-AZ) через netlink

Для меж-AZ связности на каждый тенант создаётся отдельный vxlan-netdev (их
создаёт/удаляет OVN или внешний контроллер). `--watch-vxlan` подписывается на
**netlink link events** и событийно attach'ит/detach'ит eBPF на такие устройства
(плюс начальная перечисление уже существующих):

```bash
sudo bin/agent --watch-vxlan --node-id vtep-az1 --metrics-addr :9099
```

Тонкость: на самом vxlan-netdev ядро уже **декапсулировало** — eBPF видит
inner-кадр без outer/VXLAN-заголовка, VNI в пакете нет. Поэтому watcher читает
VNI из атрибутов устройства (`Vxlan.VxlanId`) и кладёт в map `ifindex→VNI`; eBPF
по `skb->ifindex` дописывает VNI в observation (`iface_type=VXLAN`). Наблюдение
только (VTEP не отвечает — ответ приходит с tap'а дальней AZ). Ограничение:
external/`collect_metadata` vxlan-устройства несут VNI per-packet (`VxlanId=0`) и
не покрываются. Режимы комбинируются: `--watch --watch-vxlan` на одном агенте
(iface_type принудительно `auto`, т.к. и tap, и vxlan-netdev дают inner-кадры).

## Аутентификация (HMAC)

`DSCP=62 + magic` подделывается любой VM. `--hmac-key <секрет>` включает
HMAC-SHA256 поверх meta-ядра (30 байт), приписываемый после meta (payload 62 б).
**Responder** проверяет подпись входящего запроса и **не отвечает** без валидного
HMAC (счётчик `traceflow_auth_failures_total`) — это закрывает амплификацию и
спуфинг ответов. Эхо-ответы переподписываются, так что обратный путь тоже
валиден. Клиент подписывает `--hmac-key <тот же секрет>`.

```bash
sudo bin/agent  --iface tap0 --local-ip 10.0.0.2 --hmac-key SECRET
sudo bin/client icmp --dst 10.0.0.2 --hmac-key SECRET --response
```

Ограничение: eBPF HMAC не считает (дорого/непереносимо), поэтому *observations*
для не-VM-адресатов остаются advisory — enforcement на responder'е.

## Коллектор (сборка пути)

`bin/collector` принимает observations по HTTP и группирует их по `run id` —
ключ стабилен даже там, где NAT переписывает 5-tuple, поэтому путь через SNAT/DNAT
собирается как один поток. Агент шлёт с `--collector-url`; `--az` тегирует каждую
запись зоной.

```bash
bin/collector --addr :8080 &
sudo bin/agent --watch --az az-east-1 --collector-url http://collector:8080/
# GET /paths            — список run id со счётчиками
# GET /path?id=<uuid>   — observations прогона, отсортированные по hop и времени
```

### OTLP-экспорт (distributed tracing)

Путь ложится 1:1 на трейс, поэтому агент умеет экспортить прямо в любой
OpenTelemetry-бэкенд (Tempo/Jaeger) — без своего UI:

```bash
sudo bin/agent --watch --az az-1 --otlp-endpoint otel-collector:4318
```

Каждая observation → **span**; run-UUID **и есть** 128-битный **trace_id** (все
точки пути попадают в один трейс); поля → атрибуты (`traceflow.node_id/az/hop/vni/
direction/…`, `source.address`, `destination.address`). Спаны прогона делят
синтетический parent из UUID и упорядочены по атрибуту `hop` (сетевой путь — не
дерево вызовов, коррелируем по trace_id+hop, а не по вложенности). Транспорт —
OTLP/HTTP (protobuf POST на `<endpoint>/v1/traces`, insecure по умолчанию).

## Метрики и health

`--metrics-addr host:port` поднимает HTTP с `/metrics` (Prometheus) и `/healthz`:

| Метрика | Что |
|---------|-----|
| `traceflow_observations_total` | пакетов снято и отправлено в ringbuf (из eBPF, per-CPU) |
| `traceflow_ringbuf_drops_total` | потеряно из-за переполнения ringbuf (reader не успевает) |
| `traceflow_parse_errors_total` | нераспарсенные записи ringbuf |
| `traceflow_ringbuf_read_errors_total` | ошибки чтения ringbuf |
| `traceflow_replies_sent_total` | ответов отправлено responder'ом |
| `traceflow_taps_watched` | tap'ов VM под наблюдением (--watch) |
| `traceflow_vxlan_ifaces_watched` | vxlan-netdev'ов под наблюдением (--watch-vxlan) |

Все с меткой `node="<node-id>"`. Раньше переполнение ringbuf терялось молча —
теперь оно счётчик.

## Сборка

```bash
# Debian/Ubuntu
sudo apt install -y clang llvm libbpf-dev make golang

make deps       # go mod tidy (нужен сеть-доступ к модулям)
make generate   # bpf2go: bpf/traceflow.c -> agent/traceflow_bpf*.go
make build      # -> bin/agent, bin/client
```

Требования рантайма: Linux **≥ 6.6** (TCX attach), запуск от root или с
`CAP_BPF`+`CAP_NET_ADMIN`+`CAP_NET_RAW`.

## Контейнер (rootless podman)

Образ собирается **rootless** — multi-stage: builder ставит clang/llvm/libbpf,
компилирует eBPF через bpf2go, гоняет unit-тесты и собирает бинарники; рантайм —
`debian-slim` с `iproute2`/`jq` и бинарниками. Зелёная сборка = unit-тесты
прошли.

```bash
make image          # podman build -t traceflow:latest -f Containerfile .
podman run --rm traceflow:latest help

# агент внутри контейнера (нужны BPF+net-права)
podman run --rm --privileged --net=host traceflow:latest \
    agent --iface eth0 --node-id hv-01
```

> **Про rootless и eBPF.** Сборка образа и unit-тесты работают полностью
> rootless. А вот загрузка eBPF (BPF_PROG_LOAD + TCX) и `ip netns exec` из
> user-namespace ядро обычно **не разрешает** (`mount of /sys failed`,
> `operation not permitted`). Интеграционные тесты это детектируют и выдают
> **SKIP**, а не FAIL. Для реального прогона нужен rootful podman (`sudo podman
> run --privileged …`) или запуск на хосте.

## Тесты

**Unit (без прав, без ядра)** — сериализация `traceflow_meta`, чексуммы и сборка
пакетов, декодирование observation, и guard-проверка размеров структур (30 / 48
байт — контракт с C):

```bash
make test        # go test ./internal/...
```

**Интеграционные (нужны CAP_NET_ADMIN + BPF)** — поднимают реальные топологии на
network namespaces и проверяют observations от настоящего eBPF:

```bash
make itest                                   # на хосте (root)
podman run --rm --privileged traceflow:latest itest   # или в rootful-контейнере
```

- `tests/test_veth_multinetns.sh` — цепочка `ns1 — ns2(router) — ns3` через veth.
  Маркированный ICMP идёт ns1→ns3; проверяется, что на ingress роутера `hop=0`
  (TTL=255), на egress после форвардинга `hop=1` (TTL уменьшился), а на ns3 —
  снова `hop=1`; один `id` коррелирует observations с разными `node_id`. Это ровно
  правило спеки: L2 внутри подсети `hop` не меняет, L3-роутер увеличивает.
- `tests/test_vxlan.sh` — underlay `ns-a — ns-b` через veth; клиент шлёт
  VXLAN-инкапсулированный marked ICMP (VNI=100), агент на underlay видит
  `vni=100`, `iface_type=VXLAN`. Гоняется дважды — `--iface-type vxlan` и `auto`
  — чтобы доказать, что гибрид детектит инкапсуляцию так же, как явный режим.
  Отдельно проверяется структурный guard: пакет с `--intercept` при
  `--allow-intercept` всё равно `FORWARDED`, потому что он инкапсулирован.
- `tests/test_ipv6_vlan.sh` — ICMPv6 через veth (L2-инъекция, ответ v6) и
  VLAN-tagged ICMP (тег 42 снят `parse_l2`).
- `tests/test_watch_vxlan.sh` — два VXLAN-VTEP над veth; агент в nsB с
  `--watch-vxlan` (netlink). Проверяет: авто-attach существующего vxlan0 на
  старте; marked ICMP через overlay наблюдается с device-VNI `vni=100`,
  `iface_type=VXLAN`; динамический `RTM_NEWLINK` (создание vxlan101) → attach;
  `RTM_DELLINK` (удаление vxlan0, как это делает OVN) → detach.
- `tests/test_hmac.sh` — подписанный probe получает ответ, неподписанный
  отклоняется (проверка по метрикам `replies_sent`/`auth_failures`).
- `tests/test_clsact.sh` — классический clsact/cls_bpf fallback
  (`TRACEFLOW_FORCE_CLSACT=1`): фильтр реально в `tc filter`, observation снята.
- `tests/test_xdp.sh` — XDP-путь attach (`--xdp`): программа реально на netdev,
  observation на ingress.
- `tests/test_vxlan_2az.sh` — **два шасси в двух AZ через VXLAN, без veth** (нужен
  запущенный OVS). См. ниже.

Тесты, не сумевшие загрузить eBPF/создать netns (или без OVS для 2az), выходят с
кодом `77` (SKIP); итоговый прогон падает только на настоящих провалах ассертов.

## Стенд 2 AZ через VXLAN (без veth)

Два шасси (гипервизора) в двух AZ, соединённых VXLAN, **без единого veth**:
межшассийный underlay — на **OVS internal-портах** (реальные kernel-netdev'ы, не
veth), inter-AZ overlay — kernel VXLAN-устройство.

```
 host: OVS br-underlay  (обычный L2-свитч)
          ula ── в ns az1                 ulb ── в ns az2
 az1 (AZ1): ula 172.16.9.1  vxlan0(id100) 10.0.0.1 (VM-A)
 az2 (AZ2): ulb 172.16.9.2  vxlan0(id100) 10.0.0.2 (VM-B)

 marked ICMP VM-A → VM-B, один run id, три точки наблюдения:
   (1) overlay-netdev VM-A  (device vni=100)
   (2) inter-AZ VXLAN на underlay  (packet vni=100, outer Eth/IP/UDP/VXLAN)
   (3) overlay-netdev VM-B  (device vni=100)
```

```bash
sudo ovs-ctl start
sudo ./scripts/lab-2az-vxlan.sh up
sudo ./scripts/lab-2az-vxlan.sh agents &
sudo ./scripts/lab-2az-vxlan.sh probe
sudo ./scripts/lab-2az-vxlan.sh down
```

OVS internal-порт — это реальный kernel-netdev, остающийся в OVS-
datapath даже после переноса в netns, так что два netns-«шасси» соединяются через
host-datapath без veth. (`ovs-sandbox`/`make sandbox` использует **dummy**
datapath — реальных пакетов через kernel-netdev'ы там нет, eBPF/TC их не видят.)

## Быстрый локальный тест (network namespaces)

```bash
sudo ./scripts/demo-netns.sh up        # ns1(10.10.0.1) <-> ns2(10.10.0.2)
sudo ./scripts/demo-netns.sh agent &   # агент в ns2 на veth2 (regular)
sudo ./scripts/demo-netns.sh probe     # marked ICMP из ns1 с --response
sudo ./scripts/demo-netns.sh down
```

Агент напечатает observations (ingress/egress), клиент дождётся Echo Reply.

## Примеры вызова

```bash
# ICMP-проба с ответом
sudo bin/client icmp --dst 10.0.0.5 --response

# UDP-проба на порт 5000
sudo bin/client udp --dst 10.0.0.5 --dport 5000 --response

# Проверка доступности TCP-порта (handshake)
sudo bin/client tcp --dst 10.0.0.5 --dport 443

# Полный TCP-диалог
sudo bin/client ptcp --dst 10.0.0.5 --dport 443

# Перехват пакета на tap-порту (агент с --allow-intercept)
sudo bin/client icmp --dst 10.0.0.5 --intercept

# VXLAN-проба в сегменте VNI=100
sudo bin/client vxlan --dst 192.168.1.10 \
     --inner-src 10.0.0.1 --inner-dst 10.0.0.2 --vni 100 --response

# Агент на tap'е VM назначения: снимает данные И отвечает за локальную VM
sudo bin/agent --iface tap0abc --node-id hv-dst --local-ip 10.0.0.2

# Транзитный / VTEP-агент: observe-only (нет --local-ip -> никогда не отвечает)
sudo bin/agent --iface eth0 --iface-type vxlan --node-id vtep-az2

# Агент в авто-режиме (по умолчанию): сам различает VXLAN и plain по пакету,
# инкапсулированный трафик не дропает даже с --allow-intercept
sudo bin/agent --iface eth0 --node-id hv-07 --allow-intercept

# Инъекция как исходная VM: src IP/MAC берутся из OVS-tap'а (OVN port security)
sudo bin/client icmp --dst 10.0.0.2 --iface tap0abc --dst-mac <gw-mac> --as-vm --response
```

## Заметки по реализации / ограничения

- **TCP в userspace.** Responder ведёт TCP как минимальный, но
  **seq-корректный** автомат с состоянием по 4-tuple (SYN→SYN/ACK, data→ACK+echo
  с продвижением seq, FIN→FIN/ACK; server ISN детерминирован из 4-tuple).
  Отключается `--tcp-respond=false` — тогда отвечает реальный стек VM (без
  дублей на живой сервис). Ядро может слать RST на наши потоки — на наблюдение не
  влияет; для «чистого» стенда — отдельный namespace или drop RST в iptables.
- **Портируемость по ядрам.** Attach: сначала **TCX** (ядро ≥6.6), при
  неподдержке — автоматический fallback на классический **clsact + cls_bpf**
  через netlink (работает примерно с 4.5). Байткод один и тот же — программа
  трогает только стабильный UAPI (`__sk_buff` и байты пакета), поэтому CO-RE
  релокации не нужны. clsact-путь проверяется вживую даже на новом ядре:
  `TRACEFLOW_FORCE_CLSACT=1` форсит fallback (см. `tests/test_clsact.sh` —
  фильтр виден в `tc filter`, снимается чисто при остановке).
- **latency_ns** считается как `now_агента - meta.timestamp`, зависит от
  синхронизации часов (PTP); клампится в 0, при отрицательной разнице — флаг
  `clock_skew`. `capture_ns` — монотонное время ядра для порядка/оценки задержки
  ringbuf.
- **IPv6 и VLAN.** Парсер eBPF снимает IPv4 и IPv6 (inner и outer у VXLAN — обе
  семьи), пропускает до двух 802.1Q/802.1AD тегов из тела кадра **и** читает
  `skb->vlan_tci` на случай VLAN-offload (когда NIC вынес тег в метаданные skb, а
  не в байты); пишет `vlan`/`ip_version` в observation. Симметрично **responder**
  включает `PACKET_AUXDATA` и достаёт снятый тег из aux-data, чтобы вернуть ответ
  с правильным VLAN. DSCP=62 проверяется и в IPv4 ToS, и в IPv6 traffic class.
  IPv6 extension headers пропускаются (ограниченный обход Hop-by-Hop/Routing/
  Dest-Opts/Fragment); не-первый фрагмент без транспортного заголовка не маркается.
- **collect_metadata VXLAN.** Для external/collect_metadata vxlan-устройств
  (VNI per-packet, `VxlanId=0`) eBPF берёт VNI из `bpf_skb_get_tunnel_key`, а не
  из map устройства.
- **ifindex/AZ/logical_switch.** В observation пишется `ifindex` (+ имя интерфейса)
  источника; агент добавляет `--az` и резолвит `logical_switch` из OVN SB DB
  (VNI→Datapath_Binding, best-effort).
- **Ответы-эхо** отправляются с очищенными `intercept`/`need_response`, чтобы не
  вызвать бесконечный обмен между двумя responder-ами, но остаются marked — путь
  обратного направления тоже наблюдается.

## OVS-DPDK / AF_XDP

При OVS-DPDK datapath в userspace, и TC-путь может не видеть трафик:

- **OVS с `type=afxdp`** — NIC остаётся kernel-netdev'ом, но OVS вешает XDP-
  программу, которая `XDP_REDIRECT`'ит кадры в AF_XDP-сокет **до** TC-хука, так
  что TC их не видит. Флаг `--xdp` вешает тот же двухуровневый фильтр/парсеры на
  **XDP-хук** (он раньше), пишет те же observations и возвращает `XDP_PASS`
  (OVS получает кадр). Native-режим с откатом на generic (SKB).

  ```bash
  sudo bin/agent --xdp --iface eth0 --node-id hv-01
  ```

  Ограничения: XDP только ingress; один XDP-прог на netdev (для сосуществования
  с XDP OVS нужен `xdp-dispatcher`/libxdp).

- **OVS-DPDK с DPDK PMD (vfio-pci)** — NIC целиком у userspace-драйвера, kernel-
  netdev'а **нет вообще**, ни TC, ни XDP не прицепить; нужен OVS mirror-порт /
  нативный OVS-трейс (вне рамок).
- **vhost-user порты VM** — VM через unix-сокет + shared memory, netdev'а нет,
  eBPF на порту наблюдать не может в принципе.
```

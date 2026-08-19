# Traceflow

> 🇬🇧 English documentation: **[README.en.md](README.en.md)**

Диагностика сетевого пути для overlay-сетей (VXLAN) на базе eBPF.

Traceflow отправляет специально **маркированный** пакет и наблюдает, через какие
хосты он проходит — как `traceroute`, но видит не только IP-маршрутизацию, но и
туннели, VNI и коммутацию на хостах-гипервизорах. eBPF-программа на TC-хуке
каждого интерфейса распознаёт «наш» пакет и порождает **observation** — запись о
том, что пакет прошёл через эту точку. **Коллектор** собирает observations со
всех хостов по общему `id` и восстанавливает полный путь.

```
 client                      hypervisor A                 hypervisor B
 ┌─────────┐   marked pkt    ┌────────────┐   overlay    ┌────────────┐
 │  client │ ───────────────▶│ agent+eBPF │ ────────────▶│ agent+eBPF │
 └─────────┘  DSCP62+magic   │  TC hook   │   VXLAN/tap  │  TC hook   │
      ▲                      └─────┬──────┘              └─────┬──────┘
      │        observations        │  ringbuf                  │
      │        (JSON / HTTP)        ▼                           ▼
      └──────────────────────  collector  ◀──────────────  (by run id)
```

## Как распознаётся «наш» пакет — два уровня фильтрации

| Уровень | Проверка | Зачем |
|---------|----------|-------|
| L1 | `DSCP=62` (ToS `0xF8` в IP-заголовке) | Одна инструкция. 99.99% трафика с другим DSCP отсеивается мгновенно, не читая payload. |
| L2 | magic `0x54464C4F` («TFLO») в payload | DSCP=62 может использовать и чужой трафик; magic гарантирует, что это наш пакет. |

Дополнительно `TTL=255` у отправителя, поэтому `hop = 255 - TTL`. L2-коммутация
TTL не меняет: несколько observations на одном L3-хопе имеют одинаковый `hop`, но
разные `node_id`. Опционально маркер аутентифицируется через **HMAC** (см. ниже).

## Управляющая структура в payload (`traceflow_meta`, 30 байт)

Лежит сразу за транспортным заголовком (ICMP/UDP/TCP):

| Поле | Размер | Значение |
|------|--------|----------|
| `magic` | 4 | `0x54464C4F` («TFLO»), network byte order |
| `id` | 16 | UUIDv4 — идентификатор запуска, общий для всех хопов |
| `intercept` | 1 | 1 = перехватить пакет (не форвардить) |
| `need_response` | 1 | 1 = ответить обратно |
| `timestamp` | 8 | время отправки (unix ns, little-endian) — для latency |

С `--hmac-key` поверх этих 30 байт приписывается HMAC-SHA256 (payload = 62 байта).

## Модель наблюдения — tap vs VXLAN

Две точки attach, соответствующие реальному деплою OVN/OVS:

```
  intra-AZ (tap model)                         inter-AZ (VXLAN)
  agent on the VM tap                          agent on the underlay / vxlan netdev

  VM ──tap──▶ [eBPF] ──▶ OVS ──Geneve──▶ ...    ... ──▶ [eBPF] ──▶ VXLAN ──▶ other AZ
       inner frame, DSCP+magic visible               outer Eth/IP/UDP/VXLAN + inner
       iface_type=REGULAR                            iface_type=VXLAN, VNI from wire
```

- **Regular / tap** (`iface_type=regular`): `[Eth][VLAN?][IPv4/IPv6][L4][meta]`.
  Внутренний (tenant) кадр — до инкапсуляции / после декапсуляции.
- **VXLAN underlay** (`iface_type=vxlan`): агент пропускает outer
  `Eth/IP/UDP:4789/VXLAN`, извлекает 24-битный VNI и парсит inner-кадр.
  Outer может быть IPv4 или IPv6.
- **VXLAN netdev** (per-tenant устройство): ядро уже декапсулировало, поэтому
  eBPF видит inner-кадр без VNI в байтах. Netlink-watcher читает VNI устройства
  (`Vxlan.VxlanId`) в map по ключу `ifindex`; eBPF тегирует observation по
  `skb->ifindex`. Устройства `collect_metadata` (VNI per-packet) покрываются через
  `bpf_skb_get_tunnel_key`.
- **`auto`** (по умолчанию): на каждый пакет — попытка VXLAN, откат на regular.

## Флаги загрузки и safety-guard'ы

| Флаг | Значения | Смысл |
|------|----------|-------|
| `allow_intercept` | true / false | Можно ли дропать пакеты. Tap=true, VXLAN=false |
| `interface_type` | **auto** / regular / vxlan | Как парсить (по умолчанию `auto`) |

Два независимых guard'а: пакет дропается, только если `intercept` запрошен **и**
attach это разрешает **и** (в ядре) пакет не VXLAN-инкапсулирован — так
транзитный/туннельный трафик всегда только наблюдается.

## Agent — по одному на каждый гипервизор

1. Грузит eBPF через `cilium/ebpf` (pure Go, без CGO).
2. Пишет config map (`allow_intercept`, `interface_type`).
3. Прикрепляет observation-программу. По умолчанию — **TC-хук** (ingress+egress):
   **TCX** на ядре ≥6.6, с автоматическим откатом на классический
   **clsact + cls_bpf** через netlink (примерно с 4.5). С `--xdp` прикрепляется к
   **XDP-хуку** (только ingress) — см. *OVS-DPDK / AF_XDP* ниже.
4. Читает observations из ring buffer и печатает JSON (или шлёт в коллектор).
5. **Отвечает только за dst VM.** Observations снимаются на каждом хопе; ответ на
   `need_response=1` строится, только если inner `dst_ip` — локальный адрес VM
   (`--local-ip` или резолвит watcher). Транзитные/VTEP-узлы — observe-only. TCP —
   маленький, seq-корректный userspace-responder (`--tcp-respond=false` отдаёт
   ответ реальному стеку VM).

Ответы уходят через **AF_PACKET** (L2 raw socket), минуя маршрутизацию ядра;
разворот адресов переиспользует MAC/IP самой VM — то, что ожидает OVN port
security.

### Динамический attach (watch-режимы)

- `--watch` — находит OVN VM-tap'ы через `ovs-vsctl` (`external_ids:iface-id`),
  attach'ит/detach'ит eBPF по мере появления/исчезновения VM, резолвит IP каждой
  VM из OVN NB DB (`ovn-nbctl`, best-effort), так что responder отвечает
  автоматически.
- `--watch-vxlan` — следит за per-tenant VXLAN-netdev'ами через **netlink** link
  events (создаются/удаляются OVN или любым контроллером) и тегирует observations
  VNI устройства.

## Client — отправитель проб

| Команда | Что |
|---------|-----|
| `icmp` | ICMP / ICMPv6 echo (`--response` ждёт ответ) |
| `udp` | UDP-датаграмма |
| `tcp` | TCP handshake: SYN → SYN/ACK → ACK |
| `ptcp` | handshake + data + FIN — полный диалог |
| `vxlan` | VXLAN-инкапсулированный marked ICMP с заданным VNI |

IPv4 без VLAN отправляется через AF_INET raw socket (`IP_HDRINCL`). IPv6 или VLAN
требуют L2-кадра, поэтому идут через AF_PACKET (`--iface` + `--dst-mac`, `--vlan`).
`--as-vm` заполняет source IP/MAC из OVS-tap'а, чтобы прошла OVN port security.
`--hmac-key` подписывает пробу. Ответы ловятся AF_PACKET-снифером.

## Observation (JSON)

```json
{
  "id": "3f2b...-uuid",
  "node_id": "hv-07",
  "hop": 1,
  "direction": "INGRESS",
  "vni": 100,
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

`timestamp` — wall-clock захвата; `capture_ns` — монотонное время ядра; `latency_ns`
клампится в ≥0 (отрицательная разница означает рассинхрон часов между хостами и
помечается `clock_skew`). `az`/`logical_switch` добавляет агент (`--az` и VNI→switch
из OVN SB DB, best-effort).

## Аутентификация (HMAC)

`DSCP=62 + magic` подделывается. `--hmac-key <секрет>` включает HMAC-SHA256 поверх
meta-ядра; **responder проверяет подпись и не отвечает без валидного HMAC**
(`traceflow_auth_failures_total`), что закрывает амплификацию / зондирование.
Эхо-ответы переподписываются, так что обратный путь остаётся валиден. (eBPF не
считает HMAC дёшево, поэтому *observations* остаются advisory; enforcement — на
responder'е.)

## Коллектор (сборка пути)

`collector` принимает observations по HTTP и группирует их по `id` — ключу,
стабильному даже там, где NAT переписывает 5-tuple, так что путь через SNAT/DNAT
собирается как один поток. Агенты шлют с `--collector-url`.

```
GET /paths            — run id со счётчиками
GET /path?id=<uuid>   — observations прогона, по порядку hop, затем времени
```

### OTLP-экспорт (distributed tracing)

Трассируемый путь ложится 1:1 на tracing-спаны, поэтому агент может экспортить
прямо в любой OpenTelemetry-бэкенд (Tempo/Jaeger/…) — без своего UI:

```bash
sudo bin/agent --watch --az az-1 --otlp-endpoint otel-collector:4318
```

Каждая observation становится **span**; run-UUID **и есть** 128-битный **trace id**
(так observations всех хостов попадают в один trace); поля становятся атрибутами
(`traceflow.node_id/az/hop/vni/direction/…`, `source.address`, `destination.address`).
Спаны прогона делят синтетический parent из UUID и упорядочены по атрибуту `hop` —
сетевой путь не дерево вызовов, поэтому коррелируем по trace id + hop, а не по
причинной вложенности. Транспорт — OTLP/HTTP (protobuf POST на
`<endpoint>/v1/traces`, insecure по умолчанию).

## Компоненты

```
bpf/traceflow.c        eBPF/TC program: 2-level filter, VXLAN, VLAN, IPv6, ringbuf
internal/tfmeta        constants + (de)serialization + HMAC of traceflow_meta
internal/pkt           packet builders Eth/IP{4,6}/ICMP{,v6}/UDP/TCP/VXLAN + checksums
internal/observation   ring-buffer decode -> JSON
internal/ovs           OVS/OVN discovery (ovs-vsctl/ovn-nbctl/ovn-sbctl) + parsers
agent/                 eBPF loader, ring reader, responder, watchers, metrics, emitter
client/                marked-probe sender + AF_PACKET sniffer
collector/             HTTP collector: group observations by run id, assemble paths
scripts/               demo-netns.sh, lab-2az-vxlan.sh
tests/                 unit (Go) + integration (netns / veth / VXLAN / OVN)
```

## Сборка

```bash
sudo apt install -y clang llvm libbpf-dev linux-libc-dev make golang
make deps        # go mod tidy
make generate    # bpf2go: bpf/traceflow.c -> agent/traceflow_bpf*.go
make build       # -> bin/{agent,client,collector}
```

Рантайм: Linux (TCX требует ≥6.6; на старых ядрах используется clsact-fallback),
запуск от root или с `CAP_BPF`+`CAP_NET_ADMIN`+`CAP_NET_RAW`.

### Rootless-контейнер

```bash
make image                                   # unit-тесты гоняются в builder-стадии
podman run --rm --privileged traceflow itest # интеграционная suite (rootful для настоящего BPF)
```

Rootless podman может собрать образ и прогнать unit-тесты, но загрузка eBPF и
`ip netns exec` требуют настоящих BPF/net-прав — интеграционные тесты SKIP (не
fail), когда их нет; запускайте rootful или на хосте.

## Тесты

```bash
make test    # Go unit-тесты (без root)
make itest   # интеграционная suite (нужен root; TESTS ниже)
```

Интеграционная suite (каждый тест чисто SKIP'ается, если его переквизитов нет):

- `test_veth_multinetns.sh` — routed `ns1 — ns2(router) — ns3`: hop 0/1 через
  L3-роутер, корреляция по run-id, ответ dst-VM.
- `test_vxlan.sh` — парсинг VXLAN underlay (VNI, структурный intercept-guard).
- `test_ipv6_vlan.sh` — наблюдение ICMPv6 и 802.1Q VLAN.
- `test_watch_vxlan.sh` — netlink VXLAN-watcher: attach существующего, динамика
  create/delete, обогащение device-VNI.
- `test_hmac.sh` — подписанный отвечается, неподписанный отклоняется (по метрикам).
- `test_clsact.sh` — clsact/cls_bpf fallback (`TRACEFLOW_FORCE_CLSACT=1`).
- `test_xdp.sh` — XDP-путь attach (`--xdp`): программа на netdev, observation на
  ingress.
- `test_vxlan_2az.sh` — **два шасси / две AZ, соединённые VXLAN, без veth** (нужен
  OVS). См. ниже.

## Стенд 2 AZ через VXLAN (без veth)

Два шасси в стиле OVN в двух AZ, соединённых VXLAN, **без единого veth**:
межшассийный underlay построен на **OVS internal-портах** (реальные kernel-netdev'ы),
inter-AZ overlay — **kernel VXLAN-устройство**.

```
 host: OVS br-underlay  (normal L2 switch)
          ula ── moved into ns az1        ulb ── moved into ns az2
 ┌───────────────── ns az1 (AZ1) ────────┐   ┌──────────── ns az2 (AZ2) ─────────┐
 │  ula   172.16.9.1/24  (underlay)      │   │  ulb   172.16.9.2/24              │
 │  vxlan0 id100 remote .2 ── VXLAN(100) ┼───┼── vxlan0 id100 remote .1          │
 │    10.0.0.1/24  (VM-A)                │   │    10.0.0.2/24  (VM-B)            │
 └───────────────────────────────────────┘   └───────────────────────────────────┘

 A marked ICMP VM-A -> VM-B is observed at three points, one run id:
   (1) VM-A overlay netdev  (device vni=100)
   (2) inter-AZ VXLAN leg on the underlay  (packet vni=100, outer Eth/IP/UDP/VXLAN)
   (3) VM-B overlay netdev  (device vni=100)
```

```bash
sudo ovs-ctl start
sudo ./scripts/lab-2az-vxlan.sh up
sudo ./scripts/lab-2az-vxlan.sh agents &
sudo ./scripts/lab-2az-vxlan.sh probe
sudo ./scripts/lab-2az-vxlan.sh down
```

Почему internal-порты: OVS internal-порт — это реальный kernel-netdev, остающийся
прикреплённым к OVS-datapath даже после переноса в netns, так что два netns-«шасси»
соединяются через host-datapath без единого veth. (`ovs-sandbox` / `make sandbox`
использует **dummy** datapath, где реальные пакеты через kernel-netdev'ы не идут,
поэтому eBPF/TC их не видят — нужен настоящий kernel datapath.)

## Заметки / ограничения

- **HMAC** enforcement на responder'е; observations остаются advisory (eBPF не
  считает HMAC).
- **latency** между хостами требует точной синхронизации времени (PTP); клампится
  и помечается при рассинхроне.
- **IPv6** extension headers обходятся (ограниченно); не-первый фрагмент не несёт
  транспортного заголовка и не маркируется.
- **Портируемость**: TCX (≥6.6) с clsact/cls_bpf netlink-fallback; программа трогает
  только стабильный UAPI (`__sk_buff` + байты пакета), поэтому CO-RE не нужен.

## OVS-DPDK / AF_XDP

При OVS-DPDK datapath в userspace, поэтому TC-путь может не видеть трафик:

- **OVS с `type=afxdp` netdev'ами** — NIC остаётся kernel-netdev'ом, но OVS вешает
  XDP-программу, которая `XDP_REDIRECT`'ит кадры в AF_XDP-сокет *до* TC-хука, так
  что TC-программа их не видит. `--xdp` вешает тот же двухуровневый фильтр/парсеры
  на **XDP-хук** (он раньше), пишет те же observations и возвращает `XDP_PASS`, так
  что OVS всё равно получает кадр. Сначала native (driver) режим, откат на generic
  (SKB).

  ```bash
  sudo bin/agent --xdp --iface eth0 --node-id hv-01
  ```

  Оговорка: один XDP-прог на netdev, если не используется `xdp-dispatcher`
  (libxdp); на NIC, где уже висит XDP-программа OVS, нужен chaining через libxdp.
  XDP здесь только ingress.

- **OVS-DPDK с DPDK PMD (vfio-pci)** — NIC полностью у userspace DPDK-драйвера,
  поэтому kernel-netdev'а **нет вообще**, ни TC, ни XDP не прицепить. Наблюдение там
  требует OVS mirror-порта / нативного OVS-трейса; вне рамок.

- **vhost-user порты VM** — VM подключается через unix-сокет + shared memory, без
  netdev, поэтому eBPF на порту наблюдать не может в принципе.

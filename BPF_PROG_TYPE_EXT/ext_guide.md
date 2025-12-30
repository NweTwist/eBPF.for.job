# Путеводитель по BPF_PROG_TYPE_EXT (расширение программ)

Этот пример показывает, как программа типа EXT прикрепляется к существующей BPF‑программе и добавляет логирование её вызовов через `bpf_printk`.

## Что делает EXT‑программа

- Тип `BPF_PROG_TYPE_EXT` позволяет «расширить» уже загруженную BPF‑программу.
- Расширение исполняется вместе с целевой программой и может добавлять наблюдаемость (логи), метрики или политику.
- В нашем примере `ext_logger.c` печатает строку в кольцевой буфер ядра при каждом вызове целевой программы.

## Состав

- `ext_logger.c` — EXT‑программа с секцией `SEC("extension")`, выполняющая `bpf_printk`.
- `loader_ext.c` — пользовательский загрузчик: открывает целевой BPF‑объект и объект EXT, затем связывает их через `bpf_link_create` (`BPF_LINK_TYPE_PROG`).

## Сборка (Linux, libbpf)

```sh
clang -O2 -g -target bpf -c ext_logger.c -o ext_logger.o
gcc -O2 -g loader_ext.c -o loader_ext -lbpf -lelf
```

## Запуск

1. Соберите целевой BPF‑объект (например, `CGROUP_SKB/block_ports.o`).
2. Прикрепите расширение‑логгер:
```sh
./loader_ext CGROUP_SKB/block_ports.o BPF_PROG_TYPE_EXT/ext_logger.o
```
3. Проверьте логи ядра:
```sh
sudo dmesg | tail
```
Ожидаются строки вида: `EXT: program invoked`.

### Вариант: прикрепить EXT к уже загруженной программе по ID

Если целевая BPF‑программа уже загружена/прикреплена (вы видите её в `bpftool prog show` и знаете `ID`), можно прикрепить EXT напрямую к ней:

```sh
./loader_ext --target-id <ID> BPF_PROG_TYPE_EXT/ext_logger.o
```

Чтобы привязка пережила завершение процесса, закрепите link в bpffs:

```sh
sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
./loader_ext --target-id <ID> BPF_PROG_TYPE_EXT/ext_logger.o --pin-link /sys/fs/bpf/ext_link_<ID>
```

Проверка:

```sh
bpftool link show
bpftool link show pinned /sys/fs/bpf/ext_link_<ID>
```

## Практические замечания

- По умолчанию загрузчик выбирает «первую» программу в целевом объекте. Для точного выбора секции (например, `cgroup_skb/egress`) обновите логику поиска в `loader_ext.c`.
- `bpf_printk` пишет в трассировочный буфер ядра; убедитесь, что вывод разрешён и доступен (обычно через `dmesg`/`trace_pipe`).
- Тип EXT и способ привязки могут зависеть от версии ядра и libbpf; используйте актуальные заголовки UAPI (`include/uapi/linux/bpf.h`).

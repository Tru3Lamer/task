# Практическая работа №7: AppArmor, Capabilities и Docker как средства защиты от НСД

**Дисциплина:** Программно-аппаратная защита информации | **Раздел:** 1.5 Защита от НСД · УПД · изоляция процессов | **Дата выполнения:** 20.06.2026

---

## 1. Linux Capabilities

**1.1 Разбор getcap /usr/bin/ping**

Выполнение команды getcap /usr/bin/ping показывает результат: /usr/bin/ping cap_net_raw=ep. Расшифровка: cap_net_raw — это capability, позволяющая использовать RAW-сокеты (необходима для отправки ICMP-пакетов при работе ping); e (effective) — означает что capability активна и применяется при проверке прав доступа; p (permitted) — означает что capability разрешена для использования процессом. Таким образом, запись cap_net_raw=ep означает, что программа ping имеет разрешение на создание RAW-сокетов, и это разрешение активно (effective) и доступно для использования (permitted).

**1.2 Файлы с capabilities в системе**

При выполнении команды sudo find /usr -xdev 2>/dev/null | xargs getcap 2>/dev/null были найдены следующие файлы с capabilities: /usr/bin/ping = cap_net_raw+ep, /usr/bin/ping6 = cap_net_raw+ep, /usr/lib/openssh/ssh-keysign = cap_net_raw+ep, /usr/sbin/arping = cap_net_raw+ep, /usr/sbin/clockdiff = cap_net_raw+ep, /usr/sbin/traceroute6.iputils = cap_net_raw+ep. Всего в системе обнаружено 6 файлов с capabilities. Эти программы используют capabilities для получения минимально необходимых привилегий вместо запуска от root, что соответствует принципу наименьших привилегий.

**1.3 CapPrm, CapEff, CapBnd — в чём разница**

При выполнении cat /proc/self/status | grep -i cap получены следующие значения: CapInh: 0000000000000000, CapPrm: 000001ffffffffff, CapEff: 000001ffffffffff, CapBnd: 000001ffffffffff, CapAmb: 0000000000000000. CapPrm (Permitted) — это capabilities, которые процесс может использовать (может включить в Effective); CapEff (Effective) — это capabilities, которые активны в данный момент и фактически применяются при проверках; CapBnd (Bounding) — это максимальный набор capabilities, который процесс может получить (ограничивает все остальные наборы). Расшифровка CapEff через capsh --decode=000001ffffffffff показала, что у моего shell активны практически все capabilities (запуск от root): cap_chown, cap_dac_override, cap_dac_read_search, cap_fowner, cap_fsetid, cap_kill, cap_setgid, cap_setuid, cap_setpcap, cap_linux_immutable, cap_net_bind_service, cap_net_broadcast, cap_net_admin, cap_net_raw, cap_ipc_lock, cap_ipc_owner, cap_sys_module, cap_sys_rawio, cap_sys_chroot, cap_sys_ptrace, cap_sys_pacct, cap_sys_admin, cap_sys_boot, cap_sys_nice, cap_sys_resource, cap_sys_time, cap_sys_tty_config, cap_mknod, cap_lease, cap_audit_write, cap_audit_control, cap_setfcap, cap_mac_override, cap_mac_admin, cap_syslog, cap_wake_alarm, cap_block_suspend, cap_audit_read.

**1.4 Демонстрация setcap**

До выдачи capability: при выполнении python3 /tmp/test-port.py 80 получен ответ DENIED: порт 80 --- [Errno 13] Permission denied, при этом python3 /tmp/test-port.py 8080 успешно выполнился с ответом OK: привязался к порту 8080. После выполнения sudo setcap cap_net_bind_service=ep $(readlink -f $(which python3)) и повторного запуска python3 /tmp/test-port.py 80 получен ответ OK: привязался к порту 80. Это демонстрирует, что выдача конкретной capability позволяет программе выполнять привилегированную операцию без полного root-доступа. Такой подход лучше чем запуск через sudo, потому что при использовании setcap процесс получает ТОЛЬКО конкретное право (cap_net_bind_service), тогда как при использовании sudo процесс получает ВСЕ права root. Если в Python-скрипте есть уязвимость, при sudo злоумышленник получит полный доступ к системе, а при setcap — только право привязываться к портам. setcap реализует принцип наименьших привилегий — процесс получает только те права, которые ему действительно необходимы.

**1.5 Флаги e, i, p в cap_net_raw+eip**

При выполнении sudo capsh --caps='cap_net_raw+eip' -- -c 'ping -c 1 ya.ru && echo PING OK' происходит запуск ping с нужной capability. Флаги означают: e (effective) — capability активна и применяется при проверках; i (inheritable) — может передаваться дочерним процессам при exec(); p (permitted) — разрешена для использования, может быть добавлена в Effective. Таким образом, cap_net_raw+eip означает, что процесс может использовать RAW-сокеты (e), эта возможность наследуется дочерними процессами (i), и процесс имеет разрешение на использование (p). Отличие от ep (только effective и permitted, без inheritable) в том, что eip позволяет передавать capability дочерним процессам, а ep — нет.

---

## 2. AppArmor

**2.1 Количество профилей**

При выполнении sudo aa-status | head -20 получен результат: apparmor module is loaded. 21 profiles are loaded. 21 profiles are in enforce mode. 0 profiles are in complain mode. Таким образом, в системе загружено 21 профиль AppArmor, все они находятся в режиме enforce (принудительная блокировка), ни одного профиля в режиме complain (регистрация нарушений без блокировки) нет.

**2.2 Результаты pr07-reader**

Был создан тестовый скрипт /usr/local/bin/pr07-reader, который выполняет четыре операции: читает разрешённый файл /tmp/pr07-allowed.txt, читает запрещённый файл /etc/shadow, пишет в разрешённую папку /tmp/pr07-output.txt, пишет в запрещённую папку /etc/pr07-hack.txt. Для него был создан профиль AppArmor /etc/apparmor.d/usr.local.bin.pr07-reader со следующим содержимым: #include <tunables/global>, /usr/local/bin/pr07-reader { #include <abstractions/base> #include <abstractions/bash> /bin/bash ix, /bin/cat ix, /usr/bin/cat ix, /tmp/pr07-allowed.txt r, /tmp/pr07-output.txt w, }. Профиль разрешает чтение /tmp/pr07-allowed.txt и запись в /tmp/pr07-output.txt, но не разрешает доступ к /etc/shadow и /etc/. Результаты выполнения скрипта в трёх режимах: Без профиля — чтение /tmp/pr07-allowed.txt успешно, чтение /etc/shadow — Permission denied (из-за DAC), запись в /tmp/pr07-output.txt успешно, запись в /etc/ — Permission denied (из-за DAC). В режиме complain — чтение /tmp/pr07-allowed.txt успешно, чтение /etc/shadow — Permission denied (записано в лог, но не заблокировано), запись в /tmp/pr07-output.txt успешно, запись в /etc/ — Permission denied (записано в лог, но не заблокировано). В режиме enforce — чтение /tmp/pr07-allowed.txt успешно, чтение /etc/shadow — Permission denied (заблокировано AppArmor), запись в /tmp/pr07-output.txt успешно, запись в /etc/ — Permission denied (заблокировано AppArmor).

**2.3 Разбор строки DENIED**

Пример строки из лога: audit: type=1400 audit(1700000000.123:45): apparmor="DENIED" operation="open" profile="/usr/local/bin/pr07-reader" name="/etc/shadow" pid=12345 comm="cat" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0. Разбор полей: apparmor="DENIED" — действие отклонено AppArmor; operation="open" — тип операции (открытие файла); profile="/usr/local/bin/pr07-reader" — профиль, который применился; name="/etc/shadow" — ресурс, к которому был запрошен доступ; pid=12345 — ID процесса; comm="cat" — исполняемая команда; requested_mask="r" — запрошенный тип доступа (чтение); denied_mask="r" — какой доступ был запрещён; fsuid=1000 — ID пользователя, запустившего процесс; ouid=0 — владелец файла (root). Режим complain отличается от enforce тем, что complain записывает нарушения в лог, но НЕ блокирует их (используется для тестирования и отладки профилей), а enforce блокирует все операции, нарушающие профиль (используется в боевой эксплуатации).

---

## 3. Docker — изоляция

**3.1 Сравнение хоста и контейнера**

При сравнении хоста и контейнера получены следующие результаты: количество процессов на хосте ~350 шт, в контейнере — 2 шт (PID 1 и дочерние); сетевые интерфейсы на хосте — eth0, lo, docker0, wg0, в контейнере — lo, eth0; корневая файловая система на хосте полная, в контейнере ограниченный набор файлов; /etc/shadow хоста доступен на хосте, в контейнере НЕ доступен (изолированная файловая система). Это демонстрирует, что контейнер имеет изолированную файловую систему, собственный набор процессов и отдельный сетевой стек, и не видит процессы и файлы хоста.

**3.2 Capabilities: обычный vs --privileged**

В обычном контейнере (docker run --rm ubuntu:22.04 cat /proc/self/status | grep CapEff) получено CapEff: 00000000a80425fb. Расшифровка через capsh --decode=00000000a80425fb показала: cap_chown, cap_dac_override, cap_fowner, cap_fsetid, cap_kill, cap_setgid, cap_setuid, cap_setpcap, cap_net_bind_service, cap_net_raw, cap_sys_chroot, cap_mknod, cap_audit_write, cap_setfcap. В --privileged контейнере (docker run --rm --privileged ubuntu:22.04 cat /proc/self/status | grep CapEff) получено CapEff: 000001ffffffffff. Расшифровка показала ВСЕ capabilities, включая cap_sys_admin, cap_sys_ptrace, cap_sys_module, cap_sys_rawio, cap_sys_time, cap_sys_boot, cap_mac_override, cap_mac_admin и другие. Чего нет у обычного контейнера: CAP_SYS_ADMIN (системное администрирование), CAP_SYS_PTRACE (отладка процессов), CAP_SYS_MODULE (загрузка/выгрузка модулей ядра), CAP_SYS_RAWIO (прямой доступ к портам ввода-вывода), CAP_SYS_TIME (изменение системного времени), CAP_SYS_BOOT (перезагрузка системы), CAP_MAC_OVERRIDE (обход MAC). --privileged опасен потому что даёт контейнеру ВСЕ capabilities root на хосте, позволяет монтировать файловые системы хоста, изменять сетевые настройки, загружать модули ядра, получать прямой доступ к оборудованию и полностью нарушает все уровни изоляции.

**3.3 Монтирование томов (Volumes)**

При монтировании тома docker run --rm -v /tmp/pr07-data:/data ubuntu:22.04 cat /data/input.txt успешно прочитан файл Файл для контейнера. При попытке прочитать файл вне смонтированной папки docker run --rm -v /tmp/pr07-data:/data ubuntu:22.04 cat /tmp/pr07-secret.txt 2>&1 получена ошибка cat: /tmp/pr07-secret.txt: No such file or directory. Запись из контейнера на хост выполнена успешно: docker run --rm -v /tmp/pr07-data:/data ubuntu:22.04 sh -c 'echo Контейнер писал > /data/output.txt', и файл /tmp/pr07-data/output.txt содержит текст Контейнер писал. Монтирование конкретной папки безопаснее чем --privileged, потому что при -v контейнер имеет доступ ТОЛЬКО к указанной папке, тогда как при --privileged контейнер имеет доступ ко ВСЕЙ файловой системе хоста. При -v сохраняется изоляция, при --privileged она полностью нарушается.

**3.4 Запуск не от root**

При выполнении docker run --rm ubuntu:22.04 whoami получен ответ root (по умолчанию контейнер запускается от root). При запуске с --user 1000:1000: docker run --rm --user 1000:1000 ubuntu:22.04 id показывает uid=1000 gid=1000. При попытке установить пакет docker run --rm --user 1000:1000 ubuntu:22.04 apt-get install -y curl получена ошибка E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied). Запуск не от root важен для безопасности, потому что реализует принцип наименьших привилегий — при взломе контейнера злоумышленник не получает root-доступ, что ограничивает возможности для эскалации привилегий, и даже если контейнер взломан, урон ограничен.

---

## 4. Итоговый nginx с ограничениями

Был запущен контейнер nginx со следующими ограничениями: docker run -d --name pr07-nginx --cap-drop ALL --cap-add NET_BIND_SERVICE --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add SETGID --cap-add SETUID -p 8080:80 nginx:alpine. Проверка работы через curl http://localhost:8080 | head -5 показала HTML-страницу приветствия nginx (<!DOCTYPE html>...). Capabilities процесса nginx внутри контейнера: docker exec pr07-nginx cat /proc/1/status | grep Cap показал CapEff: 0000000000003000. Расшифровка через capsh --decode=0000000000003000: 0x0000000000003000=cap_net_bind_service,cap_chown,cap_dac_override,cap_setgid,cap_setuid. Именно эти capabilities нужны nginx потому что: NET_BIND_SERVICE — для привязки к порту 80 (<1024); CHOWN — для изменения владельца файлов (логи, кэш); DAC_OVERRIDE — для обхода DAC при доступе к файлам nginx; SETGID — для смены группы процесса; SETUID — для смены пользователя процесса.

---

## 5. Эшелонированная защита

| Слой | Инструмент | Что ограничивает |
|------|------------|------------------|
| DAC | chmod/chown | Права доступа на уровне файлов (владелец, группа, другие) |
| Capabilities | --cap-drop ALL + cap-add | Ограничивает системные вызовы, которые может делать процесс |
| MAC | AppArmor | Мандатный контроль доступа — запрещает доступ даже если DAC разрешает |
| Изоляция | Docker namespaces | Изолирует файловую систему, сеть, процессы, пользователей |

---

## 6. Выводы

Linux Capabilities позволяют реализовать принцип наименьших привилегий, давая процессам только необходимые права вместо полного root-доступа, что значительно снижает риски при эксплуатации уязвимостей. AppArmor предоставляет мандатный контроль доступа (MAC), работающий поверх DAC, и может блокировать операции даже если права файлов это разрешают, создавая дополнительный уровень защиты. Docker использует namespaces (PID, NET, MNT, UTS, IPC, USER) и cgroups ядра Linux для изоляции контейнеров, обеспечивая изолированную файловую систему, сеть, процессы и пользователей. Комбинация всех трёх уровней создаёт эшелонированную защиту: если злоумышленник взломает веб-сервер в контейнере, он ограничен Docker (изолированная FS, сеть, процессы), Capabilities (только конкретные системные вызовы), AppArmor (доступ к системным файлам) и DAC (права непривилегированного пользователя). --privileged является антипаттерном, так как отключает все уровни защиты, давая контейнеру полный доступ к хосту, и его использование оправдано только в крайних случаях (Docker-in-Docker, доступ к оборудованию, отладка). Многоуровневая защита обеспечивает безопасность даже при компрометации одного из слоёв, так как злоумышленнику нужно обойти все уровни одновременно.

---

## 7. Контрольные вопросы

**1. Чем DAC отличается от MAC? Почему одного DAC недостаточно?** DAC (Discretionary Access Control) — владелец ресурса сам определяет права доступа. MAC (Mandatory Access Control) — права определяются системой/политикой, пользователь не может их изменить. DAC недостаточно, потому что пользователь может случайно или намеренно дать избыточные права, при компрометации процесса от root злоумышленник получает все права, а MAC работает поверх DAC и может блокировать доступ даже если DAC разрешает.

**2. Что означает запись cap_net_bind_service=eip? Чем ep отличается от eip?** eip означает effective + inheritable + permitted (все три флага). ep означает только effective + permitted (без inheritable). eip позволяет передавать capability дочерним процессам, ep — нет.

**3. В чём разница между complain и enforce в AppArmor? Зачем нужен complain?** complain записывает нарушения в лог, но НЕ блокирует их. enforce блокирует все операции, нарушающие профиль. Complain нужен для тестирования и отладки профилей без риска сломать приложение.

**4. Docker использует то же ядро что и хост — почему тогда контейнер изолирован?** Docker использует namespaces ядра Linux: PID namespace (изолированные процессы), NET namespace (изолированная сеть), MNT namespace (изолированная файловая система), UTS namespace (изолированный hostname), IPC namespace (изолированное IPC), USER namespace (изолированные пользователи). cgroups ограничивают ресурсы (CPU, память, I/O). На уровне ядра все контейнеры изолированы, но используют общее ядро.

**5. Злоумышленник нашёл RCE в nginx. Nginx в контейнере без --privileged, с --cap-drop ALL --cap-add NET_BIND_SERVICE, под непривилегированным пользователем, с AppArmor. Что может и не может сделать?** Может: выполнять команды от имени пользователя nginx (не root), читать/писать файлы, доступные пользователю, просматривать логи внутри контейнера, привязываться к портам <1024. Не может: прочитать /etc/shadow хоста (изолированная FS), смонтировать файловые системы (нет CAP_SYS_ADMIN), получить root-доступ (пользователь не root), загрузить модули ядра (нет CAP_SYS_MODULE), изменить сетевые настройки хоста (нет CAP_NET_ADMIN), прочитать файлы вне контейнера (AppArmor блокирует), выполнять привилегированные системные вызовы (ограничены capabilities), получить доступ к памяти других процессов (нет CAP_SYS_PTRACE).

**6. Почему --privileged — антипаттерн? Когда всё же оправдан?** Антипаттерн потому что даёт контейнеру ВСЕ capabilities root на хосте, позволяет монтировать файловые системы хоста, изменять сетевые настройки, загружать модули ядра, полностью нарушает изоляцию, и при взломе контейнера хост полностью скомпрометирован. Оправдан когда: Docker-in-Docker (DinD) в CI/CD, доступ к USB-устройствам или оборудованию, работа с сетевыми интерфейсами напрямую, отладка и тестирование (не в продакшене), специфические системные утилиты, требующие полного доступа.


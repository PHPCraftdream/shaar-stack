# Checkpoint — 2026-11-05 01:42 [p09-integrated-1105]

## Session summary

Расстояние до v1:
- Принято: P01–P06, D1 (Endpoint exact-key), base58-only multibase (граф без base256emoji).
- P09 (native Mainline): код влит и принят CI на обеих ОС в `fa25006` (164 теста `shaar` lib, 2 witness, 6 base58; selected == executed, пропущен только привилегированный uid-тест). Формально P09 не закрыт: остаются реальные seam-обязательства P1–P10 (#51).
- P08: только bootstrap. Не начаты: P07 Yggdrasil (одобрен после P09, нужны acceptance/non-goals), P10 политика путей, P11 Server, P12 Client, P13 интеграция и контролируемая блокировка, P14–P16.
- Следующий шаг: #51 — закрыть или честно зафиксировать обязательства P1–P10 из `crates/shaar/src/native_discovery/runtime/tests/README.md`, затем P07.
- Блокеры: нет технических. Нужны отдельные разрешения пользователя для публичного smoke, пиров Yggdrasil и релиза.

Что сделано в этом отрезке. Листья #44–#48 (явная ошибка часов, опции и startup `NativeDiscoveredEndpoint`, connect по точному ключу, свод 7 контрактов, адреса libp2p) и #70/#71 прошли CI. Windows-кортеж перехода дерева `shaar` получен из `evidence.json` через HTTP Range (без скачивания 1,5 ГБ артефакта). Ветки слиты в одну линию, финальные кортежи (Linux `a9ce98ea…/e11c07fb…` → `cadc863f…`, Windows `bd0c1843…/590cec20…` → `2743b2fc…`) добавлены, CI зелёный. SHA `fa25006` передан в upstream `develop` быстрой перемоткой, влитые ветки и worktree удалены. Локальный `develop` = `30b0765` (восстановленные доки поверх `fa25006`), не опубликован.

Рабочие артефакты вне репозитория: `.rush/tools/ziprange.py` (чтение одного файла из удалённого zip по Range), `.rush/downloads/*` (логи и receipts CI как DATA).

## Active goal

none (прогресс ведёт TaskList; цель продукта — `docs/plans/north-star.md`).

## TaskList
### in_progress
- пусто
### pending
- #51 Закрыть P09: сводная приёмка (#212, #247, #253)
- #53 P07: acceptance и изолированный Rust adapter Yggdrasil (blockedBy: #51)
- #54 P07: встраиваемое ядро Yggdrasil-ng в CI на обеих ОС (blockedBy: #53)
- #55 P10 политика путей (#214) (blockedBy: #51, #54); #56 P10 переходы (#215) (blockedBy: #55)
- #57 P11 Server, #58 P12 Client (blockedBy: #55)
- #59 P13 интеграция и контролируемая блокировка (blockedBy: #56, #57, #58)
- #60 P14, #61 P15, #62 P16, #63 bounded public smoke (гейт пользователя)
- #72 Notices: подлинные лицензии как DATA; #73 проверяемые notices (blockedBy: #72)
- #64–#69 напоминания о процессе (неисполнимые)
### recently completed
- #49 итоговый залоченный normal SDK graph; #50 CI на финальном SHA, сверка, перелив в upstream, cleanup
- #71 base58-only multibase; #70 границы resolver; #44–#48 листья P09; #42, #52

## Decisions

- Объединённое дерево `shaar` требует собственных кортежей Linux и Windows: устаревшие промежуточные кортежи заменены финальными, две исторические записи оставлены (на них ссылается тест).
- Целевой хеш Windows-кортежа — контрольное Windows-дерево `2743b2fc…`, а не Linux `cadc863f…`.
- В upstream передан ровно протестированный SHA; локальный `develop` целиком не публикуется.
- Влитые ветки удалены, включая устаревшую upstream-ветку `native-integration-253-ci-1104` (предок `develop`).

## Open questions

- Объём закрытия #51: реализовать тесты P1–P10 (часть на уровне зависимостей) или зафиксировать их как явные принятые пробелы. Рекомендация: реализовать SDK-уровень (P7, P10, P3, P4, P8, P2), зависимые P5/P6/P1 — отдельным листом.
- Публикация локального docs-коммита `30b0765` (восстановленные доки и чекпоинты) в upstream — нужен прогон CI на нём.

## Repo state
```
(чисто, кроме нового файла чекпоинта)
```
```
30b0765 docs: restore local documentation and checkpoints after the upstream history rewrite
fa25006 fix: register the integrated shaar source trees as the reviewed transition
60a98f1 merge: integrate the base58 multibase graph with the native resolver and endpoint chain
d5e34e5 fix: register the Windows shaar source transition for the candidate tree
325295a test: reconcile the original unwired contracts and port the negative record oracle
```

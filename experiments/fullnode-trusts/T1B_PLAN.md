# T1b: что проверим на MAINNET и где остановимся

Это план и офлайн-контроли сериализации, требующие независимого review.
Реальных mainnet wallet/address/keys/tx в этой работе **ноль**. Ни узел, ни
кошелёк владельца не подключаются. Генератор не содержит RPC-клиента, запуска
Core, майнинга или broadcast. Старый T1-драйвер по-прежнему отказывает mainnet
до RPC и создания кошелька. Отдельный spend GO теперь ограничивает общий T1+T1b
расход **максимум 1 NMC**, с нового адреса, который пополняет владелец.
Он заменяет прежний 0,5 cap. Это максимум, а не требование потратить 1 NMC.
`mainnet.py` и `mainnet_t1.py` добавляют исходник конечного collector/adapter;
это не runtime admission. См. `MAINNET_SOURCE.md`: новое полное review,
отдельный готовый node-at-tip и Meta admission точных raw bytes перед КАЖДЫМ
broadcast всё ещё обязательны. Доступа к wallet владельца нет.

## Вопрос и точные образцы

После успешных core-проверок T1 предлагаем последовательно проверить ровно
**80, 100, 200, 520, 1000, 4000, 10000 байт payload** в одном OP_RETURN на
транзакцию. Содержимое — повторение ASCII `SYNTHETIC-T1B-OPRETURN-ONLY|`,
обрезанное до указанной длины. Это весь payload, без скрытой метки, гранта,
контакта, личных данных или добавленных байтов. Размер scriptPubKey включает
OP_RETURN и минимальный push-префикс:

| Payload, байт | Script, байт | Потолок signed vsize, vB | Потолок fee, sat NMC |
|---:|---:|---:|---:|
| 80 | 83 | 300 | 60000 |
| 100 | 103 | 320 | 64000 |
| 200 | 203 | 420 | 84000 |
| 520 | 524 | 740 | 148000 |
| 1000 | 1004 | 1220 | 244000 |
| 4000 | 4004 | 4220 | 844000 |
| 10000 | 10004 | 10220 | 2044000 |

`t1b.py --output ABSOLUTE_PRIVATE_OUTPUT` выпускает точные `.bin`, `.script`,
`.synthetic-tx`, manifest, бюджет и шаблоны будущих наблюдений. Manifest
содержит SHA-256 payload, script и fixture, длину сериализованного output,
синтетические vsize/fee и отдельные поля фактических наблюдений.
Все семь образцов сохраняются для review, даже если будущая серия остановится
на втором. Наличие файла не разрешает отправку.

Файлы `.synthetic-tx` — не подписанные транзакции: нулевой prevout,
107 нулевых байт вместо scriptSig и change-script с нулевым hash160. Нет
ключа или адреса. Их размеры — контроли сериализации legacy one-input,
one-change шаблона; значения fee — арифметика условного шаблона. Идентификатор
реальной mainnet-транзакции не вычисляется и не публикуется. Длина подписи,
реальные входы, остаток и пыль проверяются заново перед будущим broadcast.
Более одного обычного входа или иная форма требуют нового расчёта и review.

## Три разные ступени доказательства

1. **Локальная policy.** Сохранить точную версию Core, network/genesis,
   высоту/hash и время policy-снимка, параметры datacarrier/standardness,
   minrelay/mempool minimum, доступный estimator либо точную ошибку его
   отсутствия. Через существующий wallet RPC построить транзакцию при
   walletbroadcast=0. До broadcast проверить canonical payload/script hashes,
   signed raw hash, txid, vsize/weight, prevouts, точный fee и fee rate,
   потолки и `testmempoolaccept` вместе с reject-reason/details. Allowed здесь
   означает допуск **локального** узла. Отказ останавливает всю серию;
   peer relay и miner acceptance остаются UNKNOWN/NOT_ATTEMPTED.
2. **Наблюдаемая ретрансляция.** Только после локального allowed и отдельных
   разрешений — один обычный `sendrawtransaction` неизменённых байтов через
   тот же T1 broadcaster. Успех этого RPC и присутствие в локальном mempool
   не доказывают приём другим peer. Нужна отдельная заранее разрешённая
   наблюдательная точка: receipt существующего удалённого observer с exact
   txid/raw hash и временем обнаружения в его mempool/chain, либо уже
   доступное проверяемое входящее P2P-свидетельство об этой транзакции.
   Запись outbound inv/getdata показывает только объявление/запрос, не
   mempool acceptance. Без подходящего observer/свидетельства статус UNKNOWN;
   серию остановить. Новый observer, RPC-доступ или P2P-инструментирование
   здесь не реализованы и не разрешены. Не сохранять IP, credentials или
   peer identity: достаточно публичного псевдонима точки и хеша receipt.
3. **Блок и данные майнера.** Записать containing block hash, height, header
   UTC timestamp, время фактического наблюдения UTC, monotonic elapsed,
   canonical active-chain check и raw block/tx-in-block evidence hash.
   Проверить наличие именно txid и точного OP_RETURN; наблюдать >=1
   confirmation и активный hash на этой высоте перед переходом. Сохранить
   доступные публичные coinbase/AuxPoW сведения с хешем исходных байтов,
   или UNKNOWN с причиной. Coinbase-метка/merged-mining данные не
   удостоверяют личность майнера. Один блок доказывает включение этих байтов
   в этот блок при этом fee, а не всеобщую поддержку policy или максимум.

Default policy закреплённого Core 28 ограничивает весь script 83 байтами
(обычно 80 байт одного push). Поэтому ожидаемая возможность локального отказа
на 100 байтах — повод закончить серию без обхода. Это **не** доказательство
consensus limit, miner maximum или того, что никто не майнит больший output.
Никаких bypass standardness, manual peer relay, подмены miner policy, direct
miner submission или forced block. Возможное такое расширение требует нового
явного разрешения. Старые regtest и историческая read-only статистика полезны,
но эмпирический mainnet-тест не заменяют.

## Конечное время и остановки

Предложение: **1500 секунд на шаг**: <=60 секунд на свежие проверки/сборку,
<=120 секунд на peer receipt после единственного broadcast, оставшиеся
<=1320 секунд на inclusion. Если любая стадия исчерпала свою долю, остановка;
неиспользованное время не расширяет следующую долю. Наблюдения можно
собирать одновременно, но expiry каждой стадии остаётся фиксированной.
Не более 7 шагов / **10500 секунд (2 ч 55 мин)** на T1b. Общий deadline T1+T1b
— не позднее 21600 секунд (6 часов) от первого T1 broadcast, либо раньше по
операционному acceptance deadline. Нельзя перезапускать часы на новом размере.
Для начала полной серии должно оставаться 10500 секунд общего лимита;
иначе STOP_INSUFFICIENT_SHARED_TIME и новый отдельный план, без отправки.
Проверка выполняется до первого T1b gate/preparation по обоим исходным
deadline (UTC и monotonic). Ровно 10500 секунд допускает резервирование;
меньше, включая истёкший deadline, даёт terminal stop. Начало серии фиксируется
один раз; повторный вызов и переход размера часы не обновляют.

Collector должен применять monotonic deadlines, RPC timeout <=10 секунд,
не более 1 наблюдательного запроса / 10 секунд, один запрос в полёте,
<=2100 наблюдательных запросов за серию, <=64 MiB ответов и <=24 MiB экспорта.
В collector сохранён более строгий предел: 2100 **всех** вызовов за исходный
T1+T1b run, включая remote peer, build/sign/send, без сброса. Каждый отдельный
anchor RPC и peer poll занимает свой десятисекундный слот; batch не подменяет
единицу запроса. Одновременно выполняется максимум один внешний вызов.
Текущий literal rate несовместим с preparation <60 s: даже нижняя оценка
двух network-проверок и трёх policy reads — 11 RPC и минимум 100 s; с десятью
сохранёнными anchors это 31 RPC и 300 s. Поэтому текущий source отказывает
до сборки/подписи с STOP_OBSERVATION_PREPARATION_CONTRACT. Ограничения времени
и независимые anchor reads сохранены. См. OBSERVATION_CONSTRAINT.md;
потребуется явное новое согласование контракта, review и marker до runtime.
При ошибке RPC, исчезновении mempool tx, отказе peer, UNKNOWN relay после
120 секунд, отсутствии блока к deadline, reorg, изменении payload/fee/shape
или превышении любого лимита — stop, с точным временем, кодом и receipt.
Не отправлять следующие размеры. Reorg проверять и для ранее подтверждённых
T1/T1b tx перед каждым следующим broadcast и при финальном readback.
Проверка высот не исключает ABA reorg между чтениями; это ограничение указать.

Не делать RBF, double spend, изменённый rebroadcast или автоматическую
повторную отправку прежних байтов. Оставшаяся в mempool транзакция может
подтвердиться после deadline: report отражает timeout на момент остановки,
а последующее read-only наблюдение требует своего срока. Остановку не
переписывать в успешную серию. Никакого invalidateblock/майнинга на mainnet.

`outcome`/`advance` — только чистые офлайн-контроли правила stop-first.
Они принимают уже собранные observation records и разрешают лишь следующий
размер после полного успешного префикса. Они не проверяют криптографически
receipts и не заменяют collector, chain validation, admission или spend GO.
Collector и mainnet-adapter добавлены как исходник в `mainnet.py` и
`mainnet_t1.py`; их новое полное review и runtime admission ещё нужны.

## Полная стоимость T1+T1b

1 NMC = 100000000 sat. **200 sat/vB (0,002 NMC/kvB)** — фиксированный
source rate T1 и T1b, не estimator и не inclusion quote.
Доступность estimatesmartfee не является условием construction/spending.
Большие output не считаются relayable.
Бюджет резервирует даже все семь размеров; ранняя остановка уменьшает расход.

| Состав | NMC |
|---|---:|
| Два имени, locked | 0,02000000 |
| Один seal B, остающийся locked после revoke A | 0,00100000 |
| Десять исходных операций T1: сумма fee caps | 0,00708000 |
| Семь T1b: сумма caps 17440 vB × 200 sat/vB | 0,03488000 |
| Один перевод funding, <=230 vB | 0,00046000 |
| 10% запас на все перечисленные fee | 0,00424200 |
| Дополнительный spendable change reserve | 0,00100000 |
| **Условная верхняя модель при всех fee caps** | **0,06866200** |
| Остаток до общего cap 1 NMC | 0,93133800 |

Оба seal первоначально блокируют по 100000 sat. При revoke A его 100000 sat
превращаются в уже учтённую fee 50000 sat и spendable change 50000 sat.
После подтверждения этот change можно использовать в T1b. Имя при
firstupdate/anchor сохраняет свой principal; нового name lock не возникает.
Прежняя сумма 6966200 sat повторно резервировала освобождённые 100000 sat;
дополнительного резерва на эту сумму в данном контракте нет.

`funding.py` считает каждый префикс отдельно для A/B. В таблице ниже cash —
доступный остаток после подтверждения операции, без names и заблокированных
seals. Во всех строках предполагаются максимальные fee. Начальный cash A
6815600 sat; funder держит и платит свой fee отдельно.

| После операции | Fee, sat | Cash A, sat | Cash B, sat |
|---|---:|---:|---:|
| fund_B: фиксированный перевод B 1436600 sat | 46000 | 5333000 | 1436600 |
| A_name_new | 50400 | 4282600 | 1436600 |
| B_name_new | 50400 | 4282600 | 386200 |
| A_name_firstupdate | 102800 | 4179800 | 386200 |
| B_name_firstupdate | 102800 | 4179800 | 283400 |
| A_seal_funding | 46000 | 4033800 | 283400 |
| A_grant_anchor | 106800 | 3927000 | 283400 |
| B_seal_funding | 46000 | 3927000 | 137400 |
| B_grant_anchor | 106800 | 3927000 | 30600 |
| A_seal_revoke: fee из seal, возврат 50000 sat | 50000 | 3977000 | 30600 |
| OP_RETURN 80 | 60000 | 3917000 | 30600 |
| OP_RETURN 100 | 64000 | 3853000 | 30600 |
| OP_RETURN 200 | 84000 | 3769000 | 30600 |
| OP_RETURN 520 | 148000 | 3621000 | 30600 |
| OP_RETURN 1000 | 244000 | 3377000 | 30600 |
| OP_RETURN 4000 | 844000 | 2533000 | 30600 |
| OP_RETURN 10000 | 2044000 | 489000 | 30600 |

B требуется 1406000 sat на имя, seal и собственные fee; фиксированный перевод
оставляет 30600 sat. Обратного B-to-A перевода нет. Максимальный накопленный
отток cash A равен 6326600 sat в конце серии. Для финального совокупного
остатка 519600 sat (419600 sat = 10% экспериментальных fee, плюс явный
reserve 100000 sat) A должен закончить с 489000 sat. Поэтому требование к
начальному cash A — max(6326600, 6326600+489000) = **6815600 sat**.
Внешние **50600 sat** — provision funder для его fee <=46000 sat и margin
4600 sat; они не переводятся A. Совокупная модель — **6866200 sat**.
Если фактический fee funder превышает эту planning line, пересчитать record
через `funding.funder_record`. Само превышение 50600 sat не блокирует опыт,
пока совокупная сумма остаётся далеко ниже неизменного cap 1 NMC.
Only the owner funds the experiment; recipient funding and experimental caps do not increase.
Она совпадает с финальной алгеброй только после проверки всех префиксов.

Для одного T1 такая финальная алгебра дала бы 2878800 sat, но оставила бы A
дефицит 9800 sat перед revoke. Минимум модели T1 — 2888600 sat: A имеет
нулевой cash после anchor, затем 50000 sat возвращённого change; B имеет
30600 sat. Итог 80600 sat включает margin 70800 sat и неизбежные 9800 sat
из-за пика ликвидности, а не произвольный дополнительный reserve.

Это минимумы **учёта стоимости при объявленных caps**, а не live quote или
адрес/запрос на перевод. Повторное использование change требует подтверждения
и selectable UTXO перед следующим расходом; unconfirmed change, чужой seal
и остаток B для A не предполагаются. Реальные inputs, dust/change policy,
signed size, fixed rate, policy и время подтверждения проверяются заново до admission.
Резервы не разрешают повышать fee caps. Имена/суммы/fee применимы только к
ограниченному шаблону; conditional upper и свежий live minimum различны.

Исправление текущей lineage не требует повторения дополнительных regtest
transfer/fork-контролей на mainnet. Эти пять контрольных транзакций и
invalidateblock из regression-драйвера не входят в будущую T1/T1b процедуру
и не разрешены ею. Если scope T1 меняется, включая эти операции или дополнительные
inputs/funding transfers, пересчитать полный бюджет и получить новый review.

До любого будущего broadcast заново проверить fixed 200 sat/vB и fee/policy;
отсутствие estimator не блокирует construction/spending. Пересчитать exact signed
size/fee и суммарный остаток. Если предпосылки не соблюдены — stop, даже если
до 1 NMC ещё далеко. Запас не разрешает автоматическое повышение fee.
Если exact tx отсутствует в active chain к шестому successor block от
последнего native pre-send tip, STOP series/report. Reorg не переносит baseline;
пропущенные polls не расширяют окно. Старые time/RPC/bytes bounds могут
остановить раньше. Никаких automatic bump/replacement/resend; каждый новый
raw tx требует нового exact Meta GO. См. `MAINNET_SOURCE.md` и
`RELAY_QUALIFICATION.md`; remote block не заменяет remote mempool relay evidence.

## Общий код, композиция и gates

`transaction.build_signed` извлечён из существующего T1 `lab.raw_signed`:
те же create/name/fund/sign/decode/testmempoolaccept методы, тот же wallet
capability и точная fee arithmetic. T1 wrapper сохраняет свои 600-vB и
0,0012-NMC caps и прежний network check. Helper сам не отправляет транзакцию.
T1b использует **этот же helper** с отдельными caps, существующий `protocol.canon`
и заведомо синтетический in-memory RPC для офлайн-контролей. Никаких новых
wallet/grant форматов или grant/signature domain. Существующий T1 lab wire
format остаётся экспериментальным, он не заменяет platform grant/1 на
swarm-envelope/2 с owner-registry attestation.

Кандидат объединяет актуальную canonical main с mail/Part A/policy plan,
исправленный current-grantee lineage, helper extraction и T1b delta.
**Этот кандидат сам по себе не готов к mainnet.** Точные input head/tree,
hashes и receipts вынесены в export, без операционной provenance в product-тексте.
Для нового review проверить:

- актуальная canonical main взята как основа, старое дерево не наложено;
- принятый policy plan и исправленный T1 verifier с lineage fix сохранены;
- helper extraction/T1b delta сохраняет все изменения
  T1 regression-driver; выбрать mainnet workflow без regtest-only fork;
- весь новый mainnet collector/adapter использует те же
  `build_signed`, validation/broadcast guards и wallet capability separation;
- сверить exact blobs, constants/budget, payload manifest; заново проверить
  полное дерево, controls и подпись, без автоматического наследования review.

Порядок будущего допуска: core passes / допустимая seed provenance и tip checks;
собранный exact candidate; свежий независимый review всего head/tree;
Meta marker для **точного** payload set/manifest hash и source head/tree;
явные средства в рамках superseding owner spend GO максимум 1 NMC; bounded runtime admission;
только затем wallet/address, свежие проверки и единичный broadcast.
Любая смена байтов/размеров/исходников после marker требует нового review/marker.
Эта работа ни один gate не объявляет пройденным.

Для T1/T1b: protocol contact находится on chain. Опциональный contact,
который клиент сделал off chain, не имеет chain evidence и не восстанавливается
другими клиентами. Видимый mempool revoke сразу приостанавливает grant;
первый блок делает revoke final по принятой экспериментальной one-block
политике, без обещания необратимости при reorg. Это ограниченный план T1/T1b,
не продуктовая переделка contact semantics.

## Офлайн-проверка и границы результата

Python standard library only; внешних пакетов, Go modules/h1, upgrades и новых
зависимостей нет. Офлайн-проверки должны идти в bwrap unshare-all/clearenv,
с read-only source/tools, private 0700 absolute HOME/TMP/cache и без host home,
keys, sockets, foreign caches/network. Использовать предоставленный export
launcher; не запускать product/test напрямую на host.

Контроли отдельно разбирают сериализацию, сверяют размеры/fee budget,
сравнивают shared builder с точной предыдущей T1 функцией при успехе и отказах,
проверяют stop-first, UNKNOWN и deadlines. Они не создают криптографическую
подпись, не вызывают Core testmempoolaccept и не доказывают relay/inclusion.
Все будущие mainnet-наблюдения остаются NOT_RUN/UNKNOWN; реальные
block/miner/fee/policy данные появятся только в отдельно разрешённом опыте.

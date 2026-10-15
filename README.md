# armanVPN iOS

Other platform: [ArmanVPN macOS](https://github.com/AubakirovArman/armanvpn-macos).

Внутренний экспериментальный SSL-клиент Check Point для iPhone и iPad, iOS 17+.
Приложение SwiftUI управляет системным Packet Tunnel Provider. Протокол CCC/SLIM
перенесён на Swift по исходникам snx-rs 6.5.1, ревизия
`86aa48031888050f957af7b6adf2c2e39d4745fd`. Attribution и AGPL-3.0 находятся
в `armanVPN-IOS/Legal/` и включаются в приложение.

## Сборка

Открыть `armanVPN-IOS.xcodeproj`, схема `armanVPN-IOS`.

```sh
bash scripts/build-ios.sh simulator
bash scripts/build-ios.sh unsigned
swift test
```

Для установки работающего VPN на устройство нужна команда Apple Developer Program
с возможностью **Network Extensions** для обоих идентификаторов:

- `armanibadboy.armanVPN-IOS`
- `armanibadboy.armanVPN-IOS.PacketTunnel`

Выбрать эту команду в Signing & Capabilities обеих целей, включить автоматическую
подпись и собрать на подключённый iPhone. Команда Personal Team не поддерживает
эту возможность: Xcode отклоняет создание профилей. Сборка без подписи позволяет
проверить компиляцию, но не устанавливается на обычный iPhone.

```sh
bash scripts/build-ios.sh device
```

## Подключение

1. Ввести сервер, порт, логин и пароль.
2. Проверить сертификат и явно решить, доверять ли ему. Запоминание необязательно.
3. Разрешить добавление VPN-конфигурации в системном диалоге iOS.
4. При необходимости ввести дополнительный код подтверждения.
5. После подключения проверить внутренний ресурс и запустить тест на 10 минут.

Пароль сохраняется только по желанию пользователя, в Keychain приложения.
В VPN-конфигурации сохраняются параметры профиля и точный одобренный сертификат.
Пароль, SSL-ключ и идентификатор авторизационной сессии в конфигурацию не записываются.
SSL-ключ и идентификатор сессии передаются расширению в памяти при запуске.
Доверие сертификату действует только внутри клиента и для выбранного адреса.

## Текущее поведение и ограничения

- SSL/TCP с закреплением конкретного сертификата; TLS 1.2 для совместимости со шлюзом.
- Корпоративные IPv4-маршруты, IP-адрес и DNS получает шлюз; трафик обрабатывает
  `NEPacketTunnelProvider` через `packetFlow`.
- Поддерживаются вход по логину/паролю и последующие текстовые MFA-запросы.
  SSO, клиентские сертификаты и IPsec в эту iOS-версию не перенесены.
- Расширение работает независимо от экрана приложения, отправляет keepalive и
  завершает туннель с причиной при потере сети, тайм-ауте ответов или закрытии SSL.
- Автоматический вход после перезагрузки расширения и продление истёкшей сессии
  пока не реализованы: повторное подключение выполняется из приложения.
- «Тест на 10 минут» наблюдает за одной сессией iOS. Доступность конкретного
  внутреннего сервиса этим тестом не подтверждается.
- Проверка в симуляторе относится к интерфейсу. Рабочий туннель и стабильность
  необходимо проверить на физическом устройстве после успешной подписи.

Сохранённые пароли, принятые сертификаты и личные профили в исходники не включены.

## Проверка совместимости без входа

`tools/InspectGateway.swift` проверяет сертификат, CCC ClientHello и TLS-соединение
по явно одобренному SHA-256. Принимает JSON `host`, `port`, `fingerprint` через stdin.
Не выполняет вход, не создаёт сессию и не меняет маршруты Mac.

Документация Apple:
[Packet Tunnel Provider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider),
[Network Extensions](https://developer.apple.com/documentation/xcode/configuring-network-extensions).

## License and attribution

Source code is published under **AGPL-3.0-only**; see [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
The Check Point protocol implementation is based on snx-rs by Dmitry Pankratov and contributors.
Artwork and third-party logos are not granted trademark rights by the source-code license.
This is an independent interoperability project, with no endorsement from Check Point or the organizations depicted in the artwork.

## Public source and local settings

No VPN server address, VPN account, password, accepted server certificate, private key or signing team is supplied.
Each user configures their own gateway and credentials in the app. The numeric addresses in protocol tests are example fixtures, not a configured VPN connection.
Select your own Apple Developer Program team in Xcode and use unique bundle identifiers for both targets before building a signed app.
Local build files, logs and user settings are excluded from Git.

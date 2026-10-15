import SwiftUI

private enum Brand {
    static let background = Color(red: 0.035, green: 0.055, blue: 0.085)
    static let panel = Color(red: 0.07, green: 0.095, blue: 0.135)
    static let gold = Color(red: 0.94, green: 0.73, blue: 0.36)
}

struct ContentView: View {
    @StateObject private var vpn = MobileVPNModel()
    @Environment(\.scenePhase) private var scenePhase
    @State private var showJournal = false
    @FocusState private var editing: Bool
    private var active: Bool { vpn.connected || vpn.phase == "Подключение" || vpn.phase == "Восстановление соединения" }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    hero
                    connectionCard
                    if let error = vpn.error {
                        Label(error, systemImage: "exclamationmark.triangle.fill").font(.callout).foregroundStyle(.orange)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(16).background(.orange.opacity(0.09), in: RoundedRectangle(cornerRadius: 20))
                    }
                    profileCard
                    stabilityCard
                    memoryCard
                    Button { showJournal = true } label: { Label("Журнал и обратная связь", systemImage: "text.alignleft") }.padding(.vertical, 6)
                    Text("Friends Edition · iOS 17+\nSSL-клиент Check Point · snx-rs / AGPL-3.0").font(.caption2).foregroundStyle(.secondary).multilineTextAlignment(.center).padding(.bottom, 20)
                }.padding(.horizontal, 18)
            }.background(Brand.background).scrollDismissesKeyboard(.interactively)
            .toolbar {
                ToolbarItem(placement: .principal) { HStack(spacing: 7) { Image(systemName: "shield.lefthalf.filled").foregroundStyle(Brand.gold); Text("armanVPN").font(.headline) } }
                ToolbarItemGroup(placement: .keyboard) { Spacer(); Button("Готово") { editing = false } }
            }
            .navigationBarTitleDisplayMode(.inline)
            .sheet(item: $vpn.pendingCertificate) { certificate in CertificateView(certificate: certificate, vpn: vpn).interactiveDismissDisabled() }
            .sheet(isPresented: Binding(get: { vpn.challenge != nil }, set: { if !$0 { vpn.disconnect() } })) {
                NavigationStack {
                    Form { Section("Подтверждение входа") {
                        Text(vpn.challenge ?? "Введите код")
                        SecureField("Код или ответ", text: $vpn.challengeAnswer).textContentType(.oneTimeCode)
                        Button("Продолжить") { vpn.sendChallenge() }.disabled(vpn.challengeAnswer.isEmpty || vpn.busy)
                    } }.navigationTitle("Подтверждение").toolbar { ToolbarItem(placement: .cancellationAction) { Button("Отмена") { vpn.disconnect() } } }
                }.interactiveDismissDisabled()
            }
            .sheet(isPresented: $showJournal) {
                NavigationStack {
                    List {
                        Section { Button("Скопировать данные для отзыва", systemImage: "doc.on.doc") { vpn.copyFeedback() } }
                        Section("События на этом iPhone") {
                            if vpn.events.isEmpty { Text("Пока нет событий").foregroundStyle(.secondary) }
                            ForEach(Array(vpn.events.enumerated()), id: \.offset) { _, message in Text(message).font(.caption.monospaced()).textSelection(.enabled) }
                        }
                    }.navigationTitle("Журнал").toolbar { ToolbarItem(placement: .confirmationAction) { Button("Готово") { showJournal = false } } }
                }
            }
        }.preferredColorScheme(.dark).tint(Brand.gold)
            .onChange(of: scenePhase) { _, phase in if phase != .active { vpn.saveProfile() } }
    }
    private var hero: some View {
        ZStack(alignment: .bottomLeading) {
            Image("ArmanPoster").resizable().scaledToFill().frame(height: 285).clipped()
            LinearGradient(colors: [.clear, .black.opacity(0.9)], startPoint: .center, endPoint: .bottom)
            VStack(alignment: .leading, spacing: 7) {
                Text("СВОИ ЛЮДИ. СВОЯ СЕТЬ.").font(.system(size: 10, weight: .bold, design: .monospaced)).tracking(2).foregroundStyle(Brand.gold)
                Text("Мощная сеть.\nТеперь в кармане.").font(.system(size: 30, weight: .bold, design: .rounded))
            }.padding(20)
        }.frame(height: 285).clipShape(RoundedRectangle(cornerRadius: 26))
    }
    private var connectionCard: some View {
        VStack(spacing: 16) {
            HStack {
                Circle().fill(vpn.connected ? Color.green : Brand.gold).frame(width: 7, height: 7)
                Text(vpn.phase).font(.subheadline.weight(.semibold)); Spacer()
                Text("SSL / TCP").font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            HStack(spacing: 15) {
                Button {
                    editing = false
                    if active { vpn.disconnect() } else { vpn.connect() }
                } label: {
                    ZStack {
                        Circle().fill(vpn.connected ? Color.green.opacity(0.15) : Brand.gold.opacity(0.13)).frame(width: 72, height: 72)
                        if vpn.busy { ProgressView().tint(Brand.gold) }
                        else { Image(systemName: "power").font(.system(size: 30, weight: .medium)).foregroundStyle(vpn.connected ? .green : Brand.gold) }
                    }
                }.disabled(vpn.busy).accessibilityLabel(active ? "Отключить VPN" : "Подключить VPN")
                VStack(alignment: .leading, spacing: 5) {
                    Text(vpn.connected ? "Ты в мощной сети Армана." : "Свои люди. Своя сеть.").font(.headline)
                    if vpn.connected, let since = vpn.connectedSince { Text(since, style: .timer).font(.subheadline.monospacedDigit()).foregroundStyle(.green) }
                    else { Text(active ? "Устанавливаем туннель…" : "Нажми, чтобы подключиться").font(.caption).foregroundStyle(.secondary) }
                }; Spacer(minLength: 0)
            }
            if vpn.connected {
                Divider()
                HStack {
                    Label(ByteCountFormatter.string(fromByteCount: Int64(clamping: vpn.received), countStyle: .binary), systemImage: "arrow.down"); Spacer()
                    Label(ByteCountFormatter.string(fromByteCount: Int64(clamping: vpn.sent), countStyle: .binary), systemImage: "arrow.up")
                }.font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                HStack { Text("Сеть: \(vpn.network)"); Spacer(); Text("Ответ: \(vpn.lastReplySeconds) с назад") }.font(.caption2).foregroundStyle(.secondary)
            }
        }.padding(18).background(Brand.panel, in: RoundedRectangle(cornerRadius: 24))
    }
    private var profileCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Твоё подключение").font(.headline)
            HStack {
                TextField("Сервер VPN", text: $vpn.profile.host).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityLabel("Сервер VPN")
                Divider().frame(height: 22)
                TextField("443", text: $vpn.profile.port).keyboardType(.numberPad).frame(width: 58).accessibilityLabel("Порт VPN")
            }
            Divider()
            TextField("Логин", text: $vpn.profile.username).textContentType(.username).textInputAutocapitalization(.never).autocorrectionDisabled()
            Divider()
            SecureField(vpn.profile.rememberPassword ? "Пароль · сохранён в Связке ключей" : "Пароль VPN", text: $vpn.password).textContentType(.password)
            Toggle("Сохранить пароль", isOn: Binding(get: { vpn.profile.rememberPassword }, set: vpn.rememberPassword)).font(.subheadline).tint(Brand.gold)
            if !vpn.options.isEmpty { Picker("Способ входа", selection: $vpn.profile.loginType) { ForEach(vpn.options) { Text($0.title).tag($0.id) } }.font(.subheadline) }
            Text("Используй рабочие сервер, логин и пароль. iOS попросит разрешить добавление VPN-конфигурации.").font(.caption).foregroundStyle(.secondary)
        }.focused($editing).padding(18).background(Brand.panel, in: RoundedRectangle(cornerRadius: 24)).disabled(vpn.busy || active)
    }
    private var stabilityCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Проверка стабильности", systemImage: "waveform.path.ecg").font(.headline)
            if let started = vpn.testStarted {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let elapsed = min(600, max(0, context.date.timeIntervalSince(started)))
                    ProgressView(value: elapsed, total: 600).tint(Brand.gold)
                    Text("\(Int(elapsed)) / 600 секунд").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
            } else { Text(vpn.testResult ?? "10 минут одной VPN-сессии. Наблюдаем за соединением и ответами шлюза.").font(.subheadline).foregroundStyle(.secondary) }
            Button("Начать тест", systemImage: "play.fill") { vpn.startTest() }.buttonStyle(.bordered).disabled(!vpn.connected || vpn.testStarted != nil)
        }.padding(18).frame(maxWidth: .infinity, alignment: .leading).background(Brand.panel, in: RoundedRectangle(cornerRadius: 24))
    }
    private var memoryCard: some View {
        let memory = Int((ProcessInfo.processInfo.physicalMemory + 1_073_741_823) / 1_073_741_824)
        return HStack(spacing: 14) {
            Image(memory <= 4 ? "ArmanSkeptical" : "ArmanApproved").resizable().scaledToFill().frame(width: 65, height: 65).clipShape(RoundedRectangle(cornerRadius: 18))
            VStack(alignment: .leading, spacing: 4) {
                Text("\(memory) ГБ. Для кармана пойдёт.").font(.subheadline.weight(.semibold))
                Text("Mac я бы осудил. Тебя пускаю.").font(.caption).foregroundStyle(.secondary)
            }; Spacer(minLength: 0)
        }.padding(14).background(Brand.gold.opacity(0.07), in: RoundedRectangle(cornerRadius: 22))
    }
}

private struct CertificateView: View {
    let certificate: MobileCertificate
    @ObservedObject var vpn: MobileVPNModel
    @State private var remember = false
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label("Шлюз предъявил сертификат", systemImage: "checkmark.shield").font(.headline)
                    Text("Сверь данные с администратором и реши, доверяешь ли этому серверу.")
                }
                Section("Сертификат") {
                    LabeledContent("Сервер", value: vpn.profile.endpoint)
                    LabeledContent("Имя", value: certificate.subject)
                    LabeledContent("Действует до", value: certificate.expires.formatted(date: .numeric, time: .omitted))
                    Text("SHA-256").font(.caption).foregroundStyle(.secondary)
                    Text(certificate.fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                }
                Section {
                    Toggle("Запомнить доверие к этому сертификату", isOn: $remember)
                    Text("Доверие сохранится для этого адреса в armanVPN. При замене сертификата вопрос появится снова.").font(.caption).foregroundStyle(.secondary)
                }
                Section {
                    Button("Доверять и подключиться") { vpn.acceptCertificate(remember: remember) }.disabled(!certificate.isCurrent)
                    Button("Не доверять", role: .destructive) { vpn.rejectCertificate() }
                }
            }.navigationTitle("Доверие серверу").navigationBarTitleDisplayMode(.inline)
        }.tint(Brand.gold).preferredColorScheme(.dark)
    }
}

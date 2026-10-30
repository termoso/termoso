import XCTest

/// Golden path on a fresh profile: welcome → offline → add a host → find it →
/// settings. Runs against the real Rust core in the simulator.
final class SmokeUITests: XCTestCase {
    private var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments = ["--ui-test"]
        app.launch()
    }

    func testWelcomeOfflineAddHostAndSettings() throws {
        snap("01-welcome")
        let offline = el("welcome.offline")
        XCTAssertTrue(offline.waitForExistence(timeout: 20), "welcome did not appear (vault open failed?)")
        offline.tap()

        let hosts = el("vaults.hosts")
        XCTAssertTrue(hosts.waitForExistence(timeout: 10))
        snap("02-vaults")
        hosts.tap()

        XCTAssertTrue(el("hosts.empty").waitForExistence(timeout: 5)
            || app.staticTexts["No hosts yet"].waitForExistence(timeout: 5))
        snap("03-hosts-empty")

        el("hosts.add").tap()
        let newHost = el("hosts.newHost")
        XCTAssertTrue(newHost.waitForExistence(timeout: 5))
        newHost.tap()

        let label = el("hostEditor.label")
        XCTAssertTrue(label.waitForExistence(timeout: 5))
        label.tap()
        label.typeText("pqssh")
        let address = el("hostEditor.address")
        address.tap()
        address.typeText("pq.example.org")
        let username = el("hostEditor.username")
        if username.exists {
            username.tap()
            username.typeText("ubuntu")
        }
        snap("04-host-editor")
        el("hostEditor.save").tap()

        let row = el("hosts.host.pqssh")
        XCTAssertTrue(row.waitForExistence(timeout: 10), "saved host not listed")
        XCTAssertTrue(app.staticTexts["ubuntu@pq.example.org"].firstMatch.exists)
        snap("05-hosts-one")

        // Reopen to confirm the draft round-trips through the core. Tapping
        // the row connects; the pencil edits.
        el("hosts.edit.pqssh").tap()
        let editLabel = el("hostEditor.label")
        XCTAssertTrue(editLabel.waitForExistence(timeout: 5))
        XCTAssertEqual(editLabel.value as? String, "pqssh")
        el("hostEditor.cancel").tap()

        app.tabBars.buttons["Profile"].tap()
        XCTAssertTrue(el("settings.theme").waitForExistence(timeout: 5))
        snap("06-profile")
        // About is the last section; List rows below the fold do not exist yet.
        let core = el("settings.coreVersion")
        for _ in 0 ..< 6 where !core.exists {
            app.swipeUp()
        }
        XCTAssertTrue(core.waitForExistence(timeout: 5), "About → Core row not reachable")
        snap("06-settings-about")
    }

    func testSelfHostedRequiresValidURL() throws {
        let selfHosted = el("welcome.selfHosted")
        XCTAssertTrue(selfHosted.waitForExistence(timeout: 20))
        selfHosted.tap()

        let url = el("welcome.selfHosted.url")
        XCTAssertTrue(url.waitForExistence(timeout: 5))
        // Toolbar items wrap the button in a container that carries the same
        // identifier but not the disabled state, so target the button itself.
        let cont = app.buttons.matching(identifier: "welcome.selfHosted.continue").firstMatch
        XCTAssertTrue(cont.waitForExistence(timeout: 5))
        XCTAssertFalse(cont.isEnabled, "Continue must stay disabled for an empty address")
        url.tap()
        url.typeText("termoso.example.com")
        XCTAssertTrue(cont.isEnabled, "bare host name should normalise to https://")
        snap("07-self-hosted")
        cont.tap()

        XCTAssertTrue(el("vaults.hosts").waitForExistence(timeout: 10))
    }

    /// Terminal over the local shell (simulator only): the session opens,
    /// typed input reaches the shell and its output comes back through the
    /// Rust grid. The canvas mirrors visible text into its accessibility
    /// value under `--ui-test`.
    func testLocalShellTerminalRoundTrip() throws {
        let offline = el("welcome.offline")
        XCTAssertTrue(offline.waitForExistence(timeout: 20))
        offline.tap()

        app.tabBars.buttons["Connections"].tap()
        XCTAssertTrue(el("connections.empty").waitForExistence(timeout: 5))
        snap("10-connections-empty")
        let local = el("connections.localShell")
        XCTAssertTrue(local.waitForExistence(timeout: 5), "local shell entry missing (not a simulator build?)")
        local.tap()

        let canvas = el("terminal.canvas")
        XCTAssertTrue(canvas.waitForExistence(timeout: 10), "terminal did not open")
        XCTAssertTrue(el("terminal.keyPanel").waitForExistence(timeout: 5))
        // Wait for the shell itself, not just the connecting overlay: the
        // prompt must be on the grid before keys mean anything.
        let connecting = el("terminal.state.connecting")
        _ = connecting.waitForNonExistence(timeout: 15)
        XCTAssertTrue(
            canvasMatching("value CONTAINS '$'").waitForExistence(timeout: 20),
            "shell prompt did not appear: \(canvas.value ?? "nil")"
        )
        snap("11-terminal-open")

        // Keys typed in the first moments after focus can be dropped by the
        // simulator (first-responder hand-off, insert suppression), so retry
        // with a fresh marker instead of failing on a single lost line.
        var echoed = false
        for attempt in 0 ..< 3 where !echoed {
            canvas.tap()
            Thread.sleep(forTimeInterval: 1)
            canvas.typeText("echo termoso-$((40+\(attempt + 2)))\n")
            echoed = canvasMatching("value CONTAINS 'termoso-\(42 + attempt)'").waitForExistence(timeout: 10)
        }
        XCTAssertTrue(echoed, "shell output did not reach the grid: \(canvas.value ?? "nil")")
        snap("12-terminal-echo")

        // Extra keys: Ctrl+C via the sticky modifier, then Tab.
        el("terminal.key.ctrl").tap()
        canvas.typeText("c")
        el("terminal.key.special.tab").tap()

        // Back to Connections: the session is listed and live.
        el("terminal.close").tap()
        XCTAssertTrue(el("connections.sessions").waitForExistence(timeout: 5))
        XCTAssertTrue(app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'connections.session.'")).firstMatch.exists)
        snap("13-connections-live")

        // Disconnect from inside the terminal and confirm the closed state.
        app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'connections.session.'")).firstMatch.tap()
        XCTAssertTrue(canvas.waitForExistence(timeout: 5))
        el("terminal.more").tap()
        // Confirmation-dialog actions do not carry SwiftUI identifiers.
        let disconnect = app.buttons["Disconnect"].firstMatch
        XCTAssertTrue(disconnect.waitForExistence(timeout: 5))
        disconnect.tap()
        XCTAssertTrue(el("terminal.state.closed").waitForExistence(timeout: 10), "session did not report closed")
        snap("14-terminal-closed")
        el("terminal.closeSession").tap()
        XCTAssertTrue(el("connections.empty").waitForExistence(timeout: 5))
    }

    /// The terminal canvas once its mirrored text satisfies `predicate`.
    private func canvasMatching(_ predicate: String) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier == 'terminal.canvas' AND \(predicate)"))
            .firstMatch
    }

    /// Identifier lookup independent of the element type SwiftUI picks
    /// (List rows and toolbar menus vary between buttons, cells and others).
    private func el(_ identifier: String) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: identifier).firstMatch
    }

    private func snap(_ name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}

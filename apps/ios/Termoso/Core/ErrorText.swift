import Foundation
import TermosoCore

extension MobileError {
    /// Human-readable text; the generated `errorDescription` is the Swift
    /// reflection of the enum, not something to show a person.
    var userMessage: String {
        switch self {
        case let .Invalid(detail), let .NotFound(detail), let .Ssh(detail),
             let .HostKeyRejected(detail), let .Key(detail):
            return detail
        case .Locked:
            return "Vault is locked"
        case let .AuthFailed(remaining):
            return "Authentication failed (\(remaining))"
        case let .SecurityKey(_, detail, _):
            return detail
        case .Cancelled:
            return "Cancelled"
        case .Closed:
            return "Connection closed"
        case .ReadOnlyOffline:
            return "Read-only while offline"
        case .ReauthRequired:
            return "Please sign in again"
        case let .Other(kind, detail):
            return detail.isEmpty ? kind : detail
        }
    }
}

func userMessage(for error: any Error) -> String {
    if let mobile = error as? MobileError {
        return mobile.userMessage
    }
    return error.localizedDescription
}

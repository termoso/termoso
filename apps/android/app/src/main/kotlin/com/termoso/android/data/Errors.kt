package com.termoso.android.data

import com.termoso.android.R
import com.termoso.android.plural
import com.termoso.android.str
import com.termoso.core.MobileException

/** Human-readable text for any failure coming out of the core (or elsewhere). */
fun Throwable.userMessage(): String = when (this) {
    is MobileException.Invalid -> detail
    is MobileException.NotFound -> detail
    is MobileException.Locked -> str(R.string.the_vault_is_locked)
    is MobileException.Ssh -> detail
    is MobileException.AuthFailed -> str(R.string.authentication_failed, remaining)
    is MobileException.HostKeyRejected -> detail
    is MobileException.Key -> detail
    is MobileException.Cancelled -> str(R.string.cancelled)
    is MobileException.Closed -> str(R.string.connection_closed)
    is MobileException.ReadOnlyOffline -> str(R.string.files_read_only_offline)
    is MobileException.ReauthRequired -> str(R.string.confirm_your_password_to_make_this_change)
    is MobileException.SecurityKey -> securityKeyMessage(kind, detail, retries)
    is MobileException.Other -> when (kind) {
        "api" -> apiMessage(detail)
        "network" -> str(R.string.could_not_reach_the_server_check_the_address)
        "websocket" -> str(R.string.realtime_connection_failed)
        "vault_read_only" -> str(R.string.this_vault_is_view_only_for_you)
        "not_signed_in" -> str(R.string.not_signed_in)
        else -> detail
    }
    else -> message ?: toString()
}

/** Typed FIDO2 failures (`Fido2Error::kind`) in the words the user needs to act on them. */
private fun securityKeyMessage(kind: String, detail: String, retries: Int?): String = when (kind) {
    "fido2_no_device" -> str(R.string.no_security_key_found_plug_one_in_over)
    "fido2_device_gone" -> str(R.string.the_security_key_was_disconnected)
    "fido2_pin_required" -> str(R.string.this_security_key_needs_its_pin)
    "fido2_pin_invalid" -> str(R.string.wrong_pin) + (retries?.let { " " + plural(R.plurals.attempts_left, it, it) } ?: "")
    "fido2_pin_blocked" -> str(R.string.the_pin_is_blocked_remove_and_reinsert_the)
    "fido2_pin_not_set" -> str(R.string.this_security_key_has_no_pin_yet_set)
    "fido2_timeout" -> str(R.string.the_security_key_was_not_touched_in_time)
    "fido2_denied" -> str(R.string.the_security_key_refused_the_request)
    "fido2_wrong_device" -> str(R.string.this_key_does_not_belong_to_that_security)
    else -> detail
}

/** `server 401: invalid_credentials: Wrong email or password` → the human part. */
private fun apiMessage(detail: String): String {
    val parts = detail.split(": ", limit = 3)
    return when {
        parts.size == 3 && parts[0].startsWith("server ") -> parts[2].ifBlank { parts[1].replace('_', ' ') }
        else -> detail
    }
}

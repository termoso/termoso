package com.termoso.android.ui.hosts

import com.termoso.android.ResourceTest
import com.termoso.android.ui.components.closeHostLabel
import com.termoso.android.ui.terminal.quickTargetText
import com.termoso.core.HostDraft
import com.termoso.core.QuickTarget
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HostActionsTest : ResourceTest() {
    private fun draft() = HostDraft(
        id = null,
        vaultId = "v",
        label = "",
        address = "",
        groupId = null,
        port = null,
        username = "",
        password = null,
        sshKeyId = null,
        identityId = null,
        sshId = false,
        sshIdKeyType = null,
        useMosh = false,
        moshServerCommand = null,
        tagIds = emptyList(),
        notes = "",
        osName = null,
        icon = null,
        ipVersion = "auto",
        agentForwarding = false,
        forwardX11 = false,
        startupSnippetId = null,
        envVariables = emptyList(),
        keepAliveInterval = null,
        timeout = null,
        hasPassword = false,
        hasTotp = false,
        totpSecret = null,
        gatewayId = null,
        macAddress = null,
        shellIntegration = null,
        ssh = true,
        telnet = null,
        webdav = null,
        filesProvider = false,
        hostChainId = null,
        proxyId = null,
        colorScheme = null,
        charset = null,
        backspace = null,
    )

    @Test
    fun hostLinkOmitsDefaultPortsAndUserlessTelnet() {
        assertEquals("ssh://root@10.0.0.1", hostLink("ssh", "root", "10.0.0.1", 22))
        assertEquals("ssh://root@10.0.0.1:2222", hostLink("ssh", "root", "10.0.0.1", 2222))
        assertEquals("ssh://10.0.0.1", hostLink("ssh", "", "10.0.0.1", 22))
        assertEquals("telnet://bbs.example.org", hostLink("telnet", "guest", "bbs.example.org", 23))
        assertEquals("telnet://bbs.example.org:2323", hostLink("TELNET", "", "bbs.example.org", 2323))
    }

    @Test
    fun closeLabelsCountConnections() {
        assertEquals("Close connection", closeConnectionsLabel(1))
        assertEquals("Close all (3)", closeConnectionsLabel(3))
        assertEquals("Close all to this host (2)", closeHostLabel(2))
    }

    @Test
    fun quickTargetTextRoundTripsAddToHostsInput() {
        assertEquals("root@h", quickTargetText(QuickTarget("h", 22u, "root", "ssh")))
        assertEquals("root@h:2200", quickTargetText(QuickTarget("h", 2200u, "root", "ssh")))
        assertEquals("telnet://h", quickTargetText(QuickTarget("h", 23u, "", "telnet")))
        assertEquals("telnet://h:2323", quickTargetText(QuickTarget("h", 2323u, "", "telnet")))
    }

    @Test
    fun prefilledSshTargetFillsSshSection() {
        val d = draft().prefilled(QuickTarget("srv", 2200u, "deploy", "ssh"))
        assertEquals("srv", d.address)
        assertEquals("deploy", d.username)
        assertEquals(2200.toUShort(), d.port)
        assertTrue(d.ssh)
        assertNull(d.telnet)
        assertNull(draft().prefilled(QuickTarget("srv", 22u, "deploy", "ssh")).port)
    }

    @Test
    fun prefilledTelnetTargetSwapsToTelnetSection() {
        val d = draft().prefilled(QuickTarget("bbs", 2323u, "guest", "telnet"))
        assertEquals("bbs", d.address)
        assertFalse(d.ssh)
        val t = d.telnet!!
        assertEquals(2323.toUShort(), t.port)
        assertEquals("guest", t.username)
        assertNull(draft().prefilled(QuickTarget("bbs", 23u, "", "telnet")).telnet!!.port)
        assertEquals(draft(), draft().prefilled(null))
    }
}
